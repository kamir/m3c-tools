package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/mutationstate"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

const localMutationProfile = "local-operator-v1"

func printTrustStateUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: skillctl trust state <status|enroll|adopt> [flags]")
	fmt.Fprintln(w, "Flags: --trust-roots FILE --registry URL --home DIR --revocations FILE")
	fmt.Fprintln(w, "Enrollment also requires --profile local-operator-v1 --confirm-local-trust.")
	fmt.Fprintln(w, "Outputs JSON history metadata. No reset or automatic repair is available.")
}

func runTrustState(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printTrustStateUsage(stderr)
		return exitUsage
	}
	verb := args[0]
	if verb == "help" || verb == "--help" || verb == "-h" {
		printTrustStateUsage(stdout)
		return exitOK
	}
	if verb != "status" && verb != "enroll" && verb != "adopt" {
		printTrustStateUsage(stderr)
		return exitUsage
	}
	fs := flag.NewFlagSet("trust state "+verb, flag.ContinueOnError)
	fs.SetOutput(stderr)
	rootsPath := fs.String("trust-roots", "", "Pinned trust-roots file.")
	registry := fs.String("registry", "", "Registry selection when roots contain multiple registries.")
	home := fs.String("home", "", "Same home used by managed install.")
	evidence := fs.String("revocations", "", "Complete signed revocation-list file.")
	profile := fs.String("profile", "", "Enrollment trust profile: local-operator-v1.")
	confirm := fs.Bool("confirm-local-trust", false, "Explicitly trust the local operator and OS wall clock for enrollment.")
	fs.Usage = func() { printTrustStateUsage(stderr); fs.PrintDefaults() }
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() != 0 || (verb == "status" && *evidence != "") || (verb != "status" && *evidence == "") ||
		(verb == "enroll" && (*profile != localMutationProfile || !*confirm)) ||
		(verb != "enroll" && (*profile != "" || *confirm)) {
		fs.Usage()
		return exitUsage
	}
	_, root, err := loadAndPickRootFromPath(*rootsPath, *registry)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return mutationStateExitCode(err)
	}
	store, err := mutationStateStore(*home, root)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return mutationStateExitCode(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var status mutationstate.Status
	switch verb {
	case "status":
		status, err = store.Status(ctx)
	default:
		var raw []byte
		raw, err = readMutationEvidence(*evidence)
		if err == nil {
			if verb == "enroll" {
				status, err = store.Enroll(ctx, raw)
			} else {
				status, err = store.Adopt(ctx, raw)
			}
		}
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return mutationStateExitCode(err)
	}
	if err := json.NewEncoder(stdout).Encode(status); err != nil {
		fmt.Fprintln(stderr, "trust state: cannot write result")
		return exitGeneric
	}
	return exitOK
}

func mutationStateStore(home string, root *verify.TrustRoot) (*mutationstate.Store, error) {
	if !root.IsManaged() {
		return nil, fmt.Errorf("trust state requires a managed trust root: %w", verify.ErrRegistryNotTrusted)
	}
	if home == "" {
		var err error
		home, err = userHome()
		if err != nil || home == "" {
			return nil, errors.New("trust state: cannot resolve home")
		}
	}
	return mutationstate.New(filepath.Join(home, ".claude", "mutation-state"), root)
}

func mutationStateExitCode(err error) int {
	if errors.Is(err, mutationstate.ErrNotEnrolled) || errors.Is(err, mutationstate.ErrInvalidState) {
		if errors.Is(err, verify.ErrRegistryNotTrusted) {
			return verify.ExitCode(verify.ErrRegistryNotTrusted)
		}
		return verify.ExitRevocationStale
	}
	return verify.ExitCode(err)
}

// readMutationEvidence retains one bounded regular-file snapshot for verification
// and adoption. Installation must not re-read a potentially changed pathname.
func readMutationEvidence(path string) ([]byte, error) {
	// #nosec G703 -- --revocations explicitly selects an operator-owned local file; it is not a path confined under a remote-controlled root.
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() {
		return nil, errors.New("trust state: evidence must be a readable regular file, not a link")
	}
	// #nosec G304 G703 -- explicit local file selection; regular-file identity and bounded retained bytes are checked below.
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("trust state: open evidence: %w", err)
	}
	st, statErr := f.Stat()
	if statErr != nil || !st.Mode().IsRegular() || !os.SameFile(before, st) || st.Size() > mutationstate.MaxEvidenceBytes {
		closeErr := f.Close()
		return nil, errors.Join(errors.New("trust state: evidence must be a bounded regular file"), statErr, closeErr)
	}
	raw, readErr := io.ReadAll(io.LimitReader(f, mutationstate.MaxEvidenceBytes+1))
	err = errors.Join(readErr, f.Close())
	if err != nil {
		return nil, fmt.Errorf("trust state: read evidence: %w", err)
	}
	if len(raw) > mutationstate.MaxEvidenceBytes {
		return nil, errors.New("trust state: evidence exceeds size limit")
	}
	return raw, nil
}

func managedInstallEvidence(path string, root *verify.TrustRoot, digest string) (revocationSnapshot, []byte, error) {
	raw, err := readMutationEvidence(path)
	if err != nil {
		return revocationSnapshot{}, nil, err
	}
	var list verify.RevocationList
	if json.Unmarshal(raw, &list) != nil {
		return revocationSnapshot{}, nil, fmt.Errorf("managed install: invalid revocation evidence: %w", verify.ErrRegistryNotTrusted)
	}
	set, err := verify.VerifyRevocationList(&list, root, root.MinRevocationEpoch)
	if err != nil {
		return revocationSnapshot{}, nil, fmt.Errorf("managed install: untrusted revocation evidence: %w", verify.ErrRegistryNotTrusted)
	}
	_, revoked := set[digest]
	return revocationSnapshot{revoked: revoked, epoch: list.Epoch, issuedAt: list.IssuedAt}, raw, nil
}
