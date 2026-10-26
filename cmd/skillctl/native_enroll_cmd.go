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

	"github.com/kamir/m3c-tools/pkg/skillctl/projectpolicy"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

// Enrollment is an explicit operator bootstrap, never an install fallback or a
// recovery authorization. An erased entire authority directory is locally
// indistinguishable from first use; recovery still requires operator controls.
func runNativeStateEnroll(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("trust native-state enroll", flag.ContinueOnError)
	fs.SetOutput(stderr)
	profile := fs.String("enterprise-profile", "", "Explicit absolute native Enterprise profile")
	pin := fs.String("enterprise-profile-sha256", "", "Optional SHA-256 pin of profile bytes")
	home := fs.String("home", "", "Artifact home bound by the profile")
	evidence := fs.String("evidence", "", "Absolute regular file containing complete signed evidence")
	asJSON := fs.Bool("json", false, "Print authenticated history status as JSON")
	helpCode := exitOK
	fs.Usage = func() { helpCode = writeNativeStateHelp(stderr) }
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return helpCode
		}
		return exitUsage
	}
	if fs.NArg() != 0 || *profile == "" || *evidence == "" {
		fs.Usage()
		return exitUsage
	}
	pinSelected, homeSelected := false, false
	fs.Visit(func(f *flag.Flag) {
		pinSelected = pinSelected || f.Name == "enterprise-profile-sha256"
		homeSelected = homeSelected || f.Name == "home"
	})
	if !filepath.IsAbs(*profile) || !filepath.IsAbs(*evidence) || (homeSelected && *home == "") {
		return nativeStateFailure(stderr, projectpolicy.ErrSelection)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nativeStateFailure(stderr, projectpolicy.ErrSelection)
	}
	if !homeSelected {
		*home, err = os.UserHomeDir()
		if err != nil {
			return nativeStateFailure(stderr, projectpolicy.ErrSelection)
		}
	}
	var policy *projectpolicy.NativePolicy
	if pinSelected {
		policy, err = projectpolicy.LoadNativePinned(*profile, *pin, cwd, *home)
	} else {
		policy, err = projectpolicy.LoadNative(*profile, cwd, *home)
	}
	if err != nil {
		return nativeStateFailure(stderr, err)
	}
	if err = policy.ValidateSelection(cwd, *home, policy.CarrierSelection().Locator); err != nil {
		return nativeStateFailure(stderr, err)
	}
	selection, err := policy.OfflineInstallSelection()
	if err != nil {
		return nativeStateFailure(stderr, err)
	}
	raw, err := readNativeEnrollmentEvidence(*evidence)
	if err != nil {
		fmt.Fprintln(stderr, "Native enrollment evidence file could not be read completely and closed safely.")
		return exitGeneric
	}
	journal, err := registry.OpenNativeJournal(selection)
	if err != nil {
		return nativeStateFailure(stderr, err)
	}
	status, err := journal.Enroll(context.Background(), raw)
	if err != nil {
		return nativeStateFailure(stderr, err)
	}
	output := []byte("Native history initially enrolled. This does not authorize installation or lost-history recovery.\n")
	if *asJSON {
		output, err = json.Marshal(struct {
			HistoryAuthorityID string `json:"history_authority_id"`
			EvidenceSHA256     string `json:"evidence_sha256"`
			Epoch              int64  `json:"epoch"`
		}{status.HistoryAuthorityID, status.EvidenceDigest, status.Epoch})
		if err != nil {
			fmt.Fprintln(stderr, "Native history may already be enrolled; status output failed.")
			return exitGeneric
		}
		output = append(output, '\n')
	}
	if n, err := stdout.Write(output); err != nil || n != len(output) {
		fmt.Fprintln(stderr, "Native history may already be enrolled; status output failed.")
		return exitGeneric
	}
	return exitOK
}

func readNativeEnrollmentEvidence(path string) (raw []byte, resultErr error) {
	const limit int64 = 1 << 20
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > limit {
		return nil, errors.New("invalid native evidence file")
	}
	// #nosec G304 -- Explicit operator-selected absolute path, regular-file and
	// SameFile checks plus bounded reads; never derived from server content.
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("native evidence open failed")
	}
	defer func() {
		resultErr = errors.Join(resultErr, f.Close())
		if resultErr != nil {
			raw = nil
		}
	}()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) || opened.Size() < 1 || opened.Size() > limit {
		return nil, errors.New("native evidence file changed")
	}
	raw, err = io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || len(raw) == 0 || int64(len(raw)) > limit {
		return nil, errors.New("native evidence read failed")
	}
	return raw, nil
}
