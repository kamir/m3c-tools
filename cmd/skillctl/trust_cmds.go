package main

// Stream S7 (SPEC-0188 Phase 4 T1+T2+T3+T7) CLI runners for the trust
// subcommand. Mirrors S1's signing_cmds.go pattern: pure runner functions
// that take args + io.Writers + return numeric exit codes, so they're
// trivially unit-testable without spawning a subprocess.
//
// All non-trivial logic lives in pkg/skillctl/verify/ — this file is
// flag plumbing + IO.
//
// Subcommands:
//
//	skillctl trust list
//	skillctl trust add --registry <url> --pubkey <path> [--id <key-id>]
//	skillctl trust remove --registry <url>
//
// The numbered exit codes from SPEC-0188 §11 are documented in `skillctl
// trust --help` so CI consumers can find them; the verify subcommand (S8)
// also surfaces them.

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// runTrust is the dispatcher for `skillctl trust <verb>`. Returns the
// numeric exit code; main.go surfaces it to os.Exit. Splitting verb
// handling into its own function makes the test surface mirror the
// signing_cmds_test.go pattern.
func runTrust(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		printTrustUsage(stderr)
		return exitUsage
	}
	switch args[0] {
	case "list":
		return runTrustList(args[1:], stdout, stderr)
	case "add":
		return runTrustAdd(args[1:], stdout, stderr)
	case "remove", "rm":
		return runTrustRemove(args[1:], stdout, stderr)
	case "help", "--help", "-h":
		printTrustUsage(stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "skillctl trust: unknown verb %q\n\n", args[0])
		printTrustUsage(stderr)
		return exitUsage
	}
}

// trustConfigPath is the resolved trust-roots file path. Pulled out as a
// var so tests can override (cmd/skillctl/trust_cmds_test.go points it at
// a temp dir before running runTrust).
var trustConfigPath = func() string {
	p, err := verify.DefaultPath()
	if err != nil {
		// Falling back to a relative path is still safer than a panic;
		// the CLI will print the read error from Load explicitly.
		return ".claude/skill-trust-roots.yaml"
	}
	return p
}

// runTrustList prints every configured registry + key. Loads the file
// best-effort: if it doesn't exist, prints a short "no trust roots
// configured yet" message and exits 0 (this is informational, not a
// failure — `trust list` on a fresh machine is expected).
func runTrustList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("trust list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillctl trust list")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Print every configured registry and the keys pinned to it.")
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return exitUsage
	}

	path := trustConfigPath()
	tr, err := verify.Load(path)
	if errors.Is(err, os.ErrNotExist) {
		// Bootstrap path — print friendly message, exit 0.
		fmt.Fprintf(stdout, "trust roots: %s (does not exist yet)\n", path)
		fmt.Fprintln(stdout, "no trust roots configured")
		fmt.Fprintln(stdout, "configure one with: skillctl trust add --registry <url> --pubkey <path>")
		return exitOK
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}

	fmt.Fprintf(stdout, "trust roots: %s\n", tr.Path)
	if len(tr.Roots) == 0 {
		fmt.Fprintln(stdout, "(empty — no registries pinned)")
		return exitOK
	}
	for _, root := range tr.Roots {
		fmt.Fprintf(stdout, "\nregistry: %s\n", root.RegistryURL)
		fmt.Fprintf(stdout, "  identity_keys_authorized: %s\n", root.IdentityKeysAuthorized)
		fmt.Fprintf(stdout, "  governance_minimum:       %s\n", root.GovernanceMinimum)
		fmt.Fprintln(stdout, "  registry_keys:")
		for _, k := range root.RegistryKeys {
			retired := ""
			if !k.IsActive() {
				retired = fmt.Sprintf("  [retired %s]", k.Retired)
			}
			fmt.Fprintf(stdout, "    - id: %s   issued: %s%s\n", k.ID, k.Issued, retired)
			fmt.Fprintf(stdout, "      pubkey (b64): %s\n", k.PubkeyB64)
		}
	}
	return exitOK
}

// runTrustAdd implements `skillctl trust add --registry <url> --pubkey <path> [--id <key-id>]`.
// The pubkey is loaded as PEM SPKI (the format produced by `skillctl
// keygen` per S1's contract), decoded to 32 raw bytes, and stored
// base64-encoded in the YAML.
func runTrustAdd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("trust add", flag.ContinueOnError)
	fs.SetOutput(stderr)
	registryURL := fs.String("registry", "", "Registry URL (e.g. https://aims.example.com/api/skills). Required.")
	pubkeyPath := fs.String("pubkey", "", "Path to PEM SPKI ed25519 public key file. Required.")
	keyID := fs.String("id", "", "Optional key id label (defaults to a short fingerprint-derived id).")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillctl trust add --registry <url> --pubkey <path> [--id <key-id>]")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Pin a registry public key in ~/.claude/skill-trust-roots.yaml.")
		fmt.Fprintln(stderr, "Adding a second key under an existing registry URL is the rotation")
		fmt.Fprintln(stderr, "overlap path: the verifier will accept either non-retired key.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *registryURL == "" || *pubkeyPath == "" {
		fs.Usage()
		return exitUsage
	}

	path := trustConfigPath()
	tr, err := verify.Load(path)
	if errors.Is(err, os.ErrNotExist) {
		// First time — Load returned an empty TrustRoots with Path set.
		// Continue with that.
	} else if err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}

	if err := tr.AddRegistry(*registryURL, *pubkeyPath, *keyID); err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}
	if err := tr.Save(); err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}
	fmt.Fprintf(stdout, "added registry %s to %s\n", strings.TrimRight(*registryURL, "/"), tr.Path)
	return exitOK
}

// runTrustRemove implements `skillctl trust remove --registry <url>`.
// Deletes the entire entry (including all its keys). Convenience verb;
// a future `skillctl trust retire --registry <url> --id <k>` would mark
// a single key retired without removing the entry.
func runTrustRemove(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("trust remove", flag.ContinueOnError)
	fs.SetOutput(stderr)
	registryURL := fs.String("registry", "", "Registry URL to remove. Required.")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillctl trust remove --registry <url>")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Remove a pinned registry (including all its keys).")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *registryURL == "" {
		fs.Usage()
		return exitUsage
	}

	path := trustConfigPath()
	tr, err := verify.Load(path)
	if err != nil {
		// Including the "file does not exist" case — there's nothing
		// to remove, surface the error.
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}
	if err := tr.RemoveRegistry(*registryURL); err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}
	if err := tr.Save(); err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}
	fmt.Fprintf(stdout, "removed registry %s from %s\n", strings.TrimRight(*registryURL, "/"), tr.Path)
	return exitOK
}

// printTrustUsage prints the top-level `trust` help including the
// numbered exit codes that SPEC-0188 §11 reserves. The codes themselves
// are produced by the verify and install subcommands (which S8 owns)
// but since `trust` configures the input to those commands, advertising
// the codes here is the right place for CI authors to find them.
func printTrustUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: skillctl trust <verb> [flags]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Verbs:")
	fmt.Fprintln(w, "  list     Print configured registries and their pinned keys.")
	fmt.Fprintln(w, "  add      Pin a registry public key.")
	fmt.Fprintln(w, "  remove   Unpin a registry (alias: rm).")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Trust roots config: ~/.claude/skill-trust-roots.yaml (per SPEC-0188 §4.4).")
	fmt.Fprintln(w, "Multiple keys per registry are supported for rotation overlap windows.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Verifier exit codes (SPEC-0188 §11; surfaced by `skillctl install` /")
	fmt.Fprintln(w, "`skillctl verify` once Phase 4 ships):")
	fmt.Fprintln(w, "   0  ok")
	fmt.Fprintln(w, "   1  generic error")
	fmt.Fprintln(w, "   2  usage / flag error")
	fmt.Fprintln(w, "  10  digest mismatch")
	fmt.Fprintln(w, "  11  author signature invalid")
	fmt.Fprintln(w, "  12  registry not in trust roots")
	fmt.Fprintln(w, "  13  governance below minimum")
	fmt.Fprintln(w, "  14  depends_on unsatisfied")
	fmt.Fprintln(w, "  15  blob missing")
}
