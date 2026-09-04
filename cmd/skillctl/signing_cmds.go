package main

// Stream S1 (SPEC-0188 Phase 2) CLI runners for the three signing
// subcommands. They live in their own file so the integration branch
// can merge into the existing skillctl main.go (on the
// feature/thinking-engine-phase1 branch) by just adding three case
// branches in the dispatch switch, no logic conflicts.

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/signing"
)

// extractBundlePositional pulls the single non-flag positional (the BUNDLE.skb
// path) out of args from ANY position, returning it plus the remaining flag args
// for fs.Parse. valueFlags names the flags that consume a following value, so
// that value is not mistaken for the positional (`--key K` → K is not the
// bundle). Go's stdlib flag package stops at the first positional, so without
// this the bundle could only come AFTER the flags; this lets users write it
// before OR after (matching the usage brief, like `attest`). Returns ("", args)
// when zero or more than one positional is present, so the caller's usage check
// fires a clean exit-2 instead of guessing.
func extractBundlePositional(args []string, valueFlags map[string]bool) (bundle string, rest []string) {
	rest = make([]string, 0, len(args))
	var positionals []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" { // POSIX end-of-flags: everything after is positional
			rest = append(rest, a)
			positionals = append(positionals, args[i+1:]...)
			break
		}
		if len(a) > 1 && strings.HasPrefix(a, "-") {
			rest = append(rest, a)
			name := strings.TrimLeft(a, "-")
			if strings.ContainsRune(name, '=') {
				continue // -flag=value is self-contained
			}
			if valueFlags[name] && i+1 < len(args) {
				rest = append(rest, args[i+1]) // -flag value: keep the value with the flag
				i++
			}
			continue
		}
		positionals = append(positionals, a)
	}
	if len(positionals) == 1 {
		return positionals[0], rest
	}
	return "", args
}

// Exit codes (from S1 brief). Reserve numbers; do not redefine elsewhere.
const (
	exitOK       = 0
	exitGeneric  = 1
	exitUsage    = 2
	exitSigInval = 11
)

// runKeygen implements `skillctl keygen --out PATH`. Writes
// PATH.priv (mode 0600) and PATH.pub (mode 0644).
func runKeygen(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "Output keypair stem; produces <out>.priv and <out>.pub. Required.")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillctl keygen --out PATH")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Writes <PATH>.priv (mode 0600) and <PATH>.pub (mode 0644),")
		fmt.Fprintln(stderr, "both PEM-wrapped ed25519 (PKCS#8 / SPKI).")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Suggested location: ~/.config/m3c/skill-keys/<name>")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *out == "" {
		fs.Usage()
		return exitUsage
	}
	if !filepath.IsAbs(*out) {
		// Relative paths surprise users about CWD. Warn but don't refuse.
		fmt.Fprintf(stderr, "warning: --out %q is a relative path; resolving against CWD\n", *out)
	}

	if err := signing.Generate(*out); err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}
	fmt.Fprintf(stdout, "wrote %s.priv (mode 0600)\n", *out)
	fmt.Fprintf(stdout, "wrote %s.pub (mode 0644)\n", *out)
	return exitOK
}

// runSign implements `skillctl sign BUNDLE.skb --key PATH.priv [--identity-id ID]`.
func runSign(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyPath := fs.String("key", "", "Path to PEM PKCS#8 ed25519 private key (mode 0600). Required.")
	identityID := fs.String("identity-id", "", "Author identity id: ADVISORY ONLY, NOT embedded in the signature. The detached signature is over the bundle digest alone; author identity is bound at verify time via the trust-root pin (SPEC-0188 D4), not by this flag.")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillctl sign --key PATH.priv [--identity-id ID] BUNDLE.skb")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Computes the bundle's SHA-256 digest, signs the 32 raw bytes")
		fmt.Fprintln(stderr, "with ed25519, and writes:")
		fmt.Fprintln(stderr, "  <BUNDLE.skb>.<digest_hex>.author.sig (64 raw bytes, mode 0644)")
		fmt.Fprintln(stderr, "BUNDLE.skb may appear before or after the flags.")
		fs.PrintDefaults()
	}
	// The bundle positional may come before OR after the flags.
	bundlePath, flagArgs := extractBundlePositional(args, map[string]bool{"key": true, "identity-id": true})
	if err := fs.Parse(flagArgs); err != nil {
		return exitUsage
	}
	if bundlePath == "" || fs.NArg() != 0 {
		fs.Usage()
		return exitUsage
	}
	if *keyPath == "" {
		fs.Usage()
		return exitUsage
	}
	if !filepath.IsAbs(*keyPath) {
		fmt.Fprintf(stderr, "warning: --key %q is a relative path; resolving against CWD\n", *keyPath)
	}

	sigPath, digestHex, err := signing.SignBundle(bundlePath, *keyPath, *identityID)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitGeneric
	}
	// BUG-0213: this is the bundle digest, the SHA-256 of the .skb bytes, and it
	// is the value every later step wants. `pack` prints a DIFFERENT one (the
	// manifest digest), and nothing used to say which was which; the wrong value
	// does not fail here, it fails much later at the consumer as
	// "gate 4: no attestation ...", which points at a different problem entirely.
	// The `digest: <hex>` shape is unchanged so existing parsers keep working.
	fmt.Fprintf(stdout, "digest: %s\n", digestHex)
	fmt.Fprintf(stdout, "        ^ bundle digest: use this for `attest`, `publish --digest` and `revoke --digest`\n")
	fmt.Fprintf(stdout, "signature: %s\n", sigPath)
	return exitOK
}

// runVerifySig implements `skillctl verify-sig BUNDLE.skb --pubkey PATH.pub`.
// Returns 11 on cryptographic mismatch (reserved exit code per brief).
func runVerifySig(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify-sig", flag.ContinueOnError)
	fs.SetOutput(stderr)
	pubPath := fs.String("pubkey", "", "Path to PEM SPKI ed25519 public key. Required.")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillctl verify-sig --pubkey PATH.pub BUNDLE.skb")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Recomputes the bundle's SHA-256 digest, locates the matching")
		fmt.Fprintln(stderr, "<BUNDLE.skb>.<digest_hex>.author.sig file, and verifies it.")
		fmt.Fprintln(stderr, "Exit codes: 0 ok | 11 signature invalid | 1 other error | 2 usage.")
		fmt.Fprintln(stderr, "BUNDLE.skb may appear before or after the flags.")
		fs.PrintDefaults()
	}
	// The bundle positional may come before OR after the flags.
	bundlePath, flagArgs := extractBundlePositional(args, map[string]bool{"pubkey": true})
	if err := fs.Parse(flagArgs); err != nil {
		return exitUsage
	}
	if bundlePath == "" || fs.NArg() != 0 {
		fs.Usage()
		return exitUsage
	}
	if *pubPath == "" {
		fs.Usage()
		return exitUsage
	}

	if err := signing.VerifyDetached(bundlePath, *pubPath); err != nil {
		fmt.Fprintln(stderr, err)
		if errors.Is(err, signing.ErrSignatureInvalid) {
			return exitSigInval
		}
		return exitGeneric
	}
	fmt.Fprintln(stdout, "OK: signature verified")
	return exitOK
}
