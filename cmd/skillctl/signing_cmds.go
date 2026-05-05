package main

// Stream S1 (SPEC-0188 Phase 2) CLI runners for the three signing
// subcommands. They live in their own file so the integration branch
// can merge into the existing skillctl main.go (on the
// feature/thinking-engine-phase1 branch) by just adding three case
// branches in the dispatch switch — no logic conflicts.

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"

	"github.com/kamir/m3c-tools/pkg/skillctl/signing"
)

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
	identityID := fs.String("identity-id", "", "Author identity ID (advisory; reserved for future use).")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: skillctl sign BUNDLE.skb --key PATH.priv [--identity-id ID]")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Computes the bundle's SHA-256 digest, signs the 32 raw bytes")
		fmt.Fprintln(stderr, "with ed25519, and writes:")
		fmt.Fprintln(stderr, "  <BUNDLE.skb>.<digest_hex>.author.sig (64 raw bytes, mode 0644)")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return exitUsage
	}
	bundlePath := fs.Arg(0)
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
	fmt.Fprintf(stdout, "digest: %s\n", digestHex)
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
		fmt.Fprintln(stderr, "Usage: skillctl verify-sig BUNDLE.skb --pubkey PATH.pub")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Recomputes the bundle's SHA-256 digest, locates the matching")
		fmt.Fprintln(stderr, "<BUNDLE.skb>.<digest_hex>.author.sig file, and verifies it.")
		fmt.Fprintln(stderr, "Exit codes: 0 ok | 11 signature invalid | 1 other error | 2 usage.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return exitUsage
	}
	bundlePath := fs.Arg(0)
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
