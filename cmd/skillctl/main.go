// skillctl — m3c-tools command-line front-end.
//
// Stream S1 (SPEC-0188 Phase 2) ships ONLY the three signing
// subcommands: keygen, sign, verify-sig. The full skillctl CLI
// (scan, report, pack, browse, ...) lives on
// feature/thinking-engine-phase1 and will be merged onto the
// integration branch separately. The integration branch's main.go
// is a one-liner-per-case dispatcher; merging this stream's
// signing case branches into that file is a trivial conflict.
//
// All non-trivial logic lives in signing_cmds.go so that file can
// be cherry-picked without dragging this skeleton main along.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		printUsage(os.Stderr)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "keygen":
		os.Exit(runKeygen(os.Args[2:], os.Stdout, os.Stderr))
	case "sign":
		os.Exit(runSign(os.Args[2:], os.Stdout, os.Stderr))
	case "verify-sig":
		os.Exit(runVerifySig(os.Args[2:], os.Stdout, os.Stderr))
	// === SPEC-0188 S7: trust subcommand ===
	case "trust":
		os.Exit(runTrust(os.Args[2:], os.Stdout, os.Stderr))
	// === END SPEC-0188 S7 ===
	// === SPEC-0188 S9-cli: attest subcommand ===
	case "attest":
		os.Exit(runAttest(os.Args[2:], os.Stdout, os.Stderr))
	// === end SPEC-0188 S9-cli ===
	// === SPEC-0188 S8: install/verify subcommands ===
	case "install":
		os.Exit(runInstall(os.Args[2:], os.Stdout, os.Stderr))
	case "verify":
		os.Exit(runVerify(os.Args[2:], os.Stdout, os.Stderr))
	// === END SPEC-0188 S8 ===
	case "help", "--help", "-h":
		printUsage(os.Stdout)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "skillctl: unknown command %q\n\n", os.Args[1])
		printUsage(os.Stderr)
		os.Exit(2)
	}
}

func printUsage(w *os.File) {
	fmt.Fprintln(w, "Usage: skillctl <command> [args]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Commands (Stream S1 / SPEC-0188 Phase 2):")
	fmt.Fprintln(w, "  keygen       Generate an ed25519 keypair (PEM, PKCS#8 / SPKI).")
	fmt.Fprintln(w, "  sign         Sign a .skb bundle with an ed25519 private key.")
	fmt.Fprintln(w, "  verify-sig   Verify a detached author signature locally.")
	fmt.Fprintln(w, "  attest       POST a signed governance attestation to the registry.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Commands (Stream S7 / SPEC-0188 Phase 4):")
	fmt.Fprintln(w, "  trust        Manage ~/.claude/skill-trust-roots.yaml (list/add/remove).")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Commands (Stream S8 / SPEC-0188 Phase 4):")
	fmt.Fprintln(w, "  install      Pull, verify, and install a signed skill bundle.")
	fmt.Fprintln(w, "  verify       Re-run the trust-chain check on an installed skill.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Run any command with --help for its flags.")
}
