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
	// === SPEC-0188 Phase 1 PoC: pack ===
	case "pack":
		cmdPack(os.Args[2:])
	// === END Phase 1 PoC ===
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
	// === SPEC-0188 §4.5 (S3.6 closure 2026-05-06): revoke subcommand ===
	case "revoke":
		os.Exit(runRevoke(os.Args[2:], os.Stdout, os.Stderr))
	// === end SPEC-0188 §4.5 ===
	// === SPEC-0189 §14 (S3.3 + S3.4 closure 2026-05-06): audit subcommand ===
	case "audit":
		os.Exit(runAudit(os.Args[2:], os.Stdout, os.Stderr))
	// === end SPEC-0189 §14 ===
	// === SPEC-0194 (S3.1 closure 2026-05-06): propose subcommand ===
	case "propose":
		os.Exit(runPropose(os.Args[2:], os.Stdout, os.Stderr))
	// === end SPEC-0194 ===
	// === SPEC-0188 S8: install/verify subcommands ===
	//
	// Both routed through runWithExit so the SPEC-0188 §11 numbered exit
	// codes (10..16) surface verbatim to the parent process — see
	// cmd/skillctl/exit.go for the single audit point.
	case "install":
		runWithExit(func() int { return runInstall(os.Args[2:], os.Stdout, os.Stderr) })
	case "verify":
		runWithExit(func() int { return runVerify(os.Args[2:], os.Stdout, os.Stderr) })
	// === END SPEC-0188 S8 ===
	// === SPEC-0189 S0a: scanner family dispatchers (imported from
	// feature/thinking-engine-phase1; pre-SPEC-0189 behaviour preserved). ===
	case "scan":
		cmdScan(os.Args[2:])
	case "report":
		cmdReport(os.Args[2:])
	case "diff":
		cmdDiff(os.Args[2:])
	case "seal":
		cmdSeal(os.Args[2:])
	case "import":
		cmdImport(os.Args[2:])
	// `audit` is now SPEC-0189 §14 antivirus UX (S3.3, dispatched above);
	// the legacy SPEC-0115 cmdAudit was a Phase-2 stub and has been
	// superseded — see runAudit in audit_cmds.go.
	case "review":
		cmdReview(os.Args[2:])
	case "browse":
		cmdBrowse(os.Args[2:])
	case "consolidate":
		cmdConsolidate(os.Args[2:])
	case "sync-usage":
		cmdSyncUsage(os.Args[2:])
	// === END SPEC-0189 S0a ===
	// === SPEC-0195 S2 / Streams M1+M2: awareness + intent ===
	// `awareness` (M1) dispatches to runAwareness with sub-routes
	// {sync, verify, reset}. `intent` (M2) dispatches to runIntent
	// (today only `declare`). Both surface SPEC-0188 §11-style numbered
	// exit codes via runWithExit, including new 18 (intent_inconsistent)
	// and 19 (identity_mismatch).
	case "awareness":
		runWithExit(func() int { return runAwareness(os.Args[2:], os.Stdout, os.Stderr) })
	case "intent":
		runWithExit(func() int { return runIntent(os.Args[2:], os.Stdout, os.Stderr) })
	// === END SPEC-0195 S2 ===
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
	fmt.Fprintln(w, "Commands (SPEC-0195 / awareness bridge):")
	fmt.Fprintln(w, "  awareness sync     Admit local skills to a registry.")
	fmt.Fprintln(w, "  awareness verify   Read back per-session admissions.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Run any command with --help for its flags.")
}
