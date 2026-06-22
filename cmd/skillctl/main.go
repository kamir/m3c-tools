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

// version is stamped at build time via -ldflags "-X main.version=skillctl/vX.Y.Z".
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		printUsage(os.Stderr)
		os.Exit(2)
	}
	// FR-0043: for ER1-bound commands, auto-load the device token persisted by
	// `skillctl login` / `m3c-tools login` so users need not export it by hand.
	// Gated to networkCommands so offline commands never touch the OS keychain.
	if networkCommands[os.Args[1]] {
		autoloadDeviceToken(os.Stderr)
	}
	switch os.Args[1] {
	// === FR-0043: device login (browser pairing) + token autoload ===
	case "login":
		os.Exit(runLogin(os.Args[2:], os.Stdout, os.Stderr))
	// === END FR-0043 ===
	case "version", "--version", "-v":
		fmt.Println(version)
		os.Exit(0)
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
	// === SPEC-0276 R4.3: portable, offline, trust-nothing verification kit ===
	case "export-verification-kit":
		runWithExit(func() int { return runExportKit(os.Args[2:], os.Stdout, os.Stderr) })
	// === END SPEC-0276 R4.3 ===
	// === SPEC-0276 R5: offline compliance evidence pack ===
	case "compliance":
		os.Exit(runCompliance(os.Args[2:], os.Stdout, os.Stderr))
	// === END SPEC-0276 R5 ===
	// === SPEC-0247 P0.1: Claude Code PreToolUse(Skill) trust gate ===
	// Reads the hook event on stdin, re-runs the §7 chain against the
	// installed skill, and emits an allow/deny decision. Fail-closed:
	// deny exits 2 (Claude Code "block") AND emits the decision JSON.
	case "verify-hook":
		runWithExit(func() int { return runVerifyHook(os.Stdin, os.Stdout, os.Stderr) })
	// === END SPEC-0247 P0.1 ===
	// === SPEC-0255: gate observability — summarise the append-only audit log. ===
	case "gate-stats":
		os.Exit(runGateStats(os.Args[2:], os.Stdout, os.Stderr))
	// === END SPEC-0255 ===
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
	case "menubar":
		cmdMenubar(os.Args[2:])
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
	// === SPEC-0214 (PLM v2 / SPEC-0216): project-context resolution ===
	// Reads `.m3c/project.yaml` (a committed projection of the PLM project
	// object) to resolve project id + ER1 target/context for the cwd, with a
	// dir-slug fallback. Consumed by /session-state (SPEC-0213).
	case "project":
		os.Exit(runProject(os.Args[2:], os.Stdout, os.Stderr))
	// === END SPEC-0214 ===
	// === SPEC-0213: session-state in ER1 — the Go mirror of the /session-state
	// skill (open/checkpoint/close/resume/list/show) for CI/menubar/scripts. ===
	case "session":
		os.Exit(runSession(os.Args[2:], os.Stdout, os.Stderr))
	// === END SPEC-0213 ===
	// === SPEC-0225 P1: personal skill registry — ER1 bundle transport ===
	// `publish` admits a new bundle to the `self` tenant (or posts an
	// AttestationPublishedEvent with --attest). `pull` / `registry` / `revoke`
	// land in P2/P3.
	case "publish":
		os.Exit(runPublish(os.Args[2:], os.Stdout, os.Stderr))
	// === END SPEC-0225 P1 ===
	// === SPEC-0225 P2: pull + registry view ===
	case "pull":
		os.Exit(runPull(os.Args[2:], os.Stdout, os.Stderr))
	case "registry":
		os.Exit(runRegistry(os.Args[2:], os.Stdout, os.Stderr))
	// === END SPEC-0225 P2 ===
	// === SPEC-0272: publish an onboarding runbook into the THOH catalog ===
	case "runbook":
		os.Exit(runRunbook(os.Args[2:], os.Stdout, os.Stderr))
	// === SPEC-0246 §7: room mapping (share published bundles into a co-learning room) ===
	case "room":
		os.Exit(runRoom(os.Args[2:], os.Stdout, os.Stderr))
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
	fmt.Fprintln(w, "Commands (FR-0043 / device login):")
	fmt.Fprintln(w, "  login        Browser device-pairing against ER1; saves a token skillctl uses automatically.")
	fmt.Fprintln(w, "               Flags: --no-browser, --timeout 5m, --base-url URL, --status, --logout.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Commands (Stream S7 / SPEC-0188 Phase 4):")
	fmt.Fprintln(w, "  trust        Manage ~/.claude/skill-trust-roots.yaml (list/add/remove).")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Commands (Stream S8 / SPEC-0188 Phase 4):")
	fmt.Fprintln(w, "  install      Pull, verify, and install a signed skill bundle.")
	fmt.Fprintln(w, "  verify       Re-run the trust-chain check on an installed skill.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Commands (SPEC-0247 / Claude Code trust gate):")
	fmt.Fprintln(w, "  verify-hook  PreToolUse(Skill) gate: reads a hook event on stdin, verifies the")
	fmt.Fprintln(w, "               §7 chain, and emits allow/deny. Fail-closed. Wire as a hook, not by hand.")
	fmt.Fprintln(w, "  gate-stats   Summarise the gate-audit.jsonl (decisions, top blocks, cache-hit rate).")
	fmt.Fprintln(w, "               Flags: --since <168h|YYYY-MM-DD>, --json.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Commands (SPEC-0195 / awareness bridge):")
	fmt.Fprintln(w, "  awareness sync     Admit local skills to a registry.")
	fmt.Fprintln(w, "  awareness verify   Read back per-session admissions.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Commands (SPEC-0214 / PLM project context):")
	fmt.Fprintln(w, "  project show       Resolve the PLM project context for this dir (.m3c/project.yaml).")
	fmt.Fprintln(w, "  project resolve    Print one field (--field project_id|er1-target|er1-context|channel:<kind>|...).")
	fmt.Fprintln(w, "  project channels   List the v2 `channels:` block (--kind to filter).")
	fmt.Fprintln(w, "  project path       Print the descriptor file path, or (none).")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Commands (SPEC-0225 / personal skill registry via ER1):")
	fmt.Fprintln(w, "  publish <name[@ver]>          Admit a bundle to the `self` ER1 registry (--bundle <path>|--skill-dir <dir>).")
	fmt.Fprintln(w, "  publish --attest <name>       Post a governance attestation for an admitted digest (--level --rationale).")
	fmt.Fprintln(w, "  publish --revoke <name>       Post a BundleRevokedEvent for an admitted digest (--digest sha256:… --reason …).")
	fmt.Fprintln(w, "  publish --all                 Iterate INFRA/skill-registry/self/publish-manifest.txt: admit + attest each.")
	fmt.Fprintln(w, "  pull                          Run the 5-gate gauntlet against the `self` registry; stage verified bundles.")
	fmt.Fprintln(w, "  registry ls [--latest]        List bundles in the `self` registry.")
	fmt.Fprintln(w, "  registry show <name|sha256:…> Show full timeline (admit/attest/revoke/install) for one bundle.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Commands (SPEC-0213 / session-state in ER1):")
	fmt.Fprintln(w, "  session open       Create the session-state ER1 item for this session (idempotent).")
	fmt.Fprintln(w, "  session checkpoint Append a checkpoint child item (--auto for a git/todo snapshot).")
	fmt.Fprintln(w, "  session close      Write a final close-checkpoint (--summary | --distill).")
	fmt.Fprintln(w, "  session list       List session-state items (--project / --host / --open-only).")
	fmt.Fprintln(w, "  session show       Show a session-state item by session_id or doc_id.")
	fmt.Fprintln(w, "  session resume     Print a resume hint for a prior session.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Run any command with --help for its flags.")
}
