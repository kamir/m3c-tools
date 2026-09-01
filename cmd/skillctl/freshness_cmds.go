package main

// freshness_cmds.go — SPEC-0279 R3/R4/R5/R6 CLI wiring.
//
// The shared client glue every revocation consumer (verify --bundle, agentid
// verify, the SPEC-0247 gate) uses to honour the freshness contract on top of the
// pure verify.* core:
//
//   - load + signature-verify the OPTIONAL signed freshness checkpoint (R4) and
//     the OPTIONAL signed emergency deny-list (R5), both against the SAME pinned
//     registry key the revocation list uses;
//   - consult the emergency channel FIRST (R5) — a compromise token denies on
//     sight, before staleness or risk are even considered;
//   - resolve the effective staleness anchor (the checkpoint can reset the clock,
//     R4) and run the staleness→fail-policy decision (R3) with an INJECTABLE
//     clock;
//   - return a fully-populated, auditable verify.FreshnessDecision (R6).
//
// This file is WIRING; the policy + crypto live in pkg/skillctl/verify. No new
// crypto, no network.

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// freshnessInputs is the resolved per-invocation freshness context the consumers
// assemble (flag paths + the synced list's epoch/issued_at + the action risk).
type freshnessInputs struct {
	// root is the pinned trust root (the freshness policy + the signing keys).
	root *verify.TrustRoot

	// checkpointPath / emergencyPath are the OPTIONAL --checkpoint / --emergency
	// files. Empty = not supplied. A present-but-bad file is fail-closed.
	checkpointPath string
	emergencyPath  string

	// syncedEpoch / syncedIssuedAt come from the loaded revocation list (the
	// snapshot whose freshness we are judging). syncedIssuedAt is RFC3339.
	syncedEpoch    int
	syncedIssuedAt string

	// risk is the action's freshness risk class (high|low), classified by the
	// caller from the SPEC-0196 intent/datascope vocabulary.
	risk verify.ActionRisk

	// emergencyTokens are the identifiers to test against the emergency deny-list
	// (e.g. the bundle digest, the agent id, the owner identity). ANY hit denies.
	emergencyTokens []string

	// now is the injectable verification clock. Zero → time.Now().UTC().
	now time.Time
}

// freshnessOutcome is the consumer-facing verdict: the auditable decision, the
// emergency hit (if any), and the terminal error (nil = allowed).
type freshnessOutcome struct {
	Decision     verify.FreshnessDecision
	Emergency    bool   // an emergency deny-list token matched
	EmergencyTok string // the matched token (for the audit + message)
	Err          error  // ErrRevocationStale (stale fail-closed) or an emergency deny
}

// evaluateFreshness is the single freshness entry point. It returns a
// freshnessOutcome whose Err is:
//   - an emergency-deny error (exit 17 theme) when a token is on the deny-list;
//   - verify.ErrRevocationStale (exit 22) when the snapshot is stale + fail-closed;
//   - a registry-not-trusted error (exit 12) when a present checkpoint/emergency
//     file fails to verify (fail-closed — never silently ignored);
//   - nil when the action is allowed (fresh, or stale+low-risk+fail-open).
func evaluateFreshness(in freshnessInputs) freshnessOutcome {
	now := in.now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	floor := 0
	if in.root != nil {
		floor = in.root.MinRevocationEpoch
	}

	// R5 — emergency channel FIRST. A present-but-bad list is fail-closed.
	if strings.TrimSpace(in.emergencyPath) != "" {
		set, err := verify.LoadVerifiedEmergencyDenyList(in.emergencyPath, in.root)
		if err != nil {
			return freshnessOutcome{Err: fmt.Errorf("emergency deny-list: %w", err)}
		}
		if tok, bad := verify.EmergencyDenies(set, in.emergencyTokens...); bad {
			return freshnessOutcome{
				Emergency:    true,
				EmergencyTok: tok,
				Decision: verify.FreshnessDecision{
					Epoch: in.syncedEpoch, Risk: in.risk, Allowed: false,
					Reason: "emergency_deny",
				},
				Err: fmt.Errorf("emergency deny-list names %q (compromise event): %w", tok, verify.ErrIdentityRevoked),
			}
		}
	}

	// R2 — resolve the relying-party freshness policy from the pinned root.
	policy, err := in.root.Freshness()
	if err != nil {
		return freshnessOutcome{Err: fmt.Errorf("freshness policy: %w", err)}
	}

	// R4 — apply an OPTIONAL signed checkpoint to (maybe) reset the staleness
	// clock. A present-but-bad checkpoint is fail-closed. The checkpoint is
	// verified against the SAME single (own-company) registry root as the
	// revocation list — the single-company freshness case.
	//
	// SPEC-0279 AC4: cross-company STH freshness deferred to P5 (SPEC-0278) —
	// where a checkpoint/Signed-Tree-Head issued by ANOTHER company's log would be
	// cross-verified (a different trust anchor + inclusion proof) the branch would
	// wire HERE. Out of scope for P4; the deferral boundary is intentionally
	// visible at the call site.
	anchor := in.syncedIssuedAt
	checkpointApplied := false
	if strings.TrimSpace(in.checkpointPath) != "" {
		cp, lerr := loadCheckpointFile(in.checkpointPath)
		if lerr != nil {
			return freshnessOutcome{Err: lerr}
		}
		newAnchor, applied, aerr := verify.ApplyCheckpoint(in.syncedIssuedAt, in.syncedEpoch, cp, in.root, floor)
		if aerr != nil {
			return freshnessOutcome{Err: fmt.Errorf("freshness checkpoint: %w", aerr)}
		}
		anchor, checkpointApplied = newAnchor, applied
	}

	// R3 — the staleness → fail-policy decision (clock injected).
	dec, ferr := verify.EvaluateFreshness(in.syncedEpoch, anchor, policy, in.risk, now)
	dec.CheckpointReset = checkpointApplied
	return freshnessOutcome{Decision: dec, Err: ferr}
}

// loadCheckpointFile reads + JSON-decodes a FreshnessCheckpoint sidecar. A read
// or parse error is surfaced (not swallowed) so a malformed checkpoint the
// operator supplied is fail-closed at the call site.
func loadCheckpointFile(path string) (*verify.FreshnessCheckpoint, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("freshness checkpoint: read %s: %w", path, err)
	}
	var cp verify.FreshnessCheckpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		return nil, fmt.Errorf("freshness checkpoint: parse %s: %w", path, err)
	}
	return &cp, nil
}

// freshnessSummaryLine renders the honest one-line freshness verdict for the CLI
// output (SPEC-0279 R6 + the task's "honest output" requirement): the mode, the
// staleness, the risk, the fail-policy, and the open/closed outcome.
func freshnessSummaryLine(out freshnessOutcome, checkpointPath, emergencyPath string) string {
	d := out.Decision
	mode := "online-cadence"
	if checkpointPath != "" {
		mode = "offline-checkpoint"
	}
	parts := []string{
		"freshness[" + mode + "]",
		fmt.Sprintf("epoch=%d", d.Epoch),
		fmt.Sprintf("risk=%s", d.Risk),
	}
	if d.MaxStalenessSeconds == 0 {
		parts = append(parts, "max_staleness=none")
	} else {
		parts = append(parts, fmt.Sprintf("staleness=%ds/%ds", d.StalenessSeconds, d.MaxStalenessSeconds))
	}
	if d.CheckpointReset {
		parts = append(parts, "checkpoint=reset-clock")
	}
	if emergencyPath != "" {
		parts = append(parts, "emergency=consulted")
	}
	parts = append(parts, fmt.Sprintf("fail_policy=%s", d.FailPolicy))
	verdict := "ALLOW"
	if !d.Allowed {
		verdict = "DENY"
	}
	parts = append(parts, "→ "+verdict+" ("+d.Reason+")")
	return strings.Join(parts, " ")
}

// printFreshness writes the freshness summary to w (skipped when there is no
// ceiling AND no checkpoint/emergency, to keep the common case quiet).
func printFreshness(w io.Writer, out freshnessOutcome, checkpointPath, emergencyPath string) {
	d := out.Decision
	if d.MaxStalenessSeconds == 0 && checkpointPath == "" && emergencyPath == "" && !out.Emergency {
		return // no freshness policy in play — stay quiet.
	}
	fmt.Fprintln(w, freshnessSummaryLine(out, checkpointPath, emergencyPath))
}

// freshnessExitCode maps a freshness deny to its numeric process exit code:
//   - an emergency deny-list hit          → 17 (the SPEC-0198 revoke theme; the
//     token is burned NOW, same family as a revoked digest/agent).
//   - a stale-snapshot fail-closed        → 22 (verify.ExitRevocationStale).
//   - a present-but-bad checkpoint/emergency
//     file (registry-not-trusted)         → 12 (verify.ExitRegistryNotTrusted).
//   - nil error                           → 0.
func freshnessExitCode(out freshnessOutcome) int {
	if out.Err == nil {
		return exitOK
	}
	if out.Emergency {
		return exitBundleRevoked // 17
	}
	// verify.ExitCode handles ErrRevocationStale (22), ErrRegistryNotTrusted (12),
	// ErrIdentityRevoked (17), falling back to 1.
	return verify.ExitCode(out.Err)
}

// auditFreshnessDecision records EVERY freshness decision (SPEC-0279 R6) into the
// SPEC-0255 gate-audit trail — allow AND deny — so the verifier never fails open
// (or closed) on freshness without a durable record of (epoch, staleness, risk,
// fail_policy, outcome). Best-effort + panic-safe via appendGateEvent; never
// alters the verdict. `source` is the consumer ("verify-bundle" | "agentid" |
// "hook"); subject is the digest/agent the decision was about.
func auditFreshnessDecision(source, subject string, out freshnessOutcome) {
	home, _ := userHome()
	if home == "" {
		return
	}
	d := out.Decision
	decision := "allow"
	if !d.Allowed {
		decision = "deny"
	}
	reason := "freshness:" + d.Reason
	if out.Emergency {
		reason = "emergency_deny:" + out.EmergencyTok
	}
	appendGateEvent(home, gateEvent{
		Source:        source,
		Skill:         subject,
		Decision:      decision,
		Reason:        reason,
		ExitCode:      freshnessExitCode(out),
		ContentDigest: subject,
	})
}
