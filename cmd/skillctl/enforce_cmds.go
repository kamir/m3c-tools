package main

// enforce_cmds.go — `skillctl enforce` (SPEC-0317 P0).
//
// enforce is the enterprise-evidence twin of `verify-hook`: for a PreToolUse
// Skill event it makes the EXACT SAME allow/deny decision (AC-1 byte-parity),
// and additionally mirrors the resulting device-signed InvocationRecord into the
// authoritative SPEC-0317 outbox (audit_events, write-once) so the evidence is
// durable and later drainable to the KafShield ingest (P1 `skillctl sync`).
//
// Design — a pure silent router (the load-bearing byte-parity point):
//   - enforce does NOT re-classify, re-decide, or emit anything of its own. It
//     installs the outbox sink into the existing post-decision, fire-and-forget
//     emit seam (invocationOutboxSink, fed from appendSignedInvocation) and then
//     delegates the WHOLE decision to runVerifyHook. stdout, stderr, and the exit
//     code are therefore produced entirely by runVerifyHook — byte-identical to
//     `verify-hook` for an allow and for every deny class (AC-1).
//   - The outbox write rides the SAME seam that writes invocation-trail.jsonl,
//     never the hot decision path, and is fed the identical fully-signed record
//     (dual-sink consistency: one event_id / one signature to both sinks).
//   - The write happens BEFORE runEnforce returns: appendSignedInvocation runs in
//     runVerifyHook's deferred logger, which completes before the return value
//     propagates out through runEnforce.
//
// Decision-invariance (SPEC-0255, a LANDED contract — AC-2a): the sink is
// fire-and-forget. A forced outbox failure (SQLITE_BUSY at the ~250ms pin, a full
// disk, an open error, or an outright panic) is swallowed inside
// appendSignedInvocation's recover and its result is discarded, so exit + stdout
// + stderr stay byte-identical to the no-outbox path. On Append failure the row
// is spooled (AppendOrSpool) so the evidence is not lost either — but even a total
// double failure never alters the decision.

import (
	"fmt"
	"io"
	"os"

	"github.com/kamir/m3c-tools/pkg/skillctl/outbox"
	"github.com/kamir/m3c-tools/pkg/skillctl/pin"
	"github.com/kamir/m3c-tools/pkg/skillgate"
)

// enforceOutboxSink is the outbox-write seam. It returns whether the record was
// DURABLY recorded (outbox row OR spool line — AppendOrSpool==nil). The bool is
// consumed ONLY by the R-8.2 require_local_audit path in runEnforce; the default
// (flag unset) ignores it, so the fire-and-forget contract is untouched. The
// decision-invariance test injects a failing / panicking sink to prove exit+output
// are unchanged (AC-2a).
var enforceOutboxSink = defaultEnforceOutboxSink

// gateRequireLocalAudit reports whether the ROOT-OWNED managed settings enable the
// SPEC-0317 R-8.2 require_local_audit posture (enterprise-gated). Same source as
// the R-7.2 enterprise flag — one managed tier for both knobs. A missing/unreadable/
// malformed managed file → false (the carve-out is opt-in; absence is the default
// fire-and-forget behaviour). Seam: tests set it directly.
var gateRequireLocalAudit = func() bool {
	path, err := pin.DefaultManagedSettingsPath()
	if err != nil {
		return false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return pin.RequireLocalAuditFromBytes(b)
}

// runEnforce is the entrypoint for `skillctl enforce`. It returns the process
// exit code (0 = allow, 2 = deny/block) — the very same value runVerifyHook
// would return for the same event.
//
// It installs the outbox sink for the duration of the call and restores the
// previous value on return. Restoring matters only for tests (which run enforce
// and verify-hook in one process); in production each invocation is its own
// process. Setting the package-level seam is safe because skillctl handles one
// hook event per process — there is no concurrent gate in-process.
func runEnforce(stdin io.Reader, stdout, stderr io.Writer) int {
	reqAudit := gateRequireLocalAudit()

	// The sink is invoked once per GATED SKILL (from appendSignedInvocation, after
	// the decision). sinkCalled therefore distinguishes a real skill decision from a
	// non-Skill / no-skill passthrough allow — for which nothing is gated and
	// require_local_audit must NOT apply. durable = the record landed (outbox row or
	// spool line). Both are captured for the R-8.2 override below and otherwise ignored.
	var sinkCalled, durable bool
	prev := invocationOutboxSink
	invocationOutboxSink = func(h string, rec skillgate.InvocationRecord) {
		sinkCalled = true
		if enforceOutboxSink(h, rec) {
			durable = true
		}
	}
	defer func() { invocationOutboxSink = prev }()

	code := runVerifyHook(stdin, stdout, stderr)

	// SPEC-0317 R-8.2 — require_local_audit inverts the SPEC-0255 fire-and-forget
	// contract, OPT-IN via managed settings. It escalates a skill ALLOW whose
	// evidence could not be durably recorded (outbox row AND spool line both failed)
	// into a fail-closed deny (exit 26). A deny already stands (fail-closed); the
	// DEFAULT (flag unset) returns `code` unchanged, so decision-invariance / AC-2a
	// is preserved byte-for-byte. An allow emits nothing to stdout, so writing the
	// deny now is clean.
	//
	// SCOPE (breadth): "a skill ALLOW" means EVERY audited Skill decision the gate
	// allowed — managed, UNMANAGED (default-allow plugins / namespaced skills), AND
	// allowlisted. audActive is set before those branches, so all reach the sink.
	// So on a host whose outbox is unrecordable, turning on require_local_audit
	// denies the whole plugin ecosystem + the operator's allowlisted escapes too.
	// That is the intended enterprise posture ("no un-audited allow"), not a bug.
	//
	// The load-bearing store is the OUTBOX (+ its spool); the signed trail is a
	// best-effort projection. Because the sink spools even when outbox.Open fails
	// (defaultEnforceOutboxSink), durability tracks the SAME writable-dir condition
	// the trail write depends on — so the two land together or fail together, and a
	// fail-closed deny never coexists with a trail that recorded the allow.
	//
	// KNOWN NON-ESCALATED gaps (sink never reached → sinkCalled=false): home
	// unavailable, device key unavailable, sign-refusal (e.g. a newline-smuggled
	// field), or record marshal failure. A gated allow on such a degraded host is
	// NOT escalated — rare, and out of the disk-full case R-8.2 targets.
	if reqAudit && code == exitOK && sinkCalled && !durable {
		return emitDeny(stdout, stderr,
			fmt.Sprintf("skillctl: BLOCKED — require_local_audit is set but the enforcement event could not be durably recorded (outbox + spool both failed); refusing to allow un-audited (exit %d local_audit_unavailable, SPEC-0317 R-8.2).", exitLocalAuditUnavailable))
	}
	return code
}

// exitLocalAuditUnavailable is the semantic code carried in the R-8.2 fail-closed
// deny message. The PROCESS still exits exitHookBlock (2); the number rides the
// message, mirroring exitOfflineLocked / exitSidechannelDenied.
const exitLocalAuditUnavailable = 26 // = exitcode.LocalAuditUnavailable.Number

// defaultEnforceOutboxSink mirrors one fully-signed InvocationRecord into the
// SPEC-0317 outbox. It is called from inside appendSignedInvocation (already
// under a recover), but it defends itself as well so it is safe to call from any
// future seam. It NEVER returns an error to the caller: on any failure it either
// spools (AppendOrSpool) or drops silently, so the decision path is untouched.
func defaultEnforceOutboxSink(home string, rec skillgate.InvocationRecord) (durable bool) {
	defer func() {
		if recover() != nil {
			durable = false // a panic is not a durable write
		}
	}()
	if home == "" {
		return false // nowhere to anchor state (mirrors the trail sink's guard)
	}
	// Pin the exact signed bytes once (payload_json) + their hash, so the outbox
	// row is byte-consistent with the trail projection.
	payloadJSON, payloadHash, err := outbox.RecordPayload(rec)
	if err != nil {
		return false // a record that refuses canonicalization is not evidence we can store
	}
	st, err := outbox.Open(home)
	if err != nil {
		// Open ITSELF failed — e.g. a corrupt outbox.db on an otherwise-WRITABLE
		// dir. Do NOT give up: spool the row directly (no db I/O). This keeps
		// durability tracking the same writable-dir condition the signed trail
		// write depends on, so R-8.2 never fires a spurious deny (spool would have
		// worked) and never leaves the trail recording an allow the process denied.
		// A truly unwritable dir fails BOTH this spool and the trail → consistent.
		return outbox.SpoolTo(home, rec, payloadJSON, payloadHash) == nil
	}
	defer st.Close()
	// AppendOrSpool: on SQLITE_BUSY / db error the row falls back to spool.jsonl so a
	// later `skillctl sync` Reconcile drains it. It returns nil iff the outbox row OR
	// the spool line landed → durable. The default (fire-and-forget) path ignores
	// this bool; only R-8.2 require_local_audit consumes it.
	return st.AppendOrSpool(rec, payloadJSON, payloadHash) == nil
}
