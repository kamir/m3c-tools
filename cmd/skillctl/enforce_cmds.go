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
	"io"

	"github.com/kamir/m3c-tools/pkg/skillctl/outbox"
	"github.com/kamir/m3c-tools/pkg/skillgate"
)

// enforceOutboxSink is the outbox-write seam. Production points it at
// defaultEnforceOutboxSink; the decision-invariance test injects a failing /
// panicking sink to prove exit+output are unchanged (AC-2a).
var enforceOutboxSink = defaultEnforceOutboxSink

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
	prev := invocationOutboxSink
	invocationOutboxSink = enforceOutboxSink
	defer func() { invocationOutboxSink = prev }()
	return runVerifyHook(stdin, stdout, stderr)
}

// defaultEnforceOutboxSink mirrors one fully-signed InvocationRecord into the
// SPEC-0317 outbox. It is called from inside appendSignedInvocation (already
// under a recover), but it defends itself as well so it is safe to call from any
// future seam. It NEVER returns an error to the caller: on any failure it either
// spools (AppendOrSpool) or drops silently, so the decision path is untouched.
func defaultEnforceOutboxSink(home string, rec skillgate.InvocationRecord) {
	defer func() { _ = recover() }()
	if home == "" {
		return // nowhere to anchor state (mirrors the trail sink's guard)
	}
	// Pin the exact signed bytes once (payload_json) + their hash, so the outbox
	// row is byte-consistent with the trail projection.
	payloadJSON, payloadHash, err := outbox.RecordPayload(rec)
	if err != nil {
		return // a record that refuses canonicalization is not evidence we can store
	}
	st, err := outbox.Open(home)
	if err != nil {
		return // fail-open on the WRITE only — never on the decision
	}
	defer st.Close()
	// AppendOrSpool: on SQLITE_BUSY / db error the row falls back to spool.jsonl
	// so a later `skillctl sync` Reconcile drains it. The returned error (only if
	// BOTH sinks fail) is intentionally ignored — decision-invariance wins.
	_ = st.AppendOrSpool(rec, payloadJSON, payloadHash)
}
