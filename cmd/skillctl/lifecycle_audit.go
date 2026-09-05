package main

// lifecycle_audit.go: the install/verify audit producer (SPEC-0406 AC-07 / T15).
//
// WHAT WAS MISSING. SPEC-0403 built the shared skillctl.audit.v1 envelope and a
// complete taxonomy, and only the SPEC-0255 gate ever wrote to it. `install` and
// `verify` ran the whole §7 trust chain, refused artifacts, and left no record,
// so the SPEC-0406 acceptance matrix row T15 ("the tampering attempt is visible
// in the audit trail") could not pass. This file is the second producer.
//
// CRITICAL CONTRACT, identical to gate_audit.go and load-bearing for the same
// reason: this is fire-and-forget accountability, NOT a trust input.
// appendLifecycleEvent swallows every error and recovers from any panic, so a
// logging failure (read-only home, full disk, marshal panic, an unclassified
// reason) can NEVER change the install/verify exit code or its output. Callers
// invoke it as a bare statement and never branch on a result.
//
// The direction of that rule matters and is easy to get backwards: an audit
// system that can refuse an install has become a trust component, and then its
// own availability is part of the attack surface. It is not one here.
//
// WHY A SEPARATE FILE FROM gate-audit.jsonl. Same envelope, same directory,
// different volume and different half-life. The gate log is high-frequency
// telemetry from every tool call; the lifecycle log is a handful of lines per
// day, each one a trust decision somebody may have to defend years later.
// Mixing them would make retention a single compromise between the two, and the
// SPEC-0406 evidence question ("show me the refusals") would start with a
// filter instead of a file.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/auditevent"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// lifecycleAuditMaxBytes bounds the live log; beyond it the file rotates to
// lifecycle-audit.jsonl.1 (single generation). A var, not a const, so a test can
// exercise rotation without writing megabytes.
var lifecycleAuditMaxBytes int64 = 5 << 20 // 5 MiB

// lifecycleAuditPath reuses verdictDir so the ~/.claude/skillctl 0700 convention
// is identical to the verdict cache and the gate log.
func lifecycleAuditPath(home string) string {
	return filepath.Join(verdictDir(home), "lifecycle-audit.jsonl")
}

// lifecycleAuditSink is the write seam. A test injects a failing sink to prove
// the install/verify exit code is unchanged when logging fails: the whole point
// of the decision-invariance contract above.
var lifecycleAuditSink = defaultLifecycleAuditSink

func defaultLifecycleAuditSink(home string, line []byte) error {
	dir := verdictDir(home)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := lifecycleAuditPath(home)
	// Best-effort size rotation BEFORE the append. A lost rotation race just
	// means one extra line in the old generation.
	if fi, err := os.Stat(path); err == nil && fi.Size() >= lifecycleAuditMaxBytes {
		_ = os.Rename(path, path+".1")
	}
	// #nosec G304 -- `path` is lifecycleAuditPath(home) under the caller's OWN
	// resolved home (the --home flag or $HOME). It is the operator choosing where
	// their own audit log lives on their own machine, not attacker-controlled
	// input crossing a boundary: anyone who can set --home can already write the
	// file directly. Same construction as gate_audit.go and invocation_trail.go.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(line, '\n'))
	return err
}

// lifecycleReason resolves a verifier error into the stable audit reason code.
//
// The order mirrors verify.ExitCode deliberately: that function is the shipped
// definition of "which failure won", and a second, independently-ordered switch
// would eventually disagree with it and put one cause in the exit code and a
// different one in the audit record. A test pins the two against each other.
//
// A nil error is ReasonOK. An error nobody classified is ReasonInternalError,
// never a refusal: reporting an unrecognised fault as a policy denial would
// inflate the refusal count with our own bugs.
func lifecycleReason(err error) auditevent.ReasonCode {
	switch {
	case err == nil:
		return auditevent.ReasonOK
	case errors.Is(err, verify.ErrDigestMismatch):
		return auditevent.ReasonDigestMismatch
	case errors.Is(err, verify.ErrAuthorSigInvalid):
		return auditevent.ReasonAuthorSigInvalid
	case errors.Is(err, verify.ErrRegistryNotTrusted):
		return auditevent.ReasonRegistryNotTrusted
	case errors.Is(err, verify.ErrGovernanceBelowMin):
		return auditevent.ReasonGovernanceBelowMin
	case errors.Is(err, verify.ErrDepsUnsatisfied):
		return auditevent.ReasonDepsUnsatisfied
	case errors.Is(err, verify.ErrBlobMissing):
		return auditevent.ReasonBlobMissing
	case errors.Is(err, verify.ErrTenantBlocked):
		return auditevent.ReasonTenantBlocked
	case errors.Is(err, verify.ErrIntentInconsistent):
		return auditevent.ReasonIntentInconsistent
	case errors.Is(err, verify.ErrIdentityMismatch):
		return auditevent.ReasonIdentityMismatch
	case errors.Is(err, verify.ErrIdentityRevoked):
		return auditevent.ReasonIdentityRevoked
	case errors.Is(err, verify.ErrDataSourceDenied):
		return auditevent.ReasonDataSourceDenied
	case errors.Is(err, verify.ErrSelfAttested):
		return auditevent.ReasonSelfAttested
	case errors.Is(err, verify.ErrRevocationStale):
		return auditevent.ReasonRevocationStale
	case errors.Is(err, verify.ErrLogInclusionMissing):
		return auditevent.ReasonLogInclusionMissing
	default:
		return auditevent.ReasonInternalError
	}
}

// lifecycleReasonFor resolves the reason from BOTH the captured error and the
// exit code, and it exists because relying on the error alone was wrong.
//
// The bug it fixes, found by running the real binary rather than the test: a
// refusal path that returns a numbered code without routing its error through
// the audit variable produced `outcome: success` next to `exit_code: 1`. A
// refusal recorded as a success is the single worst record this log can hold,
// and it happened on the FIRST branch anyone checked.
//
// Discipline at every return was the wrong mechanism, because there are many
// returns and one missed branch is silent. So the invariant is structural
// instead: a non-zero exit can never be a success, whatever the caller did or
// forgot to do. An unattributed failure becomes an internal error, which is the
// honest reading (we do not know why) and never inflates the refusal count.
func lifecycleReasonFor(code int, err error) auditevent.ReasonCode {
	if err != nil {
		return lifecycleReason(err)
	}
	if code == exitOK {
		return auditevent.ReasonOK
	}
	return auditevent.ReasonInternalError
}

// appendLifecycleEvent records one install or verify outcome.
//
// Fire-and-forget: any error or panic is swallowed. Fills Ts when the caller
// left it empty. `home` is the resolved install root; an empty home means there
// is nowhere to write and the call is skipped (a pre-home usage error, which is
// not a trust decision and does not belong in this log anyway).
func appendLifecycleEvent(home string, ev auditevent.LifecycleEvent) {
	defer func() { _ = recover() }()
	if home == "" {
		return
	}
	if ev.Ts == "" {
		ev.Ts = time.Now().UTC().Format(time.RFC3339)
	}
	e, err := auditevent.FromLifecycleEvent(ev, "skillctl/"+version)
	if err != nil {
		return // an unclassified reason costs a line, never a decision.
	}
	_ = newLifecycleAuditDispatcher(home).Dispatch(e)
}

// newLifecycleAuditDispatcher builds the best-effort dispatcher for this
// producer. Redaction is the package default, the same one the gate uses: the
// two producers must not disagree about what may be written down.
func newLifecycleAuditDispatcher(home string) *auditevent.Dispatcher {
	return auditevent.NewDispatcher(auditevent.DefaultRedactor(), &lifecycleAuditSeamSink{home: home})
}

// lifecycleAuditSeamSink adapts auditevent.Sink onto the injectable write seam.
type lifecycleAuditSeamSink struct{ home string }

func (s *lifecycleAuditSeamSink) Name() string { return "lifecycle-audit" }
func (s *lifecycleAuditSeamSink) Close() error { return nil }
func (s *lifecycleAuditSeamSink) Write(e *auditevent.Event) error {
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return lifecycleAuditSink(s.home, line)
}
