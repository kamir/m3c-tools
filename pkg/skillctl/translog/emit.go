package translog

import (
	"time"
)

// Best-effort emit helpers for wiring the transparency log into the
// existing admit/attest/revoke/agentid emit points.
//
// CONTRACT (mirrors the SPEC-0202 audit-trail pattern): logging an event is
// BEST-EFFORT and MUST NEVER alter the primary decision. A caller appends
// to the log AFTER the signed event already exists; if the append fails
// (disk full, permission, etc.) the caller logs the error and proceeds —
// the absence of a log entry is later surfaced by the verifier's inclusion
// check (advisory by default, hard only under require_log_inclusion), not
// by breaking the admit/attest/revoke operation itself.
//
// These helpers exist so the call sites don't each re-derive the canonical
// LogEntry shape. They return the assigned index and any error; callers
// treat the error as advisory.

// EmitAdmit appends an admit event (a bundle was admitted). digest is the
// "sha256:<hex>" of the admitted bundle; subject is the skill name (or "").
func EmitAdmit(l *Log, digest, subject string, t time.Time) (int, error) {
	return l.Append(LogEntry{
		Type:      EventAdmit,
		Digest:    digest,
		Timestamp: FormatSTHTimestamp(t),
		Subject:   subject,
	})
}

// EmitAttest appends a governance attestation event. digest is the attested
// bundle digest; subject may carry the governance level or reviewer.
func EmitAttest(l *Log, digest, subject string, t time.Time) (int, error) {
	return l.Append(LogEntry{
		Type:      EventAttest,
		Digest:    digest,
		Timestamp: FormatSTHTimestamp(t),
		Subject:   subject,
	})
}

// EmitRevoke appends a revocation event. digest is the revoked bundle
// digest; subject may carry the actor role.
func EmitRevoke(l *Log, digest, subject string, t time.Time) (int, error) {
	return l.Append(LogEntry{
		Type:      EventRevoke,
		Digest:    digest,
		Timestamp: FormatSTHTimestamp(t),
		Subject:   subject,
	})
}

// EmitAgentIDIssue appends an AgentID issue/sign-off event (SPEC-0277).
// digest is the digest of the signed AgentID document; subject is the agent
// id.
func EmitAgentIDIssue(l *Log, digest, agentID string, t time.Time) (int, error) {
	return l.Append(LogEntry{
		Type:      EventAgentIDIssue,
		Digest:    digest,
		Timestamp: FormatSTHTimestamp(t),
		Subject:   agentID,
	})
}

// EmitAgentIDRevoke appends an AgentID revocation event (SPEC-0277).
func EmitAgentIDRevoke(l *Log, digest, agentID string, t time.Time) (int, error) {
	return l.Append(LogEntry{
		Type:      EventAgentIDRevoke,
		Digest:    digest,
		Timestamp: FormatSTHTimestamp(t),
		Subject:   agentID,
	})
}
