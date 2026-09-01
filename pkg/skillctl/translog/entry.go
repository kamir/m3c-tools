package translog

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// EventType enumerates the kinds of already-signed events whose DIGESTS get
// committed to the transparency log. We log the digest of the signed event,
// never the event payload itself (SPEC-0278 §5 — data stays off-log; only
// hashes/commitments are logged for EU data sovereignty).
type EventType string

const (
	// EventAdmit — a registry admit decision (a skill bundle was admitted).
	EventAdmit EventType = "admit"
	// EventAttest — a governance attestation (green/yellow/red verdict).
	EventAttest EventType = "attest"
	// EventRevoke — a revocation of a bundle/attestation.
	EventRevoke EventType = "revoke"
	// EventAgentIDIssue — an AgentID lifecycle issue/sign-off (SPEC-0277).
	EventAgentIDIssue EventType = "agentid-issue"
	// EventAgentIDRevoke — an AgentID revocation (SPEC-0277).
	EventAgentIDRevoke EventType = "agentid-revoke"
)

// validEventTypes is the closed acceptance set. An unknown event type is
// refused before it can be hashed into a leaf — the log's vocabulary is
// fixed, not open-ended.
var validEventTypes = map[EventType]struct{}{
	EventAdmit:         {},
	EventAttest:        {},
	EventRevoke:        {},
	EventAgentIDIssue:  {},
	EventAgentIDRevoke: {},
}

// IsValid reports whether t is one of the recognised event types.
func (t EventType) IsValid() bool {
	_, ok := validEventTypes[t]
	return ok
}

// entryDigestPattern matches the canonical digest form a LogEntry commits:
// "sha256:" followed by exactly 64 lowercase hex characters. This is the
// SAME form signing.CanonicalizeAttestationMessage / ...RevocationMessage
// already use, so an event's logged digest lines up 1:1 with the digest its
// signature was produced over.
var entryDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// entryTimestampPattern reuses the strict RFC3339-UTC-seconds shape used by
// the STH and the attestation/revocation envelopes.
var entryTimestampPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`)

// LogEntry errors.
var (
	// ErrEntryInvalid — a LogEntry failed structural validation.
	ErrEntryInvalid = errors.New("translog: invalid log entry")
)

// LogEntry is one append to the transparency log. It records WHAT KIND of
// signed event happened and the DIGEST of that event — never the event
// body. The canonical encoding (see Canonical) is what gets leaf-hashed
// (HashLeaf) into the Merkle tree.
//
// Field order in the struct does NOT define the canonical byte order;
// Canonical fixes that explicitly and deterministically.
type LogEntry struct {
	// Type is the event class (admit/attest/revoke/agentid-issue/
	// agentid-revoke).
	Type EventType `json:"type"`

	// Digest is the "sha256:<64 hex>" of the already-signed event. For an
	// attestation this is the attestation's bundle digest; for an admit it
	// is the admitted bundle's digest; for an AgentID event it is the
	// digest of the signed AgentID document. The point is that this is the
	// SAME bytes the event's own signature was computed over, so an
	// inclusion proof ties the log entry back to a verifiable signature.
	Digest string `json:"digest"`

	// Timestamp is when the event was logged, RFC3339 UTC seconds.
	Timestamp string `json:"timestamp"`

	// Subject is an optional, newline-free, human/machine identifier for
	// the event subject (e.g. a skill name, an identity id, an agent id).
	// It is bound into the canonical bytes so two events that share a
	// digest+type+timestamp but concern different subjects hash to distinct
	// leaves. Empty is allowed.
	Subject string `json:"subject,omitempty"`
}

// Validate runs strict structural checks. Called by Canonical before any
// bytes are produced so a malformed entry can never become a leaf hash.
func (e LogEntry) Validate() error {
	if !e.Type.IsValid() {
		return fmt.Errorf("%w: unknown event type %q", ErrEntryInvalid, e.Type)
	}
	if !entryDigestPattern.MatchString(e.Digest) {
		return fmt.Errorf("%w: digest %q must be sha256:<64 lowercase hex>", ErrEntryInvalid, e.Digest)
	}
	if !entryTimestampPattern.MatchString(e.Timestamp) {
		return fmt.Errorf("%w: timestamp %q must be RFC3339 UTC seconds", ErrEntryInvalid, e.Timestamp)
	}
	if strings.ContainsAny(e.Subject, "\n\r") {
		return fmt.Errorf("%w: subject must not contain newline characters", ErrEntryInvalid)
	}
	return nil
}

// Canonical returns the deterministic byte encoding of the entry that gets
// leaf-hashed. It follows the same sorted-canonical / LF-delimited pattern
// as the spine's other signed messages (attestation, revocation), with a
// leading "logentry-v1" tag so a leaf encoding can never be confused with
// any other signed-message family even before the 0x00 leaf prefix is
// applied.
//
// Format (UTF-8, LF-separated, trailing LF):
//
//	logentry-v1\n
//	<type>\n
//	<digest>\n
//	<timestamp>\n
//	<subject>\n        (may be empty, but the line is always present)
//
// Determinism: every field is a closed-vocabulary or strictly-patterned
// value, so the same logical event always yields identical bytes — a
// requirement for reproducible inclusion proofs across machines.
func (e LogEntry) Canonical() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString("logentry-v1")
	b.WriteByte('\n')
	b.WriteString(string(e.Type))
	b.WriteByte('\n')
	b.WriteString(e.Digest)
	b.WriteByte('\n')
	b.WriteString(e.Timestamp)
	b.WriteByte('\n')
	b.WriteString(e.Subject)
	b.WriteByte('\n')
	return []byte(b.String()), nil
}

// LeafHash returns the RFC-6962 leaf hash of the entry's canonical bytes:
// HashLeaf(Canonical()). This is what goes into the Merkle tree.
func (e LogEntry) LeafHash() ([HashSize]byte, error) {
	canon, err := e.Canonical()
	if err != nil {
		return [HashSize]byte{}, err
	}
	return HashLeaf(canon), nil
}
