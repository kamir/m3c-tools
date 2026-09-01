package skillgate

import (
	"crypto/ed25519"
	"fmt"
	"strings"
)

// InvocationDomainSeparator is the first line of the canonical message for a
// SPEC-0202 per-invocation runtime envelope. It is DISTINCT from
// CanonicalDomainSeparator ("capability_v1") and from the SPEC-0188
// attestation domain ("attestation"), so a signature captured under one family
// can never replay as a signature under another — even with the same key.
//
// SPEC reference: SPEC-0202 §9 (per-host-signed invocation events).
const InvocationDomainSeparator = "invocation_event_v1"

// InvocationSchema is the schema tag carried in the record and the canonical
// bytes. Versioned so a future format change is a value change at a fixed line,
// not a silent reinterpretation.
const InvocationSchema = "m3c-skill-invocation/v1"

// InvocationRecord is one per-invocation runtime-envelope event: the durable,
// device-signed evidence that a specific skill invocation happened, what it
// did, and how it ended. It is the SPEC-0202 §9 "signed invocation event",
// recorded LOCALLY in the append-only invocation trail (the durable system of
// record; any HTTP upload is best-effort on top).
//
// IMPORTANT — emission is ALWAYS-ON: every invocation produces one of these,
// regardless of whether enforcement (capability tokens) is active. That is what
// makes the EU AI Act Art.12 trail complete by construction.
//
// The struct fields below split into TWO groups:
//   - the SIGNED fields, which feed CanonicalizeInvocationRecord in a fixed
//     order (see that function for the exact line schema);
//   - DeviceSignatureB64, the detached device signature, which is EXCLUDED from
//     the canonical input (a signature can't sign itself).
type InvocationRecord struct {
	// --- signed fields (fixed canonical order) ---

	Schema    string `json:"schema"`     // InvocationSchema
	EventID   string `json:"event_id"`   // ULID / random nonce — the replay key
	EventType string `json:"event_type"` // e.g. "skill.invocation", "gate.allowed", "gate.refused"

	SkillDigest  string `json:"skill_digest"`  // sha256:<hex> of the invoked bundle ("" if unknown)
	SkillName    string `json:"skill_name"`    //
	SkillVersion string `json:"skill_version"` //

	Action    string `json:"action"`     // the action surface (e.g. "subprocess", "egress", "invoke")
	Tool      string `json:"tool"`       // the tool/binary/host the action targeted
	TokenID   string `json:"token_id"`   // capability token id if enforcement was active ("" otherwise)
	SessionID string `json:"session_id"` // Claude Code session id — the P3 join key

	OccurredAt string `json:"occurred_at"` // RFC3339 UTC seconds, e.g. 2026-06-23T14:03:11Z

	// AgentIdentity and OwnerIdentity are SPEC-0277 (P3) forward-compat
	// PLACEHOLDERS. In v1 they are ALWAYS the empty string, but the canonical
	// message ALWAYS emits their lines (present-but-empty). This is the
	// load-bearing forward-compat property: when P3 populates them, the change
	// is a VALUE change at a fixed line — NOT a format break. Omitting the
	// lines now would force a domain/version bump later. DO NOT remove them.
	AgentIdentity string `json:"agent_identity"` // SPEC-0277 P3 — present-but-empty in v1
	OwnerIdentity string `json:"owner_identity"` // SPEC-0277 P3 — present-but-empty in v1

	DeviceKeyID string `json:"device_key_id"` // the signing device key's fingerprint
	ExitCode    int    `json:"exit_code"`     // child / action exit code (0 on allow)
	RefusalCode string `json:"refusal_code"`  // gate refusal_code on a refused event ("" otherwise)

	// --- NOT part of the canonical signed message ---

	DeviceSignatureB64 string `json:"device_signature_b64,omitempty"` // detached ed25519 over the canonical bytes
}

// CanonicalizeInvocationRecord produces the byte-identical signature payload
// for an InvocationRecord. Modeled on CanonicalizeToken / the SPEC-0188
// attestation canonical: domain-separated first line, LF-terminated lines
// (including the last), fixed field order, no JSON, no escaping ambiguity.
//
// Field order — line by line — is FIXED. Changing it (reorder, add, drop,
// alter a separator) is a breaking change and MUST come with a domain/version
// bump. The golden-bytes test pins this exact output.
//
//	invocation_event_v1
//	schema=<...>
//	event_id=<...>
//	event_type=<...>
//	skill_digest=<...>
//	skill_name=<...>
//	skill_version=<...>
//	action=<...>
//	tool=<...>
//	token_id=<...>
//	session_id=<...>
//	occurred_at=<...>
//	agent_identity=<empty-in-v1>
//	owner_identity=<empty-in-v1>
//	device_key_id=<...>
//	exit_code=<int>
//	refusal_code=<...>
//
// Every value is written verbatim after the "<key>=" prefix. Callers MUST reject
// any field containing a newline BEFORE signing (see validateNoNewlines) so the
// LF-delimited framing is unambiguous — a smuggled "\n" could otherwise forge a
// field boundary. The detached device_signature_b64 is excluded.
func CanonicalizeInvocationRecord(r *InvocationRecord) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("skillgate: nil invocation record")
	}
	if err := validateNoNewlines(r); err != nil {
		return nil, err
	}
	var b strings.Builder
	w := func(line string) { b.WriteString(line); b.WriteByte('\n') }

	w(InvocationDomainSeparator)
	w("schema=" + r.Schema)
	w("event_id=" + r.EventID)
	w("event_type=" + r.EventType)
	w("skill_digest=" + r.SkillDigest)
	w("skill_name=" + r.SkillName)
	w("skill_version=" + r.SkillVersion)
	w("action=" + r.Action)
	w("tool=" + r.Tool)
	w("token_id=" + r.TokenID)
	w("session_id=" + r.SessionID)
	w("occurred_at=" + r.OccurredAt)
	// SPEC-0277 P3 placeholders — ALWAYS emitted, empty in v1. See struct doc.
	w("agent_identity=" + r.AgentIdentity)
	w("owner_identity=" + r.OwnerIdentity)
	w("device_key_id=" + r.DeviceKeyID)
	w(fmt.Sprintf("exit_code=%d", r.ExitCode))
	w("refusal_code=" + r.RefusalCode)

	return []byte(b.String()), nil
}

// validateNoNewlines refuses any signed string field that contains a CR or LF.
// The canonical format is LF-delimited; a value with an embedded newline would
// let an attacker forge field boundaries inside the signed bytes. Fail-closed:
// we never sign over ambiguous bytes. (exit_code is an int — no check needed.)
func validateNoNewlines(r *InvocationRecord) error {
	fields := map[string]string{
		"schema":         r.Schema,
		"event_id":       r.EventID,
		"event_type":     r.EventType,
		"skill_digest":   r.SkillDigest,
		"skill_name":     r.SkillName,
		"skill_version":  r.SkillVersion,
		"action":         r.Action,
		"tool":           r.Tool,
		"token_id":       r.TokenID,
		"session_id":     r.SessionID,
		"occurred_at":    r.OccurredAt,
		"agent_identity": r.AgentIdentity,
		"owner_identity": r.OwnerIdentity,
		"device_key_id":  r.DeviceKeyID,
		"refusal_code":   r.RefusalCode,
	}
	for name, v := range fields {
		if strings.ContainsAny(v, "\n\r") {
			return fmt.Errorf("skillgate: invocation field %q contains a newline; refusing to sign ambiguous bytes", name)
		}
	}
	return nil
}

// SignInvocationRecord canonicalizes the record, signs it with the device
// private key, and stamps the detached signature into r.DeviceSignatureB64
// (base64 std). The record's DeviceKeyID should already be set to the signing
// key's id so a verifier can look up the right public key.
//
// signFn is the device key's Sign method (k.Sign) — taking it as a closure keeps
// this package free of an import on pkg/skillctl/device (device imports skillgate
// indirectly via the record type at the call site, not vice-versa) and lets the
// gate use whatever signer it holds. b64 is injected too so the caller controls
// the exact encoding (std, no padding stripping).
func SignInvocationRecord(r *InvocationRecord, signFn func([]byte) []byte, b64 func([]byte) string) error {
	if r == nil {
		return fmt.Errorf("skillgate: nil record")
	}
	if signFn == nil || b64 == nil {
		return fmt.Errorf("skillgate: nil sign/encode func")
	}
	msg, err := CanonicalizeInvocationRecord(r)
	if err != nil {
		return err
	}
	sig := signFn(msg)
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("skillgate: device signature wrong length %d (want %d)", len(sig), ed25519.SignatureSize)
	}
	r.DeviceSignatureB64 = b64(sig)
	return nil
}

// VerifyInvocationRecord re-canonicalizes the record and verifies its detached
// device signature against pub. Fail-closed: any decode/length/parse problem
// returns false, never a partial accept.
//
// decode is injected (the inverse of the b64 used to sign) so this package
// stays encoding-agnostic and the caller pins the exact alphabet.
func VerifyInvocationRecord(r *InvocationRecord, pub ed25519.PublicKey, decode func(string) ([]byte, error)) bool {
	if r == nil || decode == nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	if r.DeviceSignatureB64 == "" {
		return false
	}
	sig, err := decode(r.DeviceSignatureB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	msg, err := CanonicalizeInvocationRecord(r)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, msg, sig)
}
