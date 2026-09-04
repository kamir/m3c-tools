package auditevent

// redaction.go: data minimization (SPEC-0403 §5.1). Audit logs MUST NOT carry
// passwords, private keys, access/refresh tokens, authorization headers, raw
// credentials, secret env vars, FULL LLM prompts, FULL LLM responses, FULL
// reference documents, or PII unless policy demands it (REQ-5.4). Where a
// sensitive value is needed for correlation, a digest or stable pseudonym is
// used instead (REQ-5.5). Redaction is policy-driven and configurable (REQ-5.6).
//
// SCOPE (FR-0109). This is the foundation: a configurable key-pattern scrub over
// extension fields plus a size cap on the free-text Message (the field into
// which a full prompt/response would most easily leak). The canonical struct
// fields are digest-shaped by design (SkillRef.Digest, ReferenceRef.Digest);
// they carry identifiers, never contents; so there is nothing to scrub there.
// Deeper content classification is a policy concern layered on top later.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// RedactionMode selects how a matched sensitive value is neutralized.
type RedactionMode int

const (
	// RedactDrop replaces a matched value with a fixed marker; nothing about the
	// original survives.
	RedactDrop RedactionMode = iota
	// RedactHash replaces a matched value with "sha256:<12 hex>"; a stable
	// pseudonym that still permits correlation (REQ-5.5) without exposing the
	// value.
	RedactHash
)

// RedactedMarker is the placeholder RedactDrop substitutes for a sensitive value.
const RedactedMarker = "[REDACTED]"

// DefaultMaxMessageBytes caps the free-text Message so a full prompt/response
// cannot silently ride along in it (REQ-5.4). Oversized messages are truncated.
const DefaultMaxMessageBytes = 4096

// truncationMarker is appended to a Message truncated by the size cap.
const truncationMarker = "…[truncated]"

// Redactor minimizes an Event before it reaches any sink. The zero value does
// nothing; use DefaultRedactor for the standard policy.
type Redactor struct {
	// SensitiveKeyPatterns are lowercase substrings; any Ext key whose lowercased
	// name contains one is redacted (REQ-5.4/5.6).
	SensitiveKeyPatterns []string
	// Mode selects drop vs. hash for a matched value.
	Mode RedactionMode
	// MaxMessageBytes caps Event.Message; 0 disables the cap.
	MaxMessageBytes int
}

// defaultSensitiveKeyPatterns enumerates the categories REQ-5.4 forbids, matched
// as case-insensitive substrings of an extension-field key.
var defaultSensitiveKeyPatterns = []string{
	"password", "passwd", "secret", "token", "authorization", "auth_header",
	"api_key", "apikey", "access_key", "private_key", "privatekey", "credential",
	"prompt", "completion", "response_body", "refresh", "cookie", "bearer",
}

// DefaultRedactor returns the standard §5.1 policy: hash the values of
// sensitively-named extension fields (so correlation survives, REQ-5.5) and cap
// the free-text Message at DefaultMaxMessageBytes.
func DefaultRedactor() Redactor {
	patterns := make([]string, len(defaultSensitiveKeyPatterns))
	copy(patterns, defaultSensitiveKeyPatterns)
	return Redactor{
		SensitiveKeyPatterns: patterns,
		Mode:                 RedactHash,
		MaxMessageBytes:      DefaultMaxMessageBytes,
	}
}

// Redact minimizes e in place: it scrubs sensitively-named extension fields and
// caps the Message length. It is idempotent; running it twice is a no-op after
// the first; and safe on a nil-Ext event.
func (r Redactor) Redact(e *Event) {
	if e == nil {
		return
	}
	for key, raw := range e.Ext {
		if r.isSensitiveKey(key) {
			e.Ext[key] = r.redactValue(raw)
		}
	}
	if r.MaxMessageBytes > 0 && len(e.Message) > r.MaxMessageBytes {
		e.Message = e.Message[:r.MaxMessageBytes] + truncationMarker
	}
}

// isSensitiveKey reports whether key contains any configured sensitive substring.
func (r Redactor) isSensitiveKey(key string) bool {
	lower := strings.ToLower(key)
	for _, p := range r.SensitiveKeyPatterns {
		if p != "" && strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// redactValue neutralizes one raw JSON value per the configured mode, returning a
// JSON string token. An already-redacted value is left unchanged so Redact is
// idempotent.
func (r Redactor) redactValue(raw json.RawMessage) json.RawMessage {
	if isRedactedValue(raw) {
		return raw
	}
	if r.Mode == RedactHash {
		sum := sha256.Sum256(raw)
		token := "sha256:" + hex.EncodeToString(sum[:])[:12]
		out, _ := json.Marshal(token) //nolint:errcheck // marshaling a constant string cannot fail.
		return out
	}
	out, _ := json.Marshal(RedactedMarker) //nolint:errcheck // marshaling a constant string cannot fail.
	return out
}

// isRedactedValue reports whether raw is already a redaction token (the drop
// marker or a "sha256:<12 hex>" pseudonym), so a second Redact pass is a no-op.
func isRedactedValue(raw json.RawMessage) bool {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return false // not a JSON string; never a redaction token.
	}
	if s == RedactedMarker {
		return true
	}
	const prefix = "sha256:"
	if !strings.HasPrefix(s, prefix) || len(s) != len(prefix)+12 {
		return false
	}
	for i := len(prefix); i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
