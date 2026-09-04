package auditevent

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestRedactHashScrubsSensitiveExt proves the default redactor replaces the value
// of a sensitively-named extension field with a sha256 pseudonym, so the raw
// secret never reaches a sink (REQ-5.4) while correlation survives (REQ-5.5).
func TestRedactHashScrubsSensitiveExt(t *testing.T) {
	e := New(EventPolicyAllow, OutcomeSuccess, SeverityInfo, "skillctl/x")
	secret := "Bearer sk-super-secret-token-value"
	for _, k := range []string{"authorization", "api_key", "refresh_token", "user_password"} {
		if err := e.SetExt(k, secret); err != nil {
			t.Fatalf("SetExt %q: %v", k, err)
		}
	}
	// A non-sensitive field must be left alone.
	if err := e.SetExt("gate.exit_code", 0); err != nil {
		t.Fatalf("SetExt: %v", err)
	}

	DefaultRedactor().Redact(e)

	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "super-secret") {
		t.Fatalf("secret survived redaction: %s", b)
	}
	for _, k := range []string{"authorization", "api_key", "refresh_token", "user_password"} {
		var v string
		if err := json.Unmarshal(e.Ext[k], &v); err != nil {
			t.Fatalf("ext %q not a string after redaction: %v", k, err)
		}
		if !strings.HasPrefix(v, "sha256:") {
			t.Fatalf("ext %q not pseudonymized: %q", k, v)
		}
	}
	// The non-sensitive field is untouched.
	if string(e.Ext["gate.exit_code"]) != "0" {
		t.Fatalf("non-sensitive field was altered: %s", e.Ext["gate.exit_code"])
	}
}

// TestRedactDropMode proves the drop mode replaces the value with the fixed
// marker rather than a hash.
func TestRedactDropMode(t *testing.T) {
	e := New(EventPolicyAllow, OutcomeSuccess, SeverityInfo, "skillctl/x")
	if err := e.SetExt("db_password", "hunter2"); err != nil {
		t.Fatalf("SetExt: %v", err)
	}
	r := Redactor{SensitiveKeyPatterns: []string{"password"}, Mode: RedactDrop}
	r.Redact(e)
	var v string
	if err := json.Unmarshal(e.Ext["db_password"], &v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if v != RedactedMarker {
		t.Fatalf("drop mode did not apply marker: %q", v)
	}
}

// TestRedactMessageCap proves an oversized Message is truncated (data
// minimization: a full LLM prompt/response cannot silently ride along, REQ-5.4).
func TestRedactMessageCap(t *testing.T) {
	e := New(EventSkillExecute, OutcomeSuccess, SeverityInfo, "skillctl/x")
	e.Message = strings.Repeat("A", DefaultMaxMessageBytes+500)
	DefaultRedactor().Redact(e)
	// After truncation the field is exactly the cap of raw content plus the
	// marker; the 500 excess bytes must be gone.
	if !strings.HasSuffix(e.Message, truncationMarker) {
		t.Fatalf("message not marked as truncated: ...%q", tail(e.Message))
	}
	if got := strings.Count(e.Message, "A"); got != DefaultMaxMessageBytes {
		t.Fatalf("raw content not minimized to the cap: kept %d 'A's, want %d", got, DefaultMaxMessageBytes)
	}
}

// TestRedactIdempotent proves running the default redactor twice is a no-op on
// the already-redacted value.
func TestRedactIdempotent(t *testing.T) {
	e := New(EventPolicyAllow, OutcomeSuccess, SeverityInfo, "skillctl/x")
	if err := e.SetExt("access_token", "abc123"); err != nil {
		t.Fatalf("SetExt: %v", err)
	}
	r := DefaultRedactor()
	r.Redact(e)
	first := string(e.Ext["access_token"])
	r.Redact(e)
	second := string(e.Ext["access_token"])
	if first != second {
		t.Fatalf("redaction not idempotent: %q -> %q", first, second)
	}
}

func tail(s string) string {
	if len(s) <= 20 {
		return s
	}
	return s[len(s)-20:]
}
