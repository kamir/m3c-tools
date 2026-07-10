package skillgate

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

// sampleRecord is a fully-populated v1 record with the P3 identity fields left
// empty (as v1 requires).
func sampleRecord() *InvocationRecord {
	return &InvocationRecord{
		Schema:        InvocationSchema,
		EventID:       "01HZZZEVENTID0000000000000",
		EventType:     "skill.invocation",
		SkillDigest:   "sha256:" + strings.Repeat("a", 64),
		SkillName:     "didactic-session",
		SkillVersion:  "1.0.0",
		Action:        "invoke",
		Tool:          "skill",
		TokenID:       "ct:01HZZZTOKEN0000000000000",
		SessionID:     "sess:01HZZZSESSION00000000000",
		OccurredAt:    "2026-06-23T14:03:11Z",
		AgentIdentity: "", // v1: empty placeholder
		OwnerIdentity: "", // v1: empty placeholder
		DeviceKeyID:   "device:0123456789abcdef",
		ExitCode:      0,
		RefusalCode:   "",
	}
}

func TestCanonicalize_GoldenBytes(t *testing.T) {
	got, err := CanonicalizeInvocationRecord(sampleRecord())
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	want := strings.Join([]string{
		"invocation_event_v1",
		"schema=m3c-skill-invocation/v1",
		"event_id=01HZZZEVENTID0000000000000",
		"event_type=skill.invocation",
		"skill_digest=sha256:" + strings.Repeat("a", 64),
		"skill_name=didactic-session",
		"skill_version=1.0.0",
		"action=invoke",
		"tool=skill",
		"token_id=ct:01HZZZTOKEN0000000000000",
		"session_id=sess:01HZZZSESSION00000000000",
		"occurred_at=2026-06-23T14:03:11Z",
		"agent_identity=",
		"owner_identity=",
		"device_key_id=device:0123456789abcdef",
		"exit_code=0",
		"refusal_code=",
		"", // trailing LF after the last line
	}, "\n")
	if string(got) != want {
		t.Fatalf("canonical bytes mismatch:\n--- got ---\n%q\n--- want ---\n%q", string(got), want)
	}
	// Last byte MUST be LF (every line LF-terminated, including the last).
	if got[len(got)-1] != '\n' {
		t.Errorf("canonical bytes do not end with LF")
	}
}

func TestCanonicalize_EmptyPlaceholderLinesAlwaysPresent(t *testing.T) {
	// Forward-compat proof: the agent_identity / owner_identity lines are
	// emitted EVEN when empty. This is what lets SPEC-0277 P3 populate them as a
	// value change rather than a format break.
	got, _ := CanonicalizeInvocationRecord(sampleRecord())
	s := string(got)
	if !strings.Contains(s, "\nagent_identity=\n") {
		t.Errorf("agent_identity placeholder line missing/non-empty framing")
	}
	if !strings.Contains(s, "\nowner_identity=\n") {
		t.Errorf("owner_identity placeholder line missing/non-empty framing")
	}

	// And the proof that populating them is a pure VALUE change: set them and
	// confirm ONLY those two lines differ (line count identical, same order).
	r2 := sampleRecord()
	r2.AgentIdentity = "agent:inst-01"
	r2.OwnerIdentity = "id:kamir@m3c"
	got2, _ := CanonicalizeInvocationRecord(r2)
	l1 := strings.Split(string(got), "\n")
	l2 := strings.Split(string(got2), "\n")
	if len(l1) != len(l2) {
		t.Fatalf("line count changed when populating P3 fields: %d vs %d", len(l1), len(l2))
	}
	diffs := 0
	for i := range l1 {
		if l1[i] != l2[i] {
			diffs++
		}
	}
	if diffs != 2 {
		t.Errorf("populating agent+owner changed %d lines, want exactly 2", diffs)
	}
}

func TestSignVerify_RoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	r := sampleRecord()
	err := SignInvocationRecord(r, func(m []byte) []byte { return ed25519.Sign(priv, m) }, base64.StdEncoding.EncodeToString)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if r.DeviceSignatureB64 == "" {
		t.Fatalf("signature not stamped")
	}
	if !VerifyInvocationRecord(r, pub, base64.StdEncoding.DecodeString) {
		t.Errorf("round-trip verify failed")
	}
}

func TestVerify_TamperRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	r := sampleRecord()
	_ = SignInvocationRecord(r, func(m []byte) []byte { return ed25519.Sign(priv, m) }, base64.StdEncoding.EncodeToString)

	// Tamper with a signed field — verification MUST fail (the signature no
	// longer covers the canonical bytes).
	tampered := *r
	tampered.Tool = "attacker.example"
	if VerifyInvocationRecord(&tampered, pub, base64.StdEncoding.DecodeString) {
		t.Errorf("verify accepted a tampered tool field")
	}

	// Tamper with exit_code.
	tampered2 := *r
	tampered2.ExitCode = 1
	if VerifyInvocationRecord(&tampered2, pub, base64.StdEncoding.DecodeString) {
		t.Errorf("verify accepted a tampered exit_code")
	}

	// Wrong key rejects.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if VerifyInvocationRecord(r, otherPub, base64.StdEncoding.DecodeString) {
		t.Errorf("verify accepted under the wrong public key")
	}
}

func TestVerify_FailClosed_OnBadInputs(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if VerifyInvocationRecord(nil, pub, base64.StdEncoding.DecodeString) {
		t.Errorf("nil record verified")
	}
	r := sampleRecord()
	if VerifyInvocationRecord(r, pub, base64.StdEncoding.DecodeString) {
		t.Errorf("record with empty signature verified")
	}
	r.DeviceSignatureB64 = "!!!not-base64!!!"
	if VerifyInvocationRecord(r, pub, base64.StdEncoding.DecodeString) {
		t.Errorf("record with garbage signature verified")
	}
	// short pubkey
	r2 := sampleRecord()
	_ = SignInvocationRecord(r2, func(m []byte) []byte { return make([]byte, 64) }, base64.StdEncoding.EncodeToString)
	if VerifyInvocationRecord(r2, ed25519.PublicKey{1, 2, 3}, base64.StdEncoding.DecodeString) {
		t.Errorf("verify accepted a malformed public key")
	}
}

func TestCanonicalize_RejectsNewlineSmuggling(t *testing.T) {
	// A field carrying an embedded newline could forge a field boundary inside
	// the signed bytes. Canonicalize MUST refuse to produce bytes for it.
	r := sampleRecord()
	r.Tool = "skill\nrefusal_code=token_revoked"
	if _, err := CanonicalizeInvocationRecord(r); err == nil {
		t.Fatalf("canonicalize accepted a newline-smuggled field; want refusal")
	}
}

func TestReplay_DuplicateEventIDDetectable(t *testing.T) {
	// Replay defence lives at the trail level (dedup by event_id), but it is
	// only sound if event_id is BOUND into the signed bytes — so a replayed
	// signature can't be re-pointed at a fresh event_id without breaking the
	// signature. Prove: changing event_id changes the canonical bytes.
	a := sampleRecord()
	b := sampleRecord()
	b.EventID = "01HZZZDIFFERENT0000000000000"
	ca, _ := CanonicalizeInvocationRecord(a)
	cb, _ := CanonicalizeInvocationRecord(b)
	if string(ca) == string(cb) {
		t.Fatalf("event_id is not bound into the canonical bytes — replay protection unsound")
	}

	// And a naive replay tracker dedups by event_id.
	seen := map[string]bool{}
	record := func(r *InvocationRecord) bool {
		if seen[r.EventID] {
			return false // duplicate → replay
		}
		seen[r.EventID] = true
		return true
	}
	if !record(a) {
		t.Fatalf("first record should be accepted")
	}
	dup := sampleRecord() // same EventID as a
	if record(dup) {
		t.Errorf("duplicate event_id should be rejected as a replay")
	}
	if !record(b) {
		t.Errorf("distinct event_id should be accepted")
	}
}
