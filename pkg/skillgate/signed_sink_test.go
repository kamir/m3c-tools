package skillgate

import "testing"

func gateWithEnvelope(sink SignedSink) *Gate {
	return &Gate{
		Token: &Token{
			TokenID:      "ct:test",
			SkillName:    "didactic-session",
			SkillVersion: "1.0.0",
			BundleDigest: "sha256:abc",
			TenantScope:  "kup-berlin",
			ExpiresAt:    "2999-01-01T00:00:00Z",
			Envelope: TokenEnvelope{
				Capabilities:        []string{"subprocess_run:bash"},
				SubprocessAllowlist: []string{"bash"},
			},
		},
		SessionID:  "sess:123",
		SignedSink: sink,
	}
}

func TestSignedSink_FiresOnAllow(t *testing.T) {
	var got []InvocationRecord
	g := gateWithEnvelope(func(r InvocationRecord) { got = append(got, r) })
	if err := g.Allow(Subprocess{Name: "bash"}); err != nil {
		t.Fatalf("expected allow, got %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("SignedSink fired %d times, want 1", len(got))
	}
	r := got[0]
	if r.EventType != "gate.allowed" || r.RefusalCode != "" || r.ExitCode != 0 {
		t.Errorf("allow record wrong: %+v", r)
	}
	if r.SkillName != "didactic-session" || r.TokenID != "ct:test" || r.SessionID != "sess:123" {
		t.Errorf("record metadata not stamped: %+v", r)
	}
}

func TestSignedSink_FiresOnRefuse(t *testing.T) {
	var got []InvocationRecord
	g := gateWithEnvelope(func(r InvocationRecord) { got = append(got, r) })
	// curl is not in the allowlist and subprocess_run:curl is not a capability.
	if err := g.Allow(Subprocess{Name: "curl"}); err == nil {
		t.Fatalf("expected refusal")
	}
	if len(got) != 1 {
		t.Fatalf("SignedSink fired %d times, want 1", len(got))
	}
	r := got[0]
	if r.EventType != "gate.refused" || r.RefusalCode == "" || r.ExitCode == 0 {
		t.Errorf("refuse record wrong: %+v", r)
	}
}

func TestSignedSink_NilIsSafe(t *testing.T) {
	// A nil SignedSink must not panic and must not alter the decision.
	g := gateWithEnvelope(nil)
	if err := g.Allow(Subprocess{Name: "bash"}); err != nil {
		t.Fatalf("nil sink changed the allow decision: %v", err)
	}
}
