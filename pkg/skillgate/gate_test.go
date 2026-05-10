package skillgate

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"
)

// helper — build a token signed by the given key.
func newSignedToken(t *testing.T, priv ed25519.PrivateKey, keyID string, env TokenEnvelope, expiresIn time.Duration) *Token {
	t.Helper()
	now := time.Now().UTC()
	tok := &Token{
		Schema:         "m3c-skill-capability/v1",
		TokenID:        "ct:01HZTESTTESTTESTTESTTESTTE",
		IssuedAt:       now.Format("2006-01-02T15:04:05Z"),
		ExpiresAt:      now.Add(expiresIn).Format("2006-01-02T15:04:05Z"),
		BundleDigest:   "sha256:abc",
		SkillName:      "test-skill",
		SkillVersion:   "0.1.0",
		CallerIdentity: "id:tester",
		CallerSession:  "sess:01HZSESSIONSESSIONSESSIO",
		Envelope:       env,
		RegistryKeyID:  keyID,
	}
	msg, err := CanonicalizeToken(tok)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	tok.SignatureB64 = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))
	return tok
}

func newGate(tok *Token) (*Gate, *NopPoster) {
	posted := &NopPoster{}
	return &Gate{
		Token:       tok,
		AuditPoster: posted,
	}, posted
}

// -------- subprocess --------

func TestGate_Subprocess_Allowed(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	_ = pub
	tok := newSignedToken(t, priv, "k1", TokenEnvelope{
		Capabilities:        []string{"subprocess_run"},
		SubprocessAllowlist: []string{"git"},
	}, time.Hour)
	g, _ := newGate(tok)
	if err := g.Allow(Subprocess{Name: "git", Args: []string{"status"}}); err != nil {
		t.Fatalf("expected allow, got %v", err)
	}
}

func TestGate_Subprocess_DenylistBeatsAllowlist(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	tok := newSignedToken(t, priv, "k1", TokenEnvelope{
		Capabilities:        []string{"subprocess_run"},
		SubprocessAllowlist: []string{"bash"},
		SubprocessDenylist:  []string{"bash"},
	}, time.Hour)
	g, _ := newGate(tok)
	err := g.Allow(Subprocess{Name: "bash"})
	ge, ok := err.(*GateError)
	if !ok {
		t.Fatalf("want GateError, got %T %v", err, err)
	}
	if ge.Code != RefusalSubprocessDenied || ge.ExitCode != ExitSubprocessDenied {
		t.Errorf("want denied (exit 33), got code=%s exit=%d", ge.Code, ge.ExitCode)
	}
}

func TestGate_Subprocess_NotInAllowlist(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	tok := newSignedToken(t, priv, "k1", TokenEnvelope{
		Capabilities:        []string{"subprocess_run"},
		SubprocessAllowlist: []string{"git"},
	}, time.Hour)
	g, _ := newGate(tok)
	err := g.Allow(Subprocess{Name: "rm"})
	ge, ok := err.(*GateError)
	if !ok || ge.Code != RefusalSubprocessNotAllowed {
		t.Fatalf("want subprocess_not_allowed, got %v", err)
	}
}

func TestGate_Subprocess_MissingCapability(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	tok := newSignedToken(t, priv, "k1", TokenEnvelope{
		// No subprocess_run capability — even with allowlist, must refuse
		Capabilities:        []string{},
		SubprocessAllowlist: []string{"git"},
	}, time.Hour)
	g, _ := newGate(tok)
	err := g.Allow(Subprocess{Name: "git"})
	ge, ok := err.(*GateError)
	if !ok || ge.Code != RefusalCapabilityMissing {
		t.Fatalf("want capability_missing, got %v", err)
	}
}

// -------- egress --------

func TestGate_Egress_Allowed(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	tok := newSignedToken(t, priv, "k1", TokenEnvelope{
		Capabilities:    []string{"egress"},
		EgressAllowlist: []string{"api.example.com:443"},
	}, time.Hour)
	g, _ := newGate(tok)
	if err := g.Allow(Egress{Host: "api.example.com", Port: 443}); err != nil {
		t.Fatalf("expected allow, got %v", err)
	}
}

func TestGate_Egress_NotAllowed(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	tok := newSignedToken(t, priv, "k1", TokenEnvelope{
		Capabilities:    []string{"egress"},
		EgressAllowlist: []string{"api.example.com:443"},
	}, time.Hour)
	g, _ := newGate(tok)
	err := g.Allow(Egress{Host: "evil.example.com", Port: 80})
	ge, ok := err.(*GateError)
	if !ok || ge.Code != RefusalEgressNotAllowed || ge.ExitCode != ExitEgressNotAllowed {
		t.Fatalf("want egress_not_allowed exit 32, got %v", err)
	}
}

// -------- capability --------

func TestGate_Capability_Allowed(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	tok := newSignedToken(t, priv, "k1", TokenEnvelope{
		Capabilities: []string{"fs:read"},
	}, time.Hour)
	g, _ := newGate(tok)
	if err := g.Allow(Capability{Name: "fs:read"}); err != nil {
		t.Fatalf("expected allow, got %v", err)
	}
}

func TestGate_Capability_Missing(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	tok := newSignedToken(t, priv, "k1", TokenEnvelope{
		Capabilities: []string{"fs:read"},
	}, time.Hour)
	g, _ := newGate(tok)
	err := g.Allow(Capability{Name: "fs:write"})
	ge, ok := err.(*GateError)
	if !ok || ge.Code != RefusalCapabilityMissing {
		t.Fatalf("want capability_missing, got %v", err)
	}
}

// -------- destructive --------

func TestGate_Destructive_RequiresFlag(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	tok := newSignedToken(t, priv, "k1", TokenEnvelope{
		Destructive: false,
	}, time.Hour)
	g, _ := newGate(tok)
	err := g.Allow(Destructive{})
	ge, ok := err.(*GateError)
	if !ok || ge.Code != RefusalDestructiveRequired {
		t.Fatalf("want destructive_required, got %v", err)
	}
}

func TestGate_Destructive_AllowedWhenFlagged(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	tok := newSignedToken(t, priv, "k1", TokenEnvelope{
		Destructive: true,
	}, time.Hour)
	g, _ := newGate(tok)
	if err := g.Allow(Destructive{}); err != nil {
		t.Fatalf("expected allow, got %v", err)
	}
}

// -------- audit posting --------

type recordingPoster struct {
	events []InvocationEvent
}

func (r *recordingPoster) PostInvocation(ev InvocationEvent) error {
	r.events = append(r.events, ev)
	return nil
}

func TestGate_PostsAllowedEvent(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	tok := newSignedToken(t, priv, "k1", TokenEnvelope{
		Capabilities: []string{"fs:read"},
	}, time.Hour)
	rp := &recordingPoster{}
	g := &Gate{Token: tok, AuditPoster: rp}
	_ = g.Allow(Capability{Name: "fs:read"})
	if len(rp.events) == 0 || rp.events[0].Type != "gate.allowed" {
		t.Fatalf("expected gate.allowed event, got %+v", rp.events)
	}
}

func TestGate_PostsRefusedEvent(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	tok := newSignedToken(t, priv, "k1", TokenEnvelope{
		Capabilities: []string{"fs:read"},
	}, time.Hour)
	rp := &recordingPoster{}
	g := &Gate{Token: tok, AuditPoster: rp}
	_ = g.Allow(Capability{Name: "fs:write"})
	if len(rp.events) == 0 || rp.events[0].Type != "gate.refused" {
		t.Fatalf("expected gate.refused event, got %+v", rp.events)
	}
	if rp.events[0].RefusalCode != RefusalCapabilityMissing {
		t.Errorf("refusal_code=%q want %q", rp.events[0].RefusalCode, RefusalCapabilityMissing)
	}
}

// -------- expiry --------

func TestGate_RefusesExpiredToken(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	tok := newSignedToken(t, priv, "k1", TokenEnvelope{
		Capabilities: []string{"fs:read"},
	}, -time.Minute) // already expired
	g, _ := newGate(tok)
	err := g.Allow(Capability{Name: "fs:read"})
	ge, ok := err.(*GateError)
	if !ok || ge.Code != RefusalExpired || ge.ExitCode != ExitTokenExpired {
		t.Fatalf("want expired exit 35, got %v", err)
	}
}

// -------- nil token --------

func TestGate_NilToken(t *testing.T) {
	g := &Gate{}
	err := g.Allow(Capability{Name: "fs:read"})
	if err == nil {
		t.Fatal("expected refusal on nil token")
	}
}
