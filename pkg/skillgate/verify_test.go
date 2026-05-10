package skillgate

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"
)

func makeTestToken(t *testing.T, priv ed25519.PrivateKey, keyID string, env TokenEnvelope, expiresIn time.Duration) *Token {
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

func makeRoots(keyID string, pub ed25519.PublicKey) *TrustRoots {
	return &TrustRoots{RegistryKeys: map[string][]byte{keyID: []byte(pub)}}
}

func TestVerify_HappyPath(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	tok := makeTestToken(t, priv, "k1", TokenEnvelope{Capabilities: []string{"fs:read"}}, time.Hour)
	res := Verify(tok, makeRoots("k1", pub))
	if !res.OK || res.Reason != "ok" {
		t.Fatalf("want ok, got OK=%v reason=%s", res.OK, res.Reason)
	}
}

func TestVerify_Expired(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	tok := makeTestToken(t, priv, "k1", TokenEnvelope{}, -time.Minute)
	res := Verify(tok, makeRoots("k1", pub))
	if res.OK || res.Reason != "expired" {
		t.Fatalf("want expired, got OK=%v reason=%s", res.OK, res.Reason)
	}
}

func TestVerify_BadSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	tok := makeTestToken(t, priv, "k1", TokenEnvelope{}, time.Hour)
	tok.SkillName = "tampered"
	res := Verify(tok, makeRoots("k1", pub))
	if res.OK || res.Reason != "bad_signature" {
		t.Fatalf("want bad_signature, got OK=%v reason=%s", res.OK, res.Reason)
	}
}

func TestVerify_UnknownIssuer(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	tok := makeTestToken(t, priv, "k1", TokenEnvelope{}, time.Hour)
	otherPub, _, _ := ed25519.GenerateKey(nil)
	res := Verify(tok, makeRoots("k2", otherPub)) // wrong key id
	if res.OK || res.Reason != "unknown_issuer" {
		t.Fatalf("want unknown_issuer, got OK=%v reason=%s", res.OK, res.Reason)
	}
}

func TestVerify_MalformedNoSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	tok := makeTestToken(t, priv, "k1", TokenEnvelope{}, time.Hour)
	tok.SignatureB64 = ""
	res := Verify(tok, makeRoots("k1", pub))
	if res.OK || res.Reason != "malformed" {
		t.Fatalf("want malformed, got OK=%v reason=%s", res.OK, res.Reason)
	}
}

func TestVerify_MalformedNoTrustRoots(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	tok := makeTestToken(t, priv, "k1", TokenEnvelope{}, time.Hour)
	res := Verify(tok, nil)
	if res.OK || res.Reason != "unknown_issuer" {
		t.Fatalf("want unknown_issuer (nil roots), got reason=%s", res.Reason)
	}
}

func TestVerify_NilToken(t *testing.T) {
	res := Verify(nil, &TrustRoots{})
	if res.OK || res.Reason != "malformed" {
		t.Fatalf("want malformed, got reason=%s", res.Reason)
	}
}

func TestVerify_AttenuationGrowsCapabilitiesFails(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	tok := makeTestToken(t, priv, "k1", TokenEnvelope{
		Capabilities: []string{"fs:read"},
	}, time.Hour)
	// Inject an attenuation that "grows" caps — a malicious chain.
	tok.Attenuations = []Attenuation{
		{
			AppliedAt: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
			AppliedBy: "id:attacker",
			Rule:      "grow_capabilities",
			Value:     map[string]any{"capabilities": []any{"fs:write"}},
		},
	}
	// Re-sign so step 3 (signature) passes; the chain check should still reject.
	msg, _ := CanonicalizeToken(tok)
	tok.SignatureB64 = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))
	res := Verify(tok, makeRoots("k1", pub))
	if res.OK {
		t.Fatalf("want chain rejection, got OK with reason=%s", res.Reason)
	}
}

func TestVerify_AttenuationChainTooDeep(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	tok := makeTestToken(t, priv, "k1", TokenEnvelope{}, time.Hour)
	for i := 0; i <= MaxChainDepth; i++ {
		tok.Attenuations = append(tok.Attenuations, Attenuation{
			AppliedAt: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
			AppliedBy: "id:tester",
			Rule:      "shrink_egress_allowlist",
			Value:     map[string]any{"egress_allowlist": []any{}},
		})
	}
	msg, _ := CanonicalizeToken(tok)
	tok.SignatureB64 = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))
	res := Verify(tok, makeRoots("k1", pub))
	if res.OK || res.Reason != "chain_too_deep" {
		t.Fatalf("want chain_too_deep, got OK=%v reason=%s", res.OK, res.Reason)
	}
}
