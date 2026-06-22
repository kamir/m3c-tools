package verify

// SPEC-0276 R4.4 — signed offline revocation list.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"
)

func digestOf(s string) string {
	d := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(d[:])
}

func revocationRoot(t *testing.T, regPub ed25519.PublicKey) *TrustRoot {
	t.Helper()
	return &TrustRoot{
		RegistryURL: "https://reg.example/api/skills",
		RegistryKeys: []RegistryKey{{
			ID:        "reg-key-1",
			Pubkey:    []byte(regPub),
			PubkeyB64: base64.StdEncoding.EncodeToString(regPub),
		}},
		IdentityKeysAuthorized: "pinned",
		Authors:                []AuthorKey{{ID: "id:a@m3c", Pubkey: []byte(regPub), PubkeyB64: base64.StdEncoding.EncodeToString(regPub)}},
		GovernanceMinimum:      "green",
	}
}

func TestCanonicalRevocation_DeterministicAcrossOrderAndCase(t *testing.T) {
	a := digestOf("one")
	b := digestOf("two")
	c1, err := CanonicalRevocationBytes("https://reg.example/api/skills/", "2026-06-22T10:00:00Z", []string{a, b})
	if err != nil {
		t.Fatal(err)
	}
	// Reversed order + uppercased hex + a duplicate → identical canonical bytes.
	c2, err := CanonicalRevocationBytes("https://reg.example/api/skills", "2026-06-22T10:00:00Z", []string{bytesUpper(b), a, a})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c1, c2) {
		t.Fatalf("canonical bytes not order/case invariant:\n%s\n%s", c1, c2)
	}
}

func bytesUpper(s string) string { return string(bytes.ToUpper([]byte(s))) }

func TestRevocationList_SignVerifyRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := revocationRoot(t, pub)
	target := digestOf("revoke-me")
	list, err := NewSignedRevocationList(root.RegistryURL, "2026-06-22T10:00:00Z", []string{target, digestOf("other")}, priv)
	if err != nil {
		t.Fatal(err)
	}
	set, err := VerifyRevocationList(list, root)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if _, ok := set[target]; !ok {
		t.Errorf("target digest not in verified set")
	}
}

func TestRevocationList_ForgedSignatureRejected(t *testing.T) {
	_, attackerPriv, _ := ed25519.GenerateKey(rand.Reader)
	pinnedPub, _, _ := ed25519.GenerateKey(rand.Reader) // a DIFFERENT key is pinned
	root := revocationRoot(t, pinnedPub)
	// Signed by the attacker, not by the pinned registry key.
	list, err := NewSignedRevocationList(root.RegistryURL, "2026-06-22T10:00:00Z", []string{digestOf("x")}, attackerPriv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRevocationList(list, root); !errors.Is(err, ErrRegistryNotTrusted) {
		t.Fatalf("forged list must be ErrRegistryNotTrusted, got: %v", err)
	}
}

func TestRevocationList_TamperedDigestSetBreaksSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := revocationRoot(t, pub)
	list, err := NewSignedRevocationList(root.RegistryURL, "2026-06-22T10:00:00Z", []string{digestOf("a")}, priv)
	if err != nil {
		t.Fatal(err)
	}
	// Attacker adds a digest after signing → canonical bytes change → sig fails.
	list.RevokedDigests = append(list.RevokedDigests, digestOf("sneaky"))
	if _, err := VerifyRevocationList(list, root); !errors.Is(err, ErrRegistryNotTrusted) {
		t.Fatalf("tampered digest set must be rejected, got: %v", err)
	}
}

func TestRevocationList_InvalidDigestRefused(t *testing.T) {
	if _, err := CanonicalRevocationBytes("https://reg.example/api/skills", "now", []string{"not-a-digest"}); err == nil {
		t.Fatal("expected error for malformed digest")
	}
}
