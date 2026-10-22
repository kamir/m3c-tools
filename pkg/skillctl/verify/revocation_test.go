package verify

// SPEC-0276 R4.4: signed offline revocation list.

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
	c1, err := CanonicalRevocationBytes("https://reg.example/api/skills/", "2026-06-22T10:00:00Z", 1, []string{a, b})
	if err != nil {
		t.Fatal(err)
	}
	// Reversed order + uppercased hex + a duplicate → identical canonical bytes.
	c2, err := CanonicalRevocationBytes("https://reg.example/api/skills", "2026-06-22T10:00:00Z", 1, []string{bytesUpper(b), a, a})
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
	list, err := NewSignedRevocationList(root.RegistryURL, "2026-06-22T10:00:00Z", 1, []string{target, digestOf("other")}, priv)
	if err != nil {
		t.Fatal(err)
	}
	set, err := VerifyRevocationList(list, root, 0)
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
	list, err := NewSignedRevocationList(root.RegistryURL, "2026-06-22T10:00:00Z", 1, []string{digestOf("x")}, attackerPriv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRevocationList(list, root, 0); !errors.Is(err, ErrRegistryNotTrusted) {
		t.Fatalf("forged list must be ErrRegistryNotTrusted, got: %v", err)
	}
}

func TestRevocationList_TamperedDigestSetBreaksSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := revocationRoot(t, pub)
	list, err := NewSignedRevocationList(root.RegistryURL, "2026-06-22T10:00:00Z", 1, []string{digestOf("a")}, priv)
	if err != nil {
		t.Fatal(err)
	}
	// Attacker adds a digest after signing → canonical bytes change → sig fails.
	list.RevokedDigests = append(list.RevokedDigests, digestOf("sneaky"))
	if _, err := VerifyRevocationList(list, root, 0); !errors.Is(err, ErrRegistryNotTrusted) {
		t.Fatalf("tampered digest set must be rejected, got: %v", err)
	}
}

func TestRevocationList_InvalidDigestRefused(t *testing.T) {
	if _, err := CanonicalRevocationBytes("https://reg.example/api/skills", "now", 1, []string{"not-a-digest"}); err == nil {
		t.Fatal("expected error for malformed digest")
	}
}

func TestRevocationListRegistryBinding(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	const registry = "https://reg.example/api/skills"
	for _, tc := range []struct {
		name, rootURL, listURL string
		allowed                bool
	}{
		{"same", registry, registry, true},
		{"canonical-trimming", " " + registry + "/ ", registry + "/", true},
		{"foreign-path", registry, registry + "/foreign", false},
		{"foreign-host", registry, "https://foreign.invalid/api/skills", false},
		{"foreign-scheme", registry, "http://reg.example/api/skills", false},
		{"dot-path-not-equivalent", registry, "https://reg.example/api/skills/../skills", false},
		{"empty-root", "", registry, false},
		{"empty-list", registry, "", false},
		{"both-empty", "", "", false},
		{"both-blank", " / ", " / ", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := revocationRoot(t, key.Public().(ed25519.PublicKey))
			root.RegistryURL = tc.rootURL
			list, err := NewSignedRevocationList(tc.listURL, "2026-10-23T12:00:00Z", 7, []string{digestOf("synthetic-target")}, key)
			if err != nil {
				t.Fatal(err)
			}
			set, err := VerifyRevocationList(list, root, 5)
			if tc.allowed {
				if err != nil || len(set) != 1 {
					t.Fatalf("same-registry signed set refused: %v", err)
				}
				return
			}
			if set != nil || !errors.Is(err, ErrRegistryNotTrusted) {
				t.Fatalf("foreign or empty identity accepted: %v", err)
			}
			want := "revocation list: registry does not match pinned root: " + ErrRegistryNotTrusted.Error()
			if err.Error() != want {
				t.Fatal("registry mismatch diagnostic must not reflect input URLs")
			}
		})
	}
}
