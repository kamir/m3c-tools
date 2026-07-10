package registry

import (
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"testing"
)

// buildAC mints a fully-signed admit + attestation pair and returns the
// AttestationContext plus the exact .skb bytes the digest was computed over.
func buildAC(t *testing.T, priv ed25519.PrivateKey, level string) (*AttestationContext, []byte) {
	t.Helper()
	admitItem, digest := mintAdmitItem(t, priv, "er1-push", "1.0.0", "the-real-bundle-bytes")
	attestItem := mintAttestItem(t, priv, "er1-push", "1.0.0", digest, level, "ok")
	admitEv, err := extractEvent(itemBody(admitItem))
	if err != nil {
		t.Fatalf("extract admit: %v", err)
	}
	attestEv, err := extractEvent(itemBody(attestItem))
	if err != nil {
		t.Fatalf("extract attest: %v", err)
	}
	skb, err := extractSkbBytes(itemBody(admitItem))
	if err != nil {
		t.Fatalf("extract skb: %v", err)
	}
	return &AttestationContext{AdmitEvent: admitEv, GovernanceAttestation: attestEv}, skb
}

// TestReverify_HappyPath is the SPEC-0266 F2/F19 positive control: a genuine
// signed context re-verifies against the pinned key and returns the SIGNED
// governance level.
func TestReverify_HappyPath(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	ac, skb := buildAC(t, priv, "green")
	level, err := ac.Reverify(pub, skb)
	if err != nil {
		t.Fatalf("Reverify: %v", err)
	}
	if level != "green" {
		t.Errorf("governance level = %q, want green (from the SIGNED attestation)", level)
	}
}

// TestReverify_RepackedSkb proves F2: a self-consistent repack (different .skb
// bytes than the signed digest) is rejected — content-binding alone would miss
// this because the attacker also repacks the sidecar/digest.
func TestReverify_RepackedSkb(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	ac, _ := buildAC(t, priv, "green")
	if _, err := ac.Reverify(pub, []byte("ATTACKER-REPACKED-BUNDLE")); !errors.Is(err, ErrAttestationReanchor) {
		t.Errorf("repacked .skb: err = %v, want ErrAttestationReanchor", err)
	}
}

// TestReverify_WrongKey proves the anchor is the PINNED key: a context signed by
// some other key does not verify against the pinned pub.
func TestReverify_WrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	otherPub, _, _ := ed25519.GenerateKey(nil)
	ac, skb := buildAC(t, priv, "green")
	if _, err := ac.Reverify(otherPub, skb); !errors.Is(err, ErrAttestationReanchor) {
		t.Errorf("wrong key: err = %v, want ErrAttestationReanchor", err)
	}
}

// TestReverify_ForgedGovernance proves F19: flipping governance_level in the
// (signed) attestation after the fact breaks its envelope signature, so the
// forged level never reaches the floor check.
func TestReverify_ForgedGovernance(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	ac, skb := buildAC(t, priv, "yellow")
	ac.GovernanceAttestation["governance_level"] = "green" // tamper AFTER signing
	if _, err := ac.Reverify(pub, skb); !errors.Is(err, ErrAttestationReanchor) {
		t.Errorf("forged governance: err = %v, want ErrAttestationReanchor", err)
	}
}

// TestReverify_DigestBindingAcrossEvents proves the governance attestation must
// be bound to the SAME digest as the admit event — splicing a validly-signed
// green attestation for a DIFFERENT digest onto this bundle is rejected.
func TestReverify_DigestBindingAcrossEvents(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	acA, skbA := buildAC(t, priv, "green")
	// A validly-signed green attestation for a DIFFERENT bundle (distinct digest).
	_, otherDigest := mintAdmitItem(t, priv, "other", "9.9.9", "DIFFERENT-bundle-content")
	otherAttest := mintAttestItem(t, priv, "other", "9.9.9", otherDigest, "green", "ok")
	otherAttestEv, err := extractEvent(itemBody(otherAttest))
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	acA.GovernanceAttestation = otherAttestEv // splice
	if _, err := acA.Reverify(pub, skbA); !errors.Is(err, ErrAttestationReanchor) {
		t.Errorf("spliced cross-digest attestation: err = %v, want ErrAttestationReanchor", err)
	}
}

// TestAttestationStash_RoundTrip verifies write→read of the stash.
func TestAttestationStash_RoundTrip(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	ac, _ := buildAC(t, priv, "green")
	dir := t.TempDir()
	if err := WriteAttestationStash(dir, ac); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := ReadAttestationStash(dir)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.AdmitEvent["bundle_digest"] != ac.AdmitEvent["bundle_digest"] {
		t.Errorf("round-trip lost the admit digest")
	}
	// Absent stash → ErrNoAttestationStash.
	if _, err := ReadAttestationStash(filepath.Join(dir, "nope")); !errors.Is(err, ErrNoAttestationStash) {
		t.Errorf("missing stash: err = %v, want ErrNoAttestationStash", err)
	}
}
