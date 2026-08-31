package registry

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestLoadSelfTrustRootsCrossSign: a trust-roots file that pins a governance root
// + a cross_sign_path derives the cross-signed member into the signer set (so the
// N-of-M gate consults it) without listing the member key explicitly.
func TestLoadSelfTrustRootsCrossSign(t *testing.T) {
	rootPriv, rootPub := genEd(t)
	_, memberPub := genEd(t)
	_, primaryPub := genEd(t) // the registry/author key (gate-1/gate-3)

	dir := t.TempDir()
	csDir := filepath.Join(dir, "cross")
	if err := os.MkdirAll(csDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ev, err := BuildMemberCrossSignature(CrossSignInput{
		MemberReviewerID: "alice", MemberPubKeyB64: base64.StdEncoding.EncodeToString(memberPub),
		IssuedAt: time.Now(), NotAfter: time.Now().Add(72 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignEnvelopeSignature(rootPriv, ev); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(ev)
	if err := os.WriteFile(filepath.Join(csDir, "alice.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}

	trPath := filepath.Join(dir, "trust-roots.yaml")
	yaml := "registry: self\n" +
		"pubkey_b64: " + base64.StdEncoding.EncodeToString(primaryPub) + "\n" +
		"governance_minimum: green\n" +
		"governance_root_pubkey_b64: " + base64.StdEncoding.EncodeToString(rootPub) + "\n" +
		"cross_sign_path: " + csDir + "\n"
	if err := os.WriteFile(trPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	tr, err := LoadSelfTrustRoots(trPath)
	if err != nil {
		t.Fatalf("LoadSelfTrustRoots: %v", err)
	}
	found := false
	for _, s := range tr.signerSet() {
		if s.ReviewerID == "alice" && s.pub.Equal(memberPub) {
			found = true
		}
	}
	if !found {
		t.Errorf("cross-signed member 'alice' not admitted into the signer set: %+v", tr.Signers)
	}
}

// TestCrossSignature: a governance root cross-signs a member key; verification
// admits the member only against the PINNED root, only before not_after.
func TestCrossSignature(t *testing.T) {
	rootPriv, rootPub := genEd(t)
	_, memberPub := genEd(t)
	memberB64 := base64.StdEncoding.EncodeToString(memberPub)

	ev, err := BuildMemberCrossSignature(CrossSignInput{
		MemberReviewerID: "alice",
		MemberPubKeyB64:  memberB64,
		IssuedAt:         qnow,
		NotAfter:         qnow.Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignEnvelopeSignature(rootPriv, ev); err != nil {
		t.Fatal(err)
	}

	// Verified against the correct root, before expiry → admits the member.
	s, err := VerifyCrossSignature(rootPub, ev, qnow)
	if err != nil {
		t.Fatalf("VerifyCrossSignature: %v", err)
	}
	if s.ReviewerID != "alice" || !s.pub.Equal(memberPub) {
		t.Errorf("derived signer = %+v, want alice + member key", s)
	}

	// Wrong root → rejected.
	_, otherPub := genEd(t)
	if _, err := VerifyCrossSignature(otherPub, ev, qnow); err == nil {
		t.Error("a cross-signature must not verify against a non-pinned root")
	}
	// Expired → rejected (fail-closed).
	if _, err := VerifyCrossSignature(rootPub, ev, qnow.Add(48*time.Hour)); err == nil {
		t.Error("an expired cross-signature must be rejected")
	}
	// Tampered member key → the signature no longer verifies.
	tampered := map[string]any{}
	for k, v := range ev {
		tampered[k] = v
	}
	_, otherMember := genEd(t)
	tampered["member_root_pubkey_b64"] = base64.StdEncoding.EncodeToString(otherMember)
	if _, err := VerifyCrossSignature(rootPub, tampered, qnow); err == nil {
		t.Error("tampering the member key must break the cross-signature")
	}

	// Derivation: verified + unexpired → 1 signer; after expiry → 0.
	if got := DeriveCrossSignedSigners(rootPub, []map[string]any{ev}, qnow); len(got) != 1 {
		t.Errorf("derive before expiry = %d signers, want 1", len(got))
	}
	if got := DeriveCrossSignedSigners(rootPub, []map[string]any{ev}, qnow.Add(48*time.Hour)); len(got) != 0 {
		t.Errorf("derive after expiry = %d signers, want 0", len(got))
	}
}
