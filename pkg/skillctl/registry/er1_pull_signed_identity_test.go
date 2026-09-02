package registry

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

// TestER1LoadAttestRevokeSignedIdentity is the FR-0090 IS-T4 regression. ER1 item
// tags are carrier metadata a writer controls, so loadAttestRevoke must classify by
// the SIGNED envelope shape, treating the skill-event:<kind> tag as a coarse SEARCH
// prefilter only:
//
//   - a genuinely-signed REVOKE re-tagged skill-event:attested must STILL revoke
//     (and must NOT be counted as an attestation) — otherwise a writer could hide a
//     revocation among the attestations and keep a compromised bundle installable;
//   - a genuinely-signed ATTEST re-tagged skill-event:revoked must NOT revoke (and
//     must be counted as the attestation it is) — otherwise a writer could suppress a
//     good bundle by forging a revocation from a re-tagged attestation.
//
// Against the old code (which trusted the skill-event:<kind> tag) the revoke would
// have been recorded as an empty-level attestation and the attest would have revoked
// its digest — exactly inverted from the signed truth.
func TestER1LoadAttestRevokeSignedIdentity(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	f := newPullFake(t)

	revDigest := "sha256:" + strings.Repeat("a", 64)
	attDigest := "sha256:" + strings.Repeat("b", 64)

	// A signed REVOKE, but the ER1 item is TAGGED skill-event:attested.
	revEv, err := BuildBundleRevokedEvent(RevokedEventInput{
		BundleDigest: revDigest, ReasonCode: "key-compromise", RevokedBy: "id:test@m3c", OccurredAt: testTime(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignEnvelopeSignature(priv, revEv); err != nil {
		t.Fatal(err)
	}
	f.addItem(map[string]any{
		"doc_id": "sneaky-revoke-tagged-attested",
		"tags": strings.Join([]string{
			"m3c-skill-bundle", "skill-registry:self",
			"skill:pdf", "skill-digest:" + revDigest,
			"skill-event:" + EventKindAttested, // THE LIE
		}, ","),
		"transcript": renderTestEventBody(revEv, "attested"),
	})

	// A signed ATTEST, but the ER1 item is TAGGED skill-event:revoked.
	attEv, err := BuildAttestationPublishedEvent(AttestedEventInput{
		BundleDigest: attDigest, ReviewerID: "id:test@m3c", GovernanceLevel: "green", OccurredAt: testTime(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignEnvelopeSignature(priv, attEv); err != nil {
		t.Fatal(err)
	}
	f.addItem(map[string]any{
		"doc_id": "sneaky-attest-tagged-revoked",
		"tags": strings.Join([]string{
			"m3c-skill-bundle", "skill-registry:self",
			"skill:pdf", "skill-digest:" + attDigest,
			"skill-event:" + EventKindRevoked, // THE LIE
		}, ","),
		"transcript": renderTestEventBody(attEv, "revoked"),
	})

	attestByDigest, revoked, _, err := loadAttestRevoke(f.cfg(), "skills", "", pub)
	if err != nil {
		t.Fatalf("loadAttestRevoke: %v", err)
	}

	// The re-tagged revoke: revokes, and is NOT an attestation.
	if _, ok := revoked[revDigest]; !ok {
		t.Error("a signed revoke re-tagged skill-event:attested must STILL revoke (classified by signed shape)")
	}
	if _, ok := attestByDigest[revDigest]; ok {
		t.Error("a signed revoke must NOT be counted as an attestation, whatever its skill-event tag")
	}

	// The re-tagged attest: does NOT revoke, and IS an attestation.
	if _, ok := revoked[attDigest]; ok {
		t.Error("a signed attestation re-tagged skill-event:revoked must NOT revoke")
	}
	if lvl, ok := attestByDigest[attDigest]; !ok || lvl != "green" {
		t.Errorf("a signed attestation must be counted (level %q, ok=%v); want green", lvl, ok)
	}
}
