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

	attestByDigest, revoked, _, err := loadAttestRevoke(f.cfg(), "skills", pub)
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

// TestER1LoadAttestRevokeDiscoveryDeGate is the FR-0090 IS-T4b regression (the
// IS-03 residual). loadAttestRevoke's DISCOVERY must not be prefiltered on the
// attacker-controlled skill-event:<kind> tag: a genuinely-signed REVOKE must still
// be found — and still revoke — when its ER1 item is
//
//   - re-tagged to an UNsearched kind (skill-event:installed), or
//   - stripped of the skill-event tag entirely.
//
// Against the OLD code (which searched only skill-event:{attested,revoked}) both
// items are dropped at DISCOVERY, before the signed-shape classifier, so their
// digest never enters revokedDigests and a compromised bundle stays installable.
// After de-gating (search the STABLE bundle tags, classify by the signed envelope)
// both revokes are discovered and D is revoked.
func TestER1LoadAttestRevokeDiscoveryDeGate(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	f := newPullFake(t)

	digestInstalledTag := "sha256:" + strings.Repeat("c", 64)
	digestNoTag := "sha256:" + strings.Repeat("d", 64)

	// (1) A signed REVOKE whose ER1 item is TAGGED skill-event:installed — a kind
	// the old two-search DISCOVERY never queried.
	revInstalled, err := BuildBundleRevokedEvent(RevokedEventInput{
		BundleDigest: digestInstalledTag, ReasonCode: "key-compromise", RevokedBy: "id:test@m3c", OccurredAt: testTime(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignEnvelopeSignature(priv, revInstalled); err != nil {
		t.Fatal(err)
	}
	f.addItem(map[string]any{
		"doc_id": "revoke-retagged-installed",
		"tags": strings.Join([]string{
			"m3c-skill-bundle", "skill-registry:self",
			"skill:pdf", "skill-digest:" + digestInstalledTag,
			"skill-event:" + EventKindInstalled, // dropped by the old search
		}, ","),
		"transcript": renderTestEventBody(revInstalled, "installed"),
	})

	// (2) A signed REVOKE whose ER1 item carries NO skill-event tag at all (stripped).
	// It still carries the stable bundle tags every item has.
	revNoTag, err := BuildBundleRevokedEvent(RevokedEventInput{
		BundleDigest: digestNoTag, ReasonCode: "key-compromise", RevokedBy: "id:test@m3c", OccurredAt: testTime(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignEnvelopeSignature(priv, revNoTag); err != nil {
		t.Fatal(err)
	}
	f.addItem(map[string]any{
		"doc_id": "revoke-tag-stripped",
		"tags": strings.Join([]string{
			"m3c-skill-bundle", "skill-registry:self",
			"skill:pdf", "skill-digest:" + digestNoTag,
			// no skill-event:<kind> tag — the old search would never find this item
		}, ","),
		"transcript": renderTestEventBody(revNoTag, "revoked"),
	})

	_, revoked, _, err := loadAttestRevoke(f.cfg(), "skills", pub)
	if err != nil {
		t.Fatalf("loadAttestRevoke: %v", err)
	}
	if _, ok := revoked[digestInstalledTag]; !ok {
		t.Error("a signed revoke re-tagged skill-event:installed must STILL be discovered and revoke (de-gated discovery)")
	}
	if _, ok := revoked[digestNoTag]; !ok {
		t.Error("a signed revoke with the skill-event tag stripped must STILL be discovered and revoke (de-gated discovery)")
	}
}
