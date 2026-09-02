package registry

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func genEd(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func signedAttest(t *testing.T, priv ed25519.PrivateKey, reviewerID, digest, level, occurredAt string, expires *time.Time) map[string]any {
	t.Helper()
	ev := map[string]any{
		"schema_version":   EventSchemaVersion,
		"event_id":         "e-" + occurredAt + reviewerID,
		"occurred_at":      occurredAt,
		"bundle_digest":    digest,
		"attestation_id":   "a-" + occurredAt + reviewerID,
		"reviewer_id":      reviewerID,
		"governance_level": level,
		"rationale":        "",
		"tenant_scope":     nil,
	}
	if expires != nil {
		ev["expires_at"] = expires.UTC().Format(time.RFC3339)
	}
	if _, err := SignEnvelopeSignature(priv, ev); err != nil {
		t.Fatal(err)
	}
	return ev
}

const qd = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

var qnow = time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)

// TestAccumulatorK1Parity: the default (empty Signers, quorum 1) reproduces the
// single-attestation gauntlet — a green attestation from tr.pub qualifies; a
// yellow one under a green floor does not (and is noted below-floor).
func TestAccumulatorK1Parity(t *testing.T) {
	priv, pub := genEd(t)
	tr := &SelfTrustRoots{GovernanceMinimum: "green", pub: pub}

	acc := NewAttestAccumulator(tr, qnow)
	acc.OfferAttest(signedAttest(t, priv, "id:kamir@m3c", qd, "green", "2026-08-01T00:00:00Z", nil))
	if got := acc.Qualifying(qd); len(got) != 1 {
		t.Fatalf("k=1 green attestation should qualify, got %d", len(got))
	}
	if acc.RepresentativeLevel(qd) != "green" {
		t.Errorf("representative level = %q", acc.RepresentativeLevel(qd))
	}

	// Below floor: yellow attestation under a green floor → 0 qualifying, noted.
	acc2 := NewAttestAccumulator(tr, qnow)
	acc2.OfferAttest(signedAttest(t, priv, "id:kamir@m3c", qd, "yellow", "2026-08-01T00:00:00Z", nil))
	if len(acc2.Qualifying(qd)) != 0 || !acc2.HasBelowFloor(qd) {
		t.Error("yellow under green floor must not qualify and must be noted below-floor")
	}
}

// TestAccumulatorOneKeyCannotFakeQuorum: two attestations from the SAME key dedup
// to one signer slot — the core anti-forgery property of N-of-M.
func TestAccumulatorOneKeyCannotFakeQuorum(t *testing.T) {
	priv, pub := genEd(t)
	tr := &SelfTrustRoots{GovernanceMinimum: "green", GovernanceQuorum: 2,
		Signers: []Signer{{ReviewerID: "alice", pub: pub}, {ReviewerID: "bob", pub: pub}}}
	acc := NewAttestAccumulator(tr, qnow)
	// Two differently-labelled attestations, both signed by the SAME key.
	acc.OfferAttest(signedAttest(t, priv, "alice", qd, "green", "2026-08-01T00:00:00Z", nil))
	acc.OfferAttest(signedAttest(t, priv, "bob", qd, "green", "2026-08-02T00:00:00Z", nil))
	if got := acc.Qualifying(qd); len(got) != 1 {
		t.Fatalf("one key must yield ONE signer slot, got %d (quorum-forgery!)", len(got))
	}
	if tr.MeetsQuorum([]string{acc.RepresentativeLevel(qd)}) {
		// 1 signer < quorum 2
		t.Error("MeetsQuorum should be false with 1 of 2")
	}
}

// TestAccumulatorNofM: two DISTINCT pinned keys → quorum of 2 met.
func TestAccumulatorNofM(t *testing.T) {
	privA, pubA := genEd(t)
	privB, pubB := genEd(t)
	tr := &SelfTrustRoots{GovernanceMinimum: "green", GovernanceQuorum: 2,
		Signers: []Signer{{ReviewerID: "alice", pub: pubA}, {ReviewerID: "bob", pub: pubB}}}

	// Only alice → 1 of 2, not enough.
	acc1 := NewAttestAccumulator(tr, qnow)
	acc1.OfferAttest(signedAttest(t, privA, "alice", qd, "green", "2026-08-01T00:00:00Z", nil))
	if len(acc1.Qualifying(qd)) >= tr.quorum() {
		t.Error("1 signer must not meet a quorum of 2")
	}

	// alice + bob → 2 of 2, quorum met.
	acc2 := NewAttestAccumulator(tr, qnow)
	acc2.OfferAttest(signedAttest(t, privA, "alice", qd, "green", "2026-08-01T00:00:00Z", nil))
	acc2.OfferAttest(signedAttest(t, privB, "bob", qd, "green", "2026-08-02T00:00:00Z", nil))
	if len(acc2.Qualifying(qd)) < tr.quorum() {
		t.Errorf("2 distinct signers must meet quorum 2, got %d", len(acc2.Qualifying(qd)))
	}

	// reviewer_id binding: bob's key signs but claims reviewer_id "alice" → dropped.
	acc3 := NewAttestAccumulator(tr, qnow)
	acc3.OfferAttest(signedAttest(t, privA, "alice", qd, "green", "2026-08-01T00:00:00Z", nil))
	acc3.OfferAttest(signedAttest(t, privB, "alice", qd, "green", "2026-08-02T00:00:00Z", nil)) // bob's key, wrong id
	if len(acc3.Qualifying(qd)) != 1 {
		t.Errorf("a key/reviewer_id mismatch must be dropped; got %d qualifying", len(acc3.Qualifying(qd)))
	}
}

// TestAccumulatorFreshness (D5): an expired attestation never counts; a future
// expiry counts; an unparseable expiry is treated as expired (fail-safe).
func TestAccumulatorFreshness(t *testing.T) {
	priv, pub := genEd(t)
	tr := &SelfTrustRoots{GovernanceMinimum: "green", pub: pub}
	past := qnow.Add(-time.Hour)
	future := qnow.Add(time.Hour)

	expired := NewAttestAccumulator(tr, qnow)
	expired.OfferAttest(signedAttest(t, priv, "id", qd, "green", "2026-08-01T00:00:00Z", &past))
	if len(expired.Qualifying(qd)) != 0 {
		t.Error("an expired attestation must not qualify")
	}

	fresh := NewAttestAccumulator(tr, qnow)
	fresh.OfferAttest(signedAttest(t, priv, "id", qd, "green", "2026-08-01T00:00:00Z", &future))
	if len(fresh.Qualifying(qd)) != 1 {
		t.Error("a not-yet-expired attestation must qualify")
	}

	// Unparseable expires_at → fail-safe expired.
	bad := signedAttest(t, priv, "id", qd, "green", "2026-08-01T00:00:00Z", nil)
	bad["expires_at"] = "not-a-time"
	if _, err := SignEnvelopeSignature(priv, bad); err != nil {
		t.Fatal(err)
	}
	badAcc := NewAttestAccumulator(tr, qnow)
	badAcc.OfferAttest(bad)
	if len(badAcc.Qualifying(qd)) != 0 {
		t.Error("an unparseable expires_at must be treated as expired (fail-safe)")
	}
}

// TestAccumulatorExpiryNotShadowed is the challenge-gate regression: a signer's
// NEWER expired attestation must sunset the digest even when an OLDER non-expiring
// green exists — the reviewer's latest word governs, never a fall-back.
func TestAccumulatorExpiryNotShadowed(t *testing.T) {
	priv, pub := genEd(t)
	tr := &SelfTrustRoots{GovernanceMinimum: "green", pub: pub}
	past := qnow.Add(-time.Hour)

	acc := NewAttestAccumulator(tr, qnow)
	acc.OfferAttest(signedAttest(t, priv, "id", qd, "green", "2026-08-01T00:00:00Z", nil))   // OLD, no expiry
	acc.OfferAttest(signedAttest(t, priv, "id", qd, "green", "2026-08-15T00:00:00Z", &past)) // NEWER, expired
	if len(acc.Qualifying(qd)) != 0 {
		t.Error("a newer EXPIRED attestation must sunset the digest — an older non-expiring green must not shadow it")
	}
	// Order-independent.
	acc2 := NewAttestAccumulator(tr, qnow)
	acc2.OfferAttest(signedAttest(t, priv, "id", qd, "green", "2026-08-15T00:00:00Z", &past))
	acc2.OfferAttest(signedAttest(t, priv, "id", qd, "green", "2026-08-01T00:00:00Z", nil))
	if len(acc2.Qualifying(qd)) != 0 {
		t.Error("order-independent: a newer expired attestation still sunsets")
	}
	// Sanity: an older expiry does NOT sunset a newer non-expiring green.
	acc3 := NewAttestAccumulator(tr, qnow)
	acc3.OfferAttest(signedAttest(t, priv, "id", qd, "green", "2026-08-01T00:00:00Z", &past)) // OLD, expired
	acc3.OfferAttest(signedAttest(t, priv, "id", qd, "green", "2026-08-15T00:00:00Z", nil))   // NEWER, no expiry
	if len(acc3.Qualifying(qd)) != 1 {
		t.Error("a newer non-expiring green must qualify despite an older expired sibling")
	}
}

// TestAttestationExpiresAtOptIn (D5 producer): expires_at is written only when set.
func TestAttestationExpiresAtOptIn(t *testing.T) {
	base := AttestedEventInput{BundleDigest: qd, ReviewerID: "id:kamir@m3c", GovernanceLevel: "green", OccurredAt: qnow}
	noexp, err := BuildAttestationPublishedEvent(base)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := noexp["expires_at"]; ok {
		t.Error("expires_at must be ABSENT when ExpiresAt is nil (legacy byte-identity)")
	}
	exp := qnow.Add(time.Hour)
	withExp := base
	withExp.ExpiresAt = &exp
	ev, err := BuildAttestationPublishedEvent(withExp)
	if err != nil {
		t.Fatal(err)
	}
	if ev["expires_at"] != exp.UTC().Format(time.RFC3339) {
		t.Errorf("expires_at = %v, want %s", ev["expires_at"], exp.UTC().Format(time.RFC3339))
	}
}

// TestAccumulatorRevoke: a verified revoke marks the digest revoked.
func TestAccumulatorRevoke(t *testing.T) {
	priv, pub := genEd(t)
	tr := &SelfTrustRoots{GovernanceMinimum: "green", pub: pub}
	rev := map[string]any{"schema_version": EventSchemaVersion, "event_id": "r1", "occurred_at": "2026-08-01T00:00:00Z", "bundle_digest": qd, "revoked_by": "id"}
	if _, err := SignEnvelopeSignature(priv, rev); err != nil {
		t.Fatal(err)
	}
	acc := NewAttestAccumulator(tr, qnow)
	acc.OfferRevoke(rev)
	if !acc.IsRevoked(qd) {
		t.Error("a verified revoke must mark the digest revoked")
	}
}

// signedAdmit is a genuinely-signed ADMIT envelope (admitted_by_identity, no
// revoked_by, no reviewer_id) — a signed event of the WRONG shape for a revoke or an
// attestation, used to prove the accumulator gates on signed shape, not "it verifies".
func signedAdmit(t *testing.T, priv ed25519.PrivateKey, digest string) map[string]any {
	t.Helper()
	ev := map[string]any{
		"schema_version":       EventSchemaVersion,
		"event_id":             "adm-" + digest,
		"occurred_at":          "2026-08-01T00:00:00Z",
		"bundle_digest":        digest,
		"admitted_by_identity": "id:kamir@m3c",
	}
	if _, err := SignEnvelopeSignature(priv, ev); err != nil {
		t.Fatal(err)
	}
	return ev
}

// TestOfferRevokeRequiresSignedRevokedBy is the FR-0090 IS-T3 regression: an
// admit/attest envelope — correctly signed by the pinned key — must NOT mark its
// digest revoked when fed to OfferRevoke. A revoke is the SIGNED revoked_by shape,
// not merely a signature that verifies. Against the old code (which revoked on any
// verifying envelope with a bundle_digest) both cases below would have revoked qd,
// letting an attacker suppress a good bundle by replaying a signed admit/attest into
// the revoke path.
func TestOfferRevokeRequiresSignedRevokedBy(t *testing.T) {
	priv, pub := genEd(t)
	tr := &SelfTrustRoots{GovernanceMinimum: "green", pub: pub}

	// A signed ATTEST (reviewer_id + governance_level, no revoked_by) → not a revoke.
	attest := signedAttest(t, priv, "id:kamir@m3c", qd, "green", "2026-08-01T00:00:00Z", nil)
	accA := NewAttestAccumulator(tr, qnow)
	accA.OfferRevoke(attest)
	if accA.IsRevoked(qd) {
		t.Error("a signed ATTEST fed to OfferRevoke must NOT revoke (no signed revoked_by)")
	}

	// A signed ADMIT (admitted_by_identity, no revoked_by) → not a revoke.
	accB := NewAttestAccumulator(tr, qnow)
	accB.OfferRevoke(signedAdmit(t, priv, qd))
	if accB.IsRevoked(qd) {
		t.Error("a signed ADMIT fed to OfferRevoke must NOT revoke (no signed revoked_by)")
	}

	// Sanity: a genuine signed revoke still revokes (the guard did not over-reject).
	rev := map[string]any{"schema_version": EventSchemaVersion, "event_id": "r", "occurred_at": "2026-08-01T00:00:00Z", "bundle_digest": qd, "revoked_by": "id:gov@org"}
	if _, err := SignEnvelopeSignature(priv, rev); err != nil {
		t.Fatal(err)
	}
	accC := NewAttestAccumulator(tr, qnow)
	accC.OfferRevoke(rev)
	if !accC.IsRevoked(qd) {
		t.Error("a genuine signed revoke must still mark the digest revoked")
	}
}

// TestOfferAttestRequiresSignedReviewerAndLevel is the attestation half of IS-T3: a
// signed revoke/admit envelope must never occupy a governance slot. Against the old
// code a signed revoke (which has a bundle_digest and verifies) would be recorded as
// an attestation with an empty governance_level — a shape-confusion the floor should
// never see.
func TestOfferAttestRequiresSignedReviewerAndLevel(t *testing.T) {
	priv, pub := genEd(t)
	tr := &SelfTrustRoots{GovernanceMinimum: "green", pub: pub}

	// A signed revoke fed to OfferAttest → no reviewer_id → must not qualify.
	rev := map[string]any{"schema_version": EventSchemaVersion, "event_id": "r", "occurred_at": "2026-08-01T00:00:00Z", "bundle_digest": qd, "revoked_by": "id:gov@org"}
	if _, err := SignEnvelopeSignature(priv, rev); err != nil {
		t.Fatal(err)
	}
	accA := NewAttestAccumulator(tr, qnow)
	accA.OfferAttest(rev)
	if len(accA.Qualifying(qd)) != 0 || accA.HasBelowFloor(qd) {
		t.Error("a signed revoke fed to OfferAttest must occupy NO governance slot")
	}

	// A signed admit fed to OfferAttest → no reviewer_id → must not qualify.
	accB := NewAttestAccumulator(tr, qnow)
	accB.OfferAttest(signedAdmit(t, priv, qd))
	if len(accB.Qualifying(qd)) != 0 {
		t.Error("a signed admit fed to OfferAttest must occupy NO governance slot")
	}

	// Sanity: a real attestation still qualifies.
	accC := NewAttestAccumulator(tr, qnow)
	accC.OfferAttest(signedAttest(t, priv, "id:kamir@m3c", qd, "green", "2026-08-01T00:00:00Z", nil))
	if len(accC.Qualifying(qd)) != 1 {
		t.Error("a genuine signed attestation must still qualify")
	}
}
