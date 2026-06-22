package verify

// SPEC-0281 — signed governance attestation re-verification (closes the
// red-team's red→green sidecar-downgrade exploit) + SPEC-0279 revocation epoch
// rollback protection.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/signing"
)

type govCase struct {
	currentGov    string // what the (attacker-editable) sidecar claims
	attLevel      string // the attestation row's Level
	attSignDigest string // "" = sign over the bundle's own digest; else a replay
	pinReviewer   bool
	requireSigned bool
	governanceMin string
}

func runGovCase(t *testing.T, c govCase) (*VerifyResult, error) {
	t.Helper()
	authorKey := mustKeypair(t)
	regKey := mustKeypair(t)
	revKey := mustKeypair(t)
	bundlePath, digestRaw, digestStr := writeBundle(t, []byte("gov-test bundle bytes"))
	authorID := "id:author@m3c"
	reviewerID := "id:rev@m3c"
	attestedAt := "2026-06-22T09:00:00Z"

	signDigest := digestStr
	if c.attSignDigest != "" {
		signDigest = c.attSignDigest
	}
	attMsg, err := signing.CanonicalizeAttestationMessage(signDigest, c.attLevel, attestedAt, reviewerID)
	if err != nil {
		t.Fatalf("canon attestation: %v", err)
	}
	attSig := base64.StdEncoding.EncodeToString(ed25519.Sign(revKey.priv, attMsg))

	meta := &registry.BundleMeta{
		Bundle: map[string]any{"bundle_digest": digestStr, "name": "demo", "version": "1.0.0", "status": "admitted"},
		Signatures: []registry.SignatureRow{
			{Role: "author", IdentityID: authorID, SignatureB64: signOver(t, authorKey.priv, digestRaw), Status: "active"},
			{Role: "registry", IdentityID: "id:reg@m3c", SignatureB64: signOver(t, regKey.priv, digestRaw), Status: "active"},
		},
		CurrentGovernance: c.currentGov,
		Attestations: []registry.AttestationRow{
			{Level: c.attLevel, ReviewerID: reviewerID, AttestedAt: attestedAt, SignatureB64: attSig, Status: "active"},
		},
	}
	root := pinnedTrustRoot(authorID, authorKey.pub, regKey.pub, c.governanceMin)
	root.RequireSignedGovernance = c.requireSigned
	if c.pinReviewer {
		root.Reviewers = []AuthorKey{{ID: reviewerID, Pubkey: []byte(revKey.pub), PubkeyB64: revKey.b64}}
	}
	return Verify(VerifyOpts{BundlePath: bundlePath, BundleMeta: meta, TrustRoot: root, IdentityFetcher: nil})
}

func TestGovernance_SignedAttestation_Verified(t *testing.T) {
	res, err := runGovCase(t, govCase{currentGov: "green", attLevel: "green", pinReviewer: true, requireSigned: true, governanceMin: "green"})
	if err != nil {
		t.Fatalf("valid signed green should verify: %v", err)
	}
	if !res.GovernanceVerified {
		t.Error("GovernanceVerified should be true")
	}
	if !bytes.Contains([]byte(res.ChainSummary), []byte("attested green")) {
		t.Errorf("summary should say attested green: %q", res.ChainSummary)
	}
}

// AC1 — the red-team exploit: a genuinely-RED bundle with its sidecar flipped to
// green is REFUSED under require_signed_governance (no signed green attestation).
func TestGovernance_DowngradeRefused(t *testing.T) {
	_, err := runGovCase(t, govCase{currentGov: "green", attLevel: "red", pinReviewer: true, requireSigned: true, governanceMin: "green"})
	if !errors.Is(err, ErrGovernanceBelowMin) {
		t.Fatalf("red→green downgrade must be refused, got: %v", err)
	}
}

// AC2 — a valid signed green attestation by a NON-pinned reviewer is not trusted.
func TestGovernance_NonPinnedReviewerRefused(t *testing.T) {
	_, err := runGovCase(t, govCase{currentGov: "green", attLevel: "green", pinReviewer: false, requireSigned: true, governanceMin: "green"})
	if !errors.Is(err, ErrGovernanceBelowMin) {
		t.Fatalf("non-pinned reviewer must be refused, got: %v", err)
	}
}

// AC3 — a green attestation signed over a DIFFERENT bundle's digest (replay) fails.
func TestGovernance_ReplayedAttestationRefused(t *testing.T) {
	other := digestOf("some other bundle entirely")
	_, err := runGovCase(t, govCase{currentGov: "green", attLevel: "green", attSignDigest: other, pinReviewer: true, requireSigned: true, governanceMin: "green"})
	if !errors.Is(err, ErrGovernanceBelowMin) {
		t.Fatalf("replayed attestation must be refused, got: %v", err)
	}
}

// AC4 — backward compatible: with no reviewers pinned and require off, the level
// is ADVISORY (passes the floor) and the summary does not claim "attested".
func TestGovernance_AdvisoryWhenNoReviewers(t *testing.T) {
	res, err := runGovCase(t, govCase{currentGov: "green", attLevel: "green", pinReviewer: false, requireSigned: false, governanceMin: "green"})
	if err != nil {
		t.Fatalf("advisory mode should pass: %v", err)
	}
	if res.GovernanceVerified {
		t.Error("GovernanceVerified should be false in advisory mode")
	}
	if !bytes.Contains([]byte(res.ChainSummary), []byte("governance(advisory) green")) {
		t.Errorf("summary should mark advisory: %q", res.ChainSummary)
	}
}

// SPEC-0279 R1 — a signed list with epoch below the pinned floor is refused (rollback).
func TestRevocation_EpochRollbackRefused(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := revocationRoot(t, pub)
	list, err := NewSignedRevocationList(root.RegistryURL, "2026-06-22T10:00:00Z", 1, []string{digestOf("x")}, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRevocationList(list, root, 2); !errors.Is(err, ErrRegistryNotTrusted) {
		t.Fatalf("epoch 1 below floor 2 must be refused, got: %v", err)
	}
	// epoch at/above the floor verifies.
	list2, _ := NewSignedRevocationList(root.RegistryURL, "2026-06-22T10:00:00Z", 3, []string{digestOf("x")}, priv)
	if _, err := VerifyRevocationList(list2, root, 2); err != nil {
		t.Fatalf("epoch 3 >= floor 2 should verify, got: %v", err)
	}
}
