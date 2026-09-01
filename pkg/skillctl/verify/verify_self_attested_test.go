package verify

// SPEC-0246 §5 — reviewer≠author floor (require_independent_review), P1b hardening.
//
// The floor must be CRYPTOGRAPHICALLY enforced: when require_independent_review
// is set, independence is established ONLY by a binding governance attestation
// whose ed25519 signature verifies against a PINNED reviewer key AND whose
// (signature-bound) reviewer_id differs from the author. The unsigned sidecar
// fields (self_attested, reviewer_id) are NEVER trusted to satisfy the floor —
// in the offline `verify --bundle` path the sidecar is attacker-controlled, so a
// forged reviewer_id / self_attested:false with no valid signature must FAIL
// CLOSED. This is the same unsigned-sidecar class SPEC-0281 fixed for governance.
//
// These tests exercise the offline pinned path (no IdentityFetcher) so the gate
// is proven network-free.

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/signing"
)

// signedAttestation builds a binding (global, active) governance attestation row
// signed by reviewerPriv over the canonical (digest, level, attestedAt,
// reviewerID) message. This is the ONLY way an attestation can satisfy the
// hardened floor.
func signedAttestation(t *testing.T, digestStr, level, reviewerID string, reviewerPriv ed25519.PrivateKey) registry.AttestationRow {
	t.Helper()
	attestedAt := "2026-06-22T09:00:00Z"
	msg, err := signing.CanonicalizeAttestationMessage(digestStr, level, attestedAt, reviewerID)
	if err != nil {
		t.Fatalf("canon attestation: %v", err)
	}
	return registry.AttestationRow{
		Level:        level,
		ReviewerID:   reviewerID,
		AttestedAt:   attestedAt,
		SignatureB64: base64.StdEncoding.EncodeToString(ed25519.Sign(reviewerPriv, msg)),
		Status:       "active",
	}
}

// pinReviewer pins reviewerID→reviewerPub on the opts' trust root.
func pinReviewer(opts *VerifyOpts, reviewerID string, reviewerPub ed25519.PublicKey) {
	opts.TrustRoot.Reviewers = append(opts.TrustRoot.Reviewers, AuthorKey{
		ID:        reviewerID,
		Pubkey:    []byte(reviewerPub),
		PubkeyB64: base64.StdEncoding.EncodeToString(reviewerPub),
	})
}

// setBindingReviewer overwrites the single binding attestation's reviewer id on
// a pinned-opts BundleMeta WITHOUT a signature, and clears any registry-stamped
// self_attested / author_id — i.e. the attacker-controlled, unsigned sidecar.
func setBindingReviewer(opts *VerifyOpts, reviewerID string) {
	for i := range opts.BundleMeta.Attestations {
		opts.BundleMeta.Attestations[i].ReviewerID = reviewerID
		opts.BundleMeta.Attestations[i].SignatureB64 = ""
		opts.BundleMeta.Attestations[i].SelfAttested = nil
		opts.BundleMeta.Attestations[i].AuthorID = ""
	}
}

// digestStrOf re-derives the "sha256:<hex>" digest of opts' staged bundle so a
// test can sign an attestation that binds to the real digest. pinnedOpts always
// writes the same content; we read it back through the verifier's own digest
// helper so the binding is exact.
func digestStrOf(t *testing.T, opts VerifyOpts) string {
	t.Helper()
	_, str, err := stepRecomputeDigest(opts.BundlePath)
	if err != nil {
		t.Fatalf("recompute digest: %v", err)
	}
	return str
}

func TestVerify_IndependentReview_FloorOff_SelfAllowed(t *testing.T) {
	// self tenant: floor OFF (default). A self-attested bundle must verify, and
	// the result must surface the advisory self_attested=true.
	opts, _ := pinnedOpts(t)
	setBindingReviewer(&opts, "id:kamir@m3c") // == pinned author id
	opts.TrustRoot.RequireIndependentReview = false

	res, err := Verify(opts)
	if err != nil {
		t.Fatalf("floor off: self-attested bundle should verify, got: %v", err)
	}
	if res.SelfAttested == nil || !*res.SelfAttested {
		t.Errorf("advisory self_attested should be true; got %v", res.SelfAttested)
	}
}

func TestVerify_IndependentReview_FloorOn_SelfRefused(t *testing.T) {
	// Floor ON + self-attested (even with a valid reviewer==author signature) →
	// refuse with ErrSelfAttested (exit 20).
	opts, author := pinnedOpts(t)
	digestStr := digestStrOf(t, opts)
	// Sign as the AUTHOR acting as their own reviewer.
	opts.BundleMeta.Attestations = []registry.AttestationRow{
		signedAttestation(t, digestStr, "green", "id:kamir@m3c", author.priv),
	}
	pinReviewer(&opts, "id:kamir@m3c", author.pub)
	opts.TrustRoot.RequireIndependentReview = true

	_, err := Verify(opts)
	if !errors.Is(err, ErrSelfAttested) {
		t.Fatalf("floor on + self-attested should yield ErrSelfAttested, got: %v", err)
	}
	if ExitCode(err) != ExitSelfAttested {
		t.Errorf("exit code = %d, want %d", ExitCode(err), ExitSelfAttested)
	}
}

func TestVerify_IndependentReview_FloorOn_SignedIndependentPasses(t *testing.T) {
	// Floor ON + a PROPERLY PINNED-REVIEWER-SIGNED attestation with
	// reviewer_id != author → verify, self_attested=false.
	opts, _ := pinnedOpts(t)
	digestStr := digestStrOf(t, opts)
	reviewer := mustKeypair(t)
	reviewerID := "id:independent-reviewer@m3c"
	opts.BundleMeta.Attestations = []registry.AttestationRow{
		signedAttestation(t, digestStr, "green", reviewerID, reviewer.priv),
	}
	pinReviewer(&opts, reviewerID, reviewer.pub)
	opts.TrustRoot.RequireIndependentReview = true

	res, err := Verify(opts)
	if err != nil {
		t.Fatalf("floor on + signed independent review should pass, got: %v", err)
	}
	if res.SelfAttested == nil || *res.SelfAttested {
		t.Errorf("self_attested should be false; got %v", res.SelfAttested)
	}
}

// HACKER PoC #1: a fabricated independent reviewer_id with NO valid signature in
// the attacker-controlled offline sidecar must FAIL CLOSED — the unsigned
// reviewer_id cannot launder past the floor.
func TestVerify_IndependentReview_FloorOn_ForgedReviewerID_FailsClosed(t *testing.T) {
	opts, _ := pinnedOpts(t)
	// Attacker fabricates an independent-looking reviewer with no signature.
	setBindingReviewer(&opts, "id:totally-independent@m3c") // != author, but UNSIGNED
	// Pin a reviewer so the trust root is even loadable; the forged row is signed
	// by nobody, so the pin can't rescue it.
	reviewer := mustKeypair(t)
	pinReviewer(&opts, "id:totally-independent@m3c", reviewer.pub)
	opts.TrustRoot.RequireIndependentReview = true

	_, err := Verify(opts)
	if !errors.Is(err, ErrSelfAttested) {
		t.Fatalf("forged unsigned reviewer_id must FAIL CLOSED (ErrSelfAttested), got: %v", err)
	}
	if ExitCode(err) != ExitSelfAttested {
		t.Errorf("exit code = %d, want %d", ExitCode(err), ExitSelfAttested)
	}
}

// HACKER PoC #2: an UNSIGNED self_attested:false flag in the sidecar must FAIL
// CLOSED — the unsigned flag is never trusted to assert independence.
func TestVerify_IndependentReview_FloorOn_UnsignedSelfAttestedFalse_FailsClosed(t *testing.T) {
	opts, _ := pinnedOpts(t)
	fls := false
	for i := range opts.BundleMeta.Attestations {
		opts.BundleMeta.Attestations[i].ReviewerID = "id:looks-independent@m3c"
		opts.BundleMeta.Attestations[i].SelfAttested = &fls // attacker claims independent
		opts.BundleMeta.Attestations[i].SignatureB64 = ""   // but no valid signature
	}
	reviewer := mustKeypair(t)
	pinReviewer(&opts, "id:looks-independent@m3c", reviewer.pub)
	opts.TrustRoot.RequireIndependentReview = true

	_, err := Verify(opts)
	if !errors.Is(err, ErrSelfAttested) {
		t.Fatalf("unsigned self_attested:false must FAIL CLOSED (ErrSelfAttested), got: %v", err)
	}
}

// A signature signed by a reviewer key that is NOT pinned must not satisfy the
// floor (mirrors SPEC-0281 AC2 for governance).
func TestVerify_IndependentReview_FloorOn_NonPinnedReviewer_FailsClosed(t *testing.T) {
	opts, _ := pinnedOpts(t)
	digestStr := digestStrOf(t, opts)
	reviewer := mustKeypair(t)
	reviewerID := "id:independent-reviewer@m3c"
	opts.BundleMeta.Attestations = []registry.AttestationRow{
		signedAttestation(t, digestStr, "green", reviewerID, reviewer.priv),
	}
	// Pin a DIFFERENT reviewer so validate() passes but the signing reviewer is
	// not pinned → its signature cannot be verified.
	other := mustKeypair(t)
	pinReviewer(&opts, "id:some-other-reviewer@m3c", other.pub)
	opts.TrustRoot.RequireIndependentReview = true

	_, err := Verify(opts)
	if !errors.Is(err, ErrSelfAttested) {
		t.Fatalf("non-pinned reviewer signature must FAIL CLOSED, got: %v", err)
	}
}

// An attestation signed over a DIFFERENT bundle's digest (replay) must not
// satisfy the floor.
func TestVerify_IndependentReview_FloorOn_ReplayedSignature_FailsClosed(t *testing.T) {
	opts, _ := pinnedOpts(t)
	reviewer := mustKeypair(t)
	reviewerID := "id:independent-reviewer@m3c"
	// Sign over a digest that is NOT this bundle's digest.
	wrongDigest := digestOf("some entirely different bundle")
	opts.BundleMeta.Attestations = []registry.AttestationRow{
		signedAttestation(t, wrongDigest, "green", reviewerID, reviewer.priv),
	}
	pinReviewer(&opts, reviewerID, reviewer.pub)
	opts.TrustRoot.RequireIndependentReview = true

	_, err := Verify(opts)
	if !errors.Is(err, ErrSelfAttested) {
		t.Fatalf("replayed-digest signature must FAIL CLOSED, got: %v", err)
	}
}

func TestVerify_IndependentReview_FloorOn_NoReviewerFailsClosed(t *testing.T) {
	// Floor ON but the binding attestation carries no reviewer identity and no
	// signature → we cannot prove independence → fail closed.
	opts, _ := pinnedOpts(t)
	for i := range opts.BundleMeta.Attestations {
		opts.BundleMeta.Attestations[i].ReviewerID = ""
		opts.BundleMeta.Attestations[i].SelfAttested = nil
		opts.BundleMeta.Attestations[i].AuthorID = ""
		opts.BundleMeta.Attestations[i].SignatureB64 = ""
	}
	reviewer := mustKeypair(t)
	pinReviewer(&opts, "id:some-reviewer@m3c", reviewer.pub)
	opts.TrustRoot.RequireIndependentReview = true

	_, err := Verify(opts)
	if !errors.Is(err, ErrSelfAttested) {
		t.Fatalf("floor on + unprovable independence should fail closed with ErrSelfAttested, got: %v", err)
	}
}

func TestTrustRoots_RequireIndependentReview_StrictLoaderAccepts(t *testing.T) {
	// The STRICT loader (KnownFields(true)) must accept the declared
	// require_independent_review field — but ONLY together with a non-empty
	// reviewers list (the floor must ship with the keys to enforce it).
	regKey := mustKeypair(t)
	reviewerKey := mustKeypair(t)
	body := "" +
		"trust_roots:\n" +
		"  - registry_url: https://reg.example/api/skills\n" +
		"    registry_keys:\n" +
		"      - id: reg-key-1\n" +
		"        pubkey: " + regKey.b64 + "\n" +
		"    identity_keys_authorized: from-registry\n" +
		"    governance_minimum: green\n" +
		"    require_independent_review: true\n" +
		"    reviewers:\n" +
		"      - id: id:reviewer@m3c\n" +
		"        pubkey: " + reviewerKey.b64 + "\n"
	tr, err := Load(writeTrustRootsYAML(t, body))
	if err != nil {
		t.Fatalf("strict loader should accept require_independent_review + reviewers, got: %v", err)
	}
	if !tr.Roots[0].RequireIndependentReview {
		t.Errorf("require_independent_review should be true after load")
	}
}

// The floor MUST NOT be settable without the reviewer keys to enforce it: a
// trust root with require_independent_review:true and an empty reviewers list is
// refused at Load (fail-closed configuration, mirrors require_signed_governance).
func TestTrustRoots_RequireIndependentReview_RequiresReviewers(t *testing.T) {
	regKey := mustKeypair(t)
	body := "" +
		"trust_roots:\n" +
		"  - registry_url: https://reg.example/api/skills\n" +
		"    registry_keys:\n" +
		"      - id: reg-key-1\n" +
		"        pubkey: " + regKey.b64 + "\n" +
		"    identity_keys_authorized: from-registry\n" +
		"    governance_minimum: green\n" +
		"    require_independent_review: true\n"
	_, err := Load(writeTrustRootsYAML(t, body))
	if err == nil {
		t.Fatal("require_independent_review with no reviewers must be refused at Load")
	}
	if !strings.Contains(err.Error(), "require_independent_review needs a non-empty reviewers list") {
		t.Errorf("unexpected error: %v", err)
	}
}
