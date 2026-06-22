package verify

// SPEC-0246 §5 — reviewer≠author floor (require_independent_review).
//
// These tests exercise the offline pinned path (no IdentityFetcher) so the
// reviewer≠author gate is proven to be network-free. The binding governance
// attestation's reviewer_id is set equal to (self) or different from
// (independent) the pinned author identity; the trust-root floor is toggled.

import (
	"errors"
	"testing"
)

// setBindingReviewer overwrites the single binding attestation's reviewer id on
// a pinned-opts BundleMeta so a test can flip self vs independent review.
func setBindingReviewer(opts *VerifyOpts, reviewerID string) {
	for i := range opts.BundleMeta.Attestations {
		opts.BundleMeta.Attestations[i].ReviewerID = reviewerID
		// Clear any registry-stamped self_attested / author_id so the verifier
		// recomputes from reviewer vs the verified author identity.
		opts.BundleMeta.Attestations[i].SelfAttested = nil
		opts.BundleMeta.Attestations[i].AuthorID = ""
	}
}

func TestVerify_IndependentReview_FloorOff_SelfAllowed(t *testing.T) {
	// self tenant: floor OFF (default). A self-attested bundle must verify, and
	// the result must surface self_attested=true.
	opts, _ := pinnedOpts(t)
	setBindingReviewer(&opts, "id:kamir@m3c") // == pinned author id
	opts.TrustRoot.RequireIndependentReview = false

	res, err := Verify(opts)
	if err != nil {
		t.Fatalf("floor off: self-attested bundle should verify, got: %v", err)
	}
	if res.SelfAttested == nil || !*res.SelfAttested {
		t.Errorf("self_attested should be true; got %v", res.SelfAttested)
	}
}

func TestVerify_IndependentReview_FloorOn_SelfRefused(t *testing.T) {
	// Floor ON + self-attested → refuse with ErrSelfAttested (exit 20).
	opts, _ := pinnedOpts(t)
	setBindingReviewer(&opts, "id:kamir@m3c") // == pinned author id
	opts.TrustRoot.RequireIndependentReview = true

	_, err := Verify(opts)
	if !errors.Is(err, ErrSelfAttested) {
		t.Fatalf("floor on + self-attested should yield ErrSelfAttested, got: %v", err)
	}
	if ExitCode(err) != ExitSelfAttested {
		t.Errorf("exit code = %d, want %d", ExitCode(err), ExitSelfAttested)
	}
}

func TestVerify_IndependentReview_FloorOn_IndependentPasses(t *testing.T) {
	// Floor ON + independent reviewer → verify, self_attested=false.
	opts, _ := pinnedOpts(t)
	setBindingReviewer(&opts, "id:independent-reviewer@m3c") // != author
	opts.TrustRoot.RequireIndependentReview = true

	res, err := Verify(opts)
	if err != nil {
		t.Fatalf("floor on + independent review should pass, got: %v", err)
	}
	if res.SelfAttested == nil || *res.SelfAttested {
		t.Errorf("self_attested should be false; got %v", res.SelfAttested)
	}
}

func TestVerify_IndependentReview_FloorOn_RegistryStampedSelfRefused(t *testing.T) {
	// A registry-stamped self_attested:true is authoritative and must be
	// refused under the floor even if reviewer_id were spoofed to differ —
	// proving an attacker cannot launder a self-attestation by editing the id
	// while leaving the trusted server's verdict intact.
	opts, _ := pinnedOpts(t)
	tru := true
	for i := range opts.BundleMeta.Attestations {
		opts.BundleMeta.Attestations[i].ReviewerID = "id:looks-independent@m3c"
		opts.BundleMeta.Attestations[i].SelfAttested = &tru
	}
	opts.TrustRoot.RequireIndependentReview = true

	_, err := Verify(opts)
	if !errors.Is(err, ErrSelfAttested) {
		t.Fatalf("registry-stamped self_attested must be refused under the floor, got: %v", err)
	}
}

func TestVerify_IndependentReview_FloorOn_NoReviewerFailsClosed(t *testing.T) {
	// Floor ON but the binding attestation carries no reviewer identity and no
	// stamped self_attested → we cannot prove independence → fail closed.
	opts, _ := pinnedOpts(t)
	for i := range opts.BundleMeta.Attestations {
		opts.BundleMeta.Attestations[i].ReviewerID = ""
		opts.BundleMeta.Attestations[i].SelfAttested = nil
		opts.BundleMeta.Attestations[i].AuthorID = ""
	}
	opts.TrustRoot.RequireIndependentReview = true

	_, err := Verify(opts)
	if !errors.Is(err, ErrSelfAttested) {
		t.Fatalf("floor on + unprovable independence should fail closed with ErrSelfAttested, got: %v", err)
	}
}

func TestTrustRoots_RequireIndependentReview_StrictLoaderAccepts(t *testing.T) {
	// The STRICT loader (KnownFields(true)) must accept the declared
	// require_independent_review field — a typo'd/undeclared field would be
	// rejected, so this proves the field is wired into the schema.
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
	tr, err := Load(writeTrustRootsYAML(t, body))
	if err != nil {
		t.Fatalf("strict loader should accept require_independent_review, got: %v", err)
	}
	if !tr.Roots[0].RequireIndependentReview {
		t.Errorf("require_independent_review should be true after load")
	}
}
