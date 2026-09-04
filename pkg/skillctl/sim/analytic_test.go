package sim

import "testing"

// The theory has to be checkable on its own, without running the binary: these
// tests pin the closed form so a later edit to the model is a deliberate act
// rather than an accident.

func TestDecideIsFirstFailureInOrder(t *testing.T) {
	// A state that violates BOTH governance and the digest must report the
	// GOVERNANCE gate, because governance is evaluated first. Getting this wrong
	// is the single most likely modelling error, and it was made in the first
	// draft of this package.
	s := State{EnvelopeSigned: true, SigsVerify: true, GovQualifies: false, DigestMatches: false}
	ok, gate := s.Decide()
	if ok || gate != "gate 4" {
		t.Fatalf("first failure in evaluation order must win, got ok=%v gate=%q", ok, gate)
	}
}

func TestDecideRevokedBeatsGovernance(t *testing.T) {
	s := State{EnvelopeSigned: true, SigsVerify: true, DigestMatches: true, Revoked: true, GovQualifies: false}
	ok, gate := s.Decide()
	if ok || gate != "gate 5" {
		t.Fatalf("a revoke is checked before governance, got ok=%v gate=%q", ok, gate)
	}
}

func TestStateAtTransitTamperFailsGovernanceNotDigest(t *testing.T) {
	// The intuitive answer is "digest mismatch". It is wrong: the reviewer attested
	// the PRE-tamper digest, so the admitted bytes carry no governance at all.
	s := StateAt(Params{Gov: GovGreen, Key: KeySeparatePin, Adv: AdvTransitSkipped}, false)
	ok, gate := s.Decide()
	if ok || gate != "gate 4" {
		t.Fatalf("transit tampering must surface as a governance failure, got ok=%v gate=%q", ok, gate)
	}
}

func TestStateAtStripRevokeHidesTheRevoke(t *testing.T) {
	// Deleting the event hides it; renaming it does not, because identity comes
	// from the signed envelope and never from the path.
	stripped := StateAt(Params{Gov: GovGreen, Key: KeySeparatePin, Adv: AdvStripRevoke, Revoke: true}, true)
	if stripped.Revoked {
		t.Error("a deleted revoke event is not visible to the consumer")
	}
	relabelled := StateAt(Params{Gov: GovGreen, Key: KeySeparatePin, Adv: AdvRelabelRevoke, Revoke: true}, true)
	if !relabelled.Revoked {
		t.Error("a RENAMED revoke must still count: the path is not the identity")
	}
}

func TestGenerateProducesNoDuplicateIDs(t *testing.T) {
	seen := map[string]bool{}
	for _, sc := range Generate(0) {
		if seen[sc.ID] {
			t.Fatalf("duplicate scenario id %s: the corpus is padded", sc.ID)
		}
		seen[sc.ID] = true
	}
}

// Sampling must span the space rather than take an alphabetical prefix.
func TestGenerateSamplesAcrossCasts(t *testing.T) {
	casts := map[Cast]bool{}
	for _, sc := range Generate(20) {
		casts[sc.P.Cast] = true
	}
	if len(casts) < 3 {
		t.Errorf("a 20-scenario sample reached only %d of 3 casts: the sampler is biased", len(casts))
	}
}
