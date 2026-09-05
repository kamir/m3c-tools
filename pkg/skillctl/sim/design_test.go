package sim

import (
	"testing"
)

// TestCoveringArrayCoversEveryAdmissiblePair pins the DEFINING property, not an
// incidental one. A covering array is worth having only if the claim printed in
// the report ("every admissible 2-way combination appears") is actually true, and
// that claim is checked here against an independent enumeration rather than
// against the algorithm's own bookkeeping.
func TestCoveringArrayCoversEveryAdmissiblePair(t *testing.T) {
	for _, strength := range []int{1, 2} {
		rows, stats := CoveringArray(strength)
		if len(rows) == 0 {
			t.Fatalf("t=%d: empty design", strength)
		}

		want := map[tuple]bool{}
		for _, p := range allParams() {
			if !meaningful(p) {
				continue
			}
			for _, tp := range tuplesOf(levelsOf(p), strength) {
				want[tp] = true
			}
		}
		got := map[tuple]bool{}
		for _, p := range rows {
			for _, tp := range tuplesOf(levelsOf(p), strength) {
				got[tp] = true
			}
		}
		for tp := range want {
			if !got[tp] {
				t.Errorf("t=%d: combination %s=%s appears in no row", strength, tp.axes, tp.vals)
			}
		}
		if stats.Admissible != len(want) {
			t.Errorf("t=%d: reported %d admissible combinations, enumerated %d",
				strength, stats.Admissible, len(want))
		}
	}
}

// TestCoverageAccountingAddsUp guards the number that would be easiest to fake.
// A coverage figure whose denominator quietly shrinks always looks excellent, so
// the excluded combinations must be reported and must reconcile with the total.
func TestCoverageAccountingAddsUp(t *testing.T) {
	_, stats := CoveringArray(2)
	if stats.Admissible+stats.Uncoverable != stats.Total {
		t.Errorf("%d admissible + %d uncoverable != %d total",
			stats.Admissible, stats.Uncoverable, stats.Total)
	}
	if stats.Uncoverable == 0 {
		t.Error("no combination is excluded, so either the model gained no constraints " +
			"or the exclusion accounting stopped working; both deserve a look")
	}
	if stats.Rows > stats.FullEnumeration {
		t.Errorf("design of %d rows is larger than the %d-row exhaustive corpus it replaces",
			stats.Rows, stats.FullEnumeration)
	}
}

// TestCoveringArrayIsDeterministic matters because two reports are only comparable
// if they ran the same experiment. A greedy search with an unstable tie-break would
// silently change the corpus between runs and turn every comparison into noise.
func TestCoveringArrayIsDeterministic(t *testing.T) {
	a, sa := GenerateCovering(2)
	b, sb := GenerateCovering(2)
	if sa != sb {
		t.Fatalf("stats differ between runs: %+v vs %+v", sa, sb)
	}
	if len(a) != len(b) {
		t.Fatalf("row count differs between runs: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].ID != b[i].ID {
			t.Fatalf("row %d differs between runs: %s vs %s", i, a[i].ID, b[i].ID)
		}
	}
}

// TestExcludedPointsAreExcludedForAStatedReason keeps the two invariants honest.
// They were once described on a poster as a single cause, and recomputing the bits
// showed they are two, so each is asserted separately here.
func TestExcludedPointsAreExcludedForAStatedReason(t *testing.T) {
	for _, p := range allParams() {
		if meaningful(p) {
			// R1: a revoke presupposes a release.
			if p.Revoke && p.Gov != GovGreen {
				t.Errorf("R1 violated: %+v is admissible but revokes without a release", p)
			}
			// R2: the envelope forgery is decided by the first gate.
			if p.Adv == AdvForgeEnvelope && (p.Gov != GovGreen || p.Key != KeySeparatePin) {
				t.Errorf("R2 violated: %+v is admissible but varies axes the first gate makes moot", p)
			}
		}
	}
}

// TestStepOracleAgreesWithTheAnalyticModel is the regression for the defect the
// covering array found the moment it was switched on: the per-step prediction and
// the closed form were two separate implementations of one theory, and they had
// drifted apart on the envelope forgery. They must not diverge again.
func TestStepOracleAgreesWithTheAnalyticModel(t *testing.T) {
	for _, p := range allParams() {
		if !meaningful(p) {
			continue
		}
		ok, gate, _ := installExpected(p)
		accept, g := StateAt(p, false).Decide()
		if ok != accept || (!ok && gate != g) {
			t.Errorf("%+v: step oracle says (accept=%v, %q), model says (accept=%v, %q)",
				p, ok, gate, accept, g)
		}
	}
}
