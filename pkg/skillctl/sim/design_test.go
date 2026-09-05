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
			// R1 IS NOT ASSERTED HERE ANY MORE, and its absence is the point.
			//
			// It said a revoke presupposes a release. An external reviewer showed on
			// 2026-09-05 that a digest can be blocked pre-emptively, before anyone
			// attests or installs it, so the rule excluded a region that is both real
			// and worth testing. The corpus now enters it, which is why this test
			// checks that such points ARE admissible rather than that they are not.
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

// TestRevokeWithoutReleaseIsAdmissible is the positive form of the rule that was
// removed. A pre-emptive block is a legitimate use of a kill switch, so the corpus
// must be able to express it; if this ever fails, R1 has crept back.
func TestRevokeWithoutReleaseIsAdmissible(t *testing.T) {
	p := Params{Cast: CastSolo, Key: KeySeparatePin, Gov: GovNone, Adv: AdvNone, Revoke: true}
	if !meaningful(p) {
		t.Error("a revoke without a prior release is excluded from the corpus again; " +
			"that region is where a pre-emptive block lives")
	}
}

// TestGateSeedsIsolateTheirGate pins the property the seeds exist for: each one
// must make ITS gate the first to fail, judged by the analytic model rather than
// by the author's intention.
//
// Without this, a seed can quietly stop isolating its gate when the model changes,
// and the design would keep carrying a row that no longer buys what it was added
// for. That is how gate 2 became unobservable in the first place.
func TestGateSeedsIsolateTheirGate(t *testing.T) {
	want := []string{"gate 1", "gate 2", "gate 3", "gate 4", "gate 5"}
	seeds := gateSeeds()
	if len(seeds) != len(want) {
		t.Fatalf("%d seeds for %d gates", len(seeds), len(want))
	}
	for i, p := range seeds {
		if !meaningful(p) {
			t.Errorf("%s seed %+v is not admissible, so it can never enter the design", want[i], p)
			continue
		}
		accept, gate := StateAt(p, p.Revoke).Decide()
		if accept {
			t.Errorf("%s seed %+v is accepted, so it isolates nothing", want[i], p)
			continue
		}
		if gate != want[i] {
			t.Errorf("%s seed %+v fails at %s instead: an earlier gate masks the one under test",
				want[i], p, gate)
		}
	}
}

// TestEveryGateIsSeeded is the coverage guarantee itself: the design must contain
// a row for every gate the specification declares, whatever the greedy fill does
// with the rest of the space.
func TestEveryGateIsSeeded(t *testing.T) {
	rows, _ := CoveringArray(2)
	seen := map[string]bool{}
	for _, p := range rows {
		if accept, gate := StateAt(p, false).Decide(); !accept {
			seen[gate] = true
		}
		if p.Revoke {
			if accept, gate := StateAt(p, true).Decide(); !accept {
				seen[gate] = true
			}
		}
	}
	for _, g := range []string{"gate 1", "gate 2", "gate 3", "gate 4", "gate 5"} {
		if !seen[g] {
			t.Errorf("%s is not reached by any row of the design; that control is unobservable", g)
		}
	}
}
