package sim

import (
	"strings"
	"testing"
)

// A traceability matrix that is maintained by hand drifts from the code exactly
// the way the poster drifted from the corpus, and for the same reason: nothing
// forces it to stay true. These tests are that force.

// TestEveryGateAndInvariantIsTraced fails when a gate or an invariant exists in
// the model without an entry saying where it came from. That is the failure mode
// worth catching: adding a check is easy, and an untraced check silently makes the
// matrix incomplete while the report keeps looking thorough.
func TestEveryGateAndInvariantIsTraced(t *testing.T) {
	traced := map[string]int{}
	for _, it := range TraceMatrix() {
		traced[it.ID]++
	}
	for id, n := range traced {
		if n > 1 {
			t.Errorf("%s appears %d times in the matrix; a claim with two origins has none", id, n)
		}
	}
	for _, g := range gauntlet {
		if traced[g.name] == 0 {
			t.Errorf("%s is evaluated by the model but has no traceability entry", g.name)
		}
	}
	for _, inv := range []Invariant{
		InvIntegrity, InvRevocation, InvGovernance, InvLoudRefusal, InvNoDowngrade,
		InvRefusalIsInert, InvAcceptDelivers, InvMetadataDecidesAlone,
	} {
		short := string(inv)
		if i := strings.Index(short, "-"); i > 0 {
			if j := strings.Index(short[i+1:], "-"); j > 0 {
				short = short[:i+1+j]
			}
		}
		if traced[short] == 0 {
			t.Errorf("%s is checked at runtime but has no traceability entry (looked for %q)", inv, short)
		}
	}
}

// TestNoTraceEntryIsOrphaned is the other direction: an entry for something the
// model no longer evaluates describes evidence that is not produced.
func TestNoTraceEntryIsOrphaned(t *testing.T) {
	known := map[string]bool{}
	for _, g := range gauntlet {
		known[g.name] = true
	}
	for _, inv := range []Invariant{
		InvIntegrity, InvRevocation, InvGovernance, InvLoudRefusal, InvNoDowngrade,
		InvRefusalIsInert, InvAcceptDelivers, InvMetadataDecidesAlone,
	} {
		s := string(inv)
		if i := strings.Index(s, "-"); i > 0 {
			if j := strings.Index(s[i+1:], "-"); j > 0 {
				known[s[:i+1+j]] = true
			}
		}
	}
	for _, it := range TraceMatrix() {
		if strings.HasPrefix(it.ID, "order: ") || strings.HasPrefix(it.ID, "verb: ") {
			// Ordering claims are properties of the composition, not single checks;
			// verb claims are checked by scenario steps rather than by the gauntlet.
			continue
		}
		if !known[it.ID] {
			t.Errorf("the matrix traces %q, which nothing in the model evaluates", it.ID)
		}
	}
}

// TestEveryTraceEntryHasASource pins the property that makes the matrix worth
// printing. An entry whose source a reader cannot check looks like provenance and
// is not, which is worse than leaving the row out.
func TestEveryTraceEntryHasASource(t *testing.T) {
	for _, it := range TraceMatrix() {
		if strings.TrimSpace(it.Source) == "" {
			t.Errorf("%s has no source", it.ID)
		}
		if strings.TrimSpace(it.What) == "" {
			t.Errorf("%s does not say what it asserts", it.ID)
		}
		// An observed or open rule must carry the caveat with it. Without the note
		// a reader takes a characterisation test for conformance evidence, which is
		// the single most expensive misreading this report can cause.
		if (it.Prov == ProvObserved || it.Prov == ProvOpen) && strings.TrimSpace(it.Note) == "" {
			t.Errorf("%s is %s and carries no note saying what that costs", it.ID, it.Prov)
		}
	}
}

// TestOutcomeCoverageNamesEveryDeclaredGate keeps the outcome measure honest: a
// declared decision missing from the target list would never be reported as
// missing, which is how a coverage figure quietly loses its denominator.
func TestOutcomeCoverageNamesEveryDeclaredGate(t *testing.T) {
	oc := Report{}.OutputCoverage()
	declared := map[string]bool{}
	for _, d := range oc.Declared {
		declared[d] = true
	}
	for _, g := range gauntlet {
		if !declared[g.name] {
			t.Errorf("%s is a declared decision but is not in the outcome coverage target", g.name)
		}
	}
	if !declared["accept"] {
		t.Error("acceptance is a decision too and must be counted")
	}
}
