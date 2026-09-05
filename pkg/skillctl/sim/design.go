package sim

// design.go replaces a hand-written filter with a DESIGNED experiment.
//
// The corpus used to be chosen by a function called meaningful(), which decided
// point by point what looked interesting. It was honestly commented and it worked,
// but a reviewer put the objection correctly on 2026-09-05: the selection was
// justified by its ORIGIN (it came from the documented user scenarios), never by
// its ADEQUACY. And the measured yield said the same thing: 17 distinct decision
// paths out of 100 scenarios, so 83 runs were compute without a new statement.
//
// The established form for this is a COVERING ARRAY of strength t: a set of rows
// such that every combination of t factor values appears in at least one row. It
// turns "is this corpus broad?" from a feeling into an arithmetic property, and it
// usually needs an order of magnitude fewer rows than a full enumeration.
//
// Strength, decided 2026-09-05: t=2 as the gate, t=3 for the weekly run. Pairwise
// catches the interactions between any two knobs; three-way catches what needs
// three things to line up at once, which is exactly where the two real defects of
// this week were found, and it is too slow to run on every commit.
//
// CONSTRAINTS matter here and are the reason this is not a textbook covering
// array. Some factor combinations are excluded by the model itself (a revoke
// presupposes a release; the envelope forgery is pinned to one governance level).
// A pair that only exists inside an excluded region is NOT coverable, and demanding
// it would either force nonsense scenarios or make the coverage number a permanent
// failure. So the target set is computed from the ADMISSIBLE points, and the report
// says how many pairs that leaves.

import (
	"fmt"
	"sort"
	"strings"
)

// factors is the experiment design: each axis with its levels. Order is fixed so
// two runs of the generator produce the same array.
func factors() []struct {
	name   string
	levels []string
} {
	return []struct {
		name   string
		levels []string
	}{
		{"cast", strsOf(AllCasts())},
		{"key", strsOf(AllKeyings())},
		{"gov", strsOf(AllGovs())},
		{"adv", strsOf(AllAdvKinds())},
		{"revoke", []string{"false", "true"}},
	}
}

// strsOf renders any axis of named string constants as its levels. It exists so
// the design reads the SAME list the generator enumerates: a factor table that
// keeps its own copy of the levels will eventually plan over a space the corpus
// no longer has, and it did.
func strsOf[T ~string](vals []T) []string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		out = append(out, string(v))
	}
	return out
}

// levelsOf projects a corpus point onto the design axes.
func levelsOf(p Params) []string {
	return []string{
		string(p.Cast), string(p.Key), string(p.Gov), string(p.Adv),
		map[bool]string{true: "true", false: "false"}[p.Revoke],
	}
}

// tuple identifies one t-way combination: which axes, and which values on them.
type tuple struct {
	axes string // e.g. "0,3"
	vals string // e.g. "solo|stolen-key"
}

// tuplesOf enumerates the t-way combinations a single point covers.
func tuplesOf(vals []string, t int) []tuple {
	var out []tuple
	n := len(vals)
	var rec func(start int, idx []int)
	rec = func(start int, idx []int) {
		if len(idx) == t {
			a, v := "", ""
			for i, j := range idx {
				if i > 0 {
					a, v = a+",", v+"|"
				}
				a += fmt.Sprint(j)
				v += vals[j]
			}
			out = append(out, tuple{a, v})
			return
		}
		for j := start; j < n; j++ {
			rec(j+1, append(idx, j))
		}
	}
	rec(0, nil)
	return out
}

// CoveringArray builds a strength-t design over the ADMISSIBLE corpus points.
//
// The algorithm is greedy set cover: repeatedly take the candidate that covers the
// most still-uncovered tuples. Greedy is not optimal, and it does not need to be:
// the guarantee that matters is COMPLETE coverage of the coverable tuples, which
// greedy always reaches because every tuple has at least one candidate containing
// it by construction. Determinism comes from the fixed factor order plus a stable
// tie-break on the scenario id, so the same array comes out every time and two
// reports stay comparable.
func CoveringArray(t int) ([]Params, CoverageStats) {
	var candidates []Params
	for _, p := range allParams() {
		if meaningful(p) {
			candidates = append(candidates, p)
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		return build(candidates[i]).ID < build(candidates[j]).ID
	})

	// The target set: every t-tuple that at least one admissible point realises.
	// Tuples that live only in the excluded region are not coverable and are
	// counted separately, because a coverage figure that silently drops its
	// denominator is the oldest trick in this business.
	target := map[tuple]bool{}
	for _, p := range candidates {
		for _, tp := range tuplesOf(levelsOf(p), t) {
			target[tp] = true
		}
	}
	all := map[tuple]bool{}
	for _, p := range allParams() {
		for _, tp := range tuplesOf(levelsOf(p), t) {
			all[tp] = true
		}
	}

	uncovered := map[tuple]bool{}
	for k := range target {
		uncovered[k] = true
	}

	var chosen []Params
	for len(uncovered) > 0 {
		best, bestGain := -1, 0
		for i, p := range candidates {
			gain := 0
			for _, tp := range tuplesOf(levelsOf(p), t) {
				if uncovered[tp] {
					gain++
				}
			}
			if gain > bestGain {
				best, bestGain = i, gain
			}
		}
		if best < 0 {
			break // unreachable: every target tuple came from a candidate
		}
		chosen = append(chosen, candidates[best])
		for _, tp := range tuplesOf(levelsOf(candidates[best]), t) {
			delete(uncovered, tp)
		}
		candidates = append(candidates[:best], candidates[best+1:]...)
	}

	return chosen, CoverageStats{
		Strength:        t,
		Rows:            len(chosen),
		Admissible:      len(target),
		Total:           len(all),
		Uncoverable:     len(all) - len(target),
		FullEnumeration: countAdmissible(),
	}
}

// DesignAxes renders the experiment design for the report: which axes exist and
// how many levels each has. Printing it is what lets a reader judge whether the
// factor space is the right one, which is a question no coverage number answers.
func DesignAxes() string {
	parts := make([]string, 0, 5)
	for _, f := range factors() {
		parts = append(parts, fmt.Sprintf("%s(%d)", f.name, len(f.levels)))
	}
	return strings.Join(parts, " x ")
}

// CoverageStats is what the report needs to make the design arguable.
type CoverageStats struct {
	Strength        int
	Rows            int // scenarios in the array
	Admissible      int // t-tuples reachable inside the admissible region
	Total           int // t-tuples in the unconstrained factor space
	Uncoverable     int // Total minus Admissible: excluded by the model's own rules
	FullEnumeration int // how many scenarios the exhaustive corpus would have
}

func countAdmissible() int {
	n := 0
	for _, p := range allParams() {
		if meaningful(p) {
			n++
		}
	}
	return n
}

// GenerateCovering produces the scenarios of a strength-t design.
func GenerateCovering(t int) ([]Scenario, CoverageStats) {
	pts, stats := CoveringArray(t)
	out := make([]Scenario, 0, len(pts))
	for _, p := range pts {
		out = append(out, build(p))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, stats
}
