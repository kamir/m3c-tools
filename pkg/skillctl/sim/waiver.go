package sim

// waiver.go replaces the worst mechanism this package has had.
//
// A known-open finding used to be handled by marking its step UNCLAIMED, which
// removed it from the comparison entirely. An IEEE 1012 reviewer took the run
// apart on 2026-09-05 and showed what that produced: the single step whose model
// prediction disagreed with the binary was the step that had been removed, so the
// headline "conflicts: none" was selection on the outcome. The report even carried
// a comment warning against exactly that, four lines above the code doing it.
//
// A waiver is the honest shape. The comparison runs, the conflict is produced,
// judged and counted, and a named waiver says who accepted it and under which
// finding. The gate does not fail on a waived conflict, and the report prints the
// waiver every time, next to the number it modifies. Nothing disappears.
//
// The difference matters because the two look identical in a green run and behave
// oppositely when the product changes. An unclaimed step stays silent forever. A
// waived conflict starts shouting the moment its observation changes, because the
// waiver names the exact observation it covers.

import (
	"fmt"
	"io"
	"sort"
)

// Waiver accepts one specific disagreement, on the record.
type Waiver struct {
	Adv      AdvKind // the corpus dimension it applies to
	Expected string  // the gate the model predicts
	Observed string  // the gate actually seen, "" for none
	Finding  string  // the tracked finding
	Why      string
}

// Waivers is the register. Empty is the goal.
func Waivers() []Waiver {
	return []Waiver{
		{
			Adv: AdvPublisherBadSigs, Expected: "gate 3", Observed: "",
			Finding: "FR-0121",
			Why: "the model predicts gate 3 and the binary refuses without naming a gate. " +
				"Three attempts to construct a bundle that reaches gate 3 failed for three " +
				"different reasons, and the gate-3 mutant is NOT detected, so which side is " +
				"wrong is genuinely open. The refusal itself, its exit code and the untouched " +
				"install target are compared and hold",
		},
	}
}

// waiverFor returns the waiver covering this disagreement, if any.
func waiverFor(sc Scenario, r StepResult) *Waiver {
	for i := range Waivers() {
		w := Waivers()[i]
		if sc.P.Adv == w.Adv && r.Step.Expect.Gate == w.Expected && r.Gate == w.Observed {
			return &w
		}
	}
	return nil
}

// WaivedConflicts counts the conflicts a waiver covers, and the ones it does not.
func (rep Report) WaivedConflicts() (waived, unwaived int) {
	for _, r := range rep.Results {
		for i, v := range r.Verdicts {
			if v != VerdictConflict {
				continue
			}
			if waiverFor(r.Scenario, r.Steps[i]) != nil {
				waived++
			} else {
				unwaived++
			}
		}
	}
	return
}

// WriteWaivers prints the register beside the numbers it modifies.
func (rep Report) WriteWaivers(w io.Writer) {
	ws := Waivers()
	if len(ws) == 0 {
		return
	}
	waived, unwaived := rep.WaivedConflicts()
	sort.Slice(ws, func(i, j int) bool { return ws[i].Finding < ws[j].Finding })
	fmt.Fprintf(w, "\nwaivers: accepted disagreements, on the record (%d)\n", len(ws))
	for _, x := range ws {
		obs := x.Observed
		if obs == "" {
			obs = "no gate named"
		}
		fmt.Fprintf(w, "  %s  %s: model says %s, binary says %s\n", x.Finding, x.Adv, x.Expected, obs)
		fmt.Fprintf(w, "      %s\n", x.Why)
	}
	fmt.Fprintf(w, "  %d conflict(s) waived, %d not waived. A waived conflict is COUNTED and\n", waived, unwaived)
	fmt.Fprintf(w, "  reported; it does not fail the gate. It is not the same as a step that was\n")
	fmt.Fprintf(w, "  never compared: change what the binary does here and the waiver stops\n")
	fmt.Fprintf(w, "  matching, and the conflict fails the run again.\n")
}
