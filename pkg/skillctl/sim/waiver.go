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

	// Invariant, when set, also waives that invariant for this dimension. A defect
	// that trips both the gate comparison and an invariant should be waived once
	// and visibly, not silenced in one place and left to fail in the other.
	Invariant Invariant
}

// Waivers is the register. Empty is the goal.
func Waivers() []Waiver {
	return []Waiver{
		{
			Adv: AdvStaleChecksums, Expected: "", Observed: "accept",
			Finding:   "BUG-0217",
			Invariant: InvAcceptDelivers,
			Why: "MEASURED SPEC VIOLATION, not an open question. SPEC-0188 §7 step 8 verifies " +
				"the CHECKSUMS file inside the bundle and says any failure in steps 3 to 8 means " +
				"no write. The trust-mode pull path extracts without that check (extractSkb does " +
				"not validate; the other install path does), and a bundle whose internal manifest " +
				"no longer describes its contents is installed. Waived so the gate stays usable " +
				"while the fix is decided; it is a defect, not a naming question",
		},
		{
			Adv: AdvPublisherBadSigs, Expected: "gate 3", Observed: "accept",
			Finding: "FR-0121",
			Why: "UNSTABLE MEASUREMENT, and that is the finding. This case has been observed " +
				"both refusing without a gate name and accepting, across successive harness " +
				"revisions on the same product build. One clean re-measurement on a frozen " +
				"harness is owed before anything is concluded from it. Originally: " +
				"The mutant for gate 3 is indistinguishable from the unmutated baseline, so " +
				"nothing here depends on that control and it is UNVERIFIED. Two earlier " +
				"descriptions of this case, both withdrawn, are recorded in FR-0121. What is " +
				"waived is the outcome comparison; INV-6 still asserts that the refusal, where " +
				"one happens, leaves the install target untouched",
		},
	}
}

// waiverFor returns the waiver covering this disagreement, if any.
func waiverFor(sc Scenario, r StepResult) *Waiver {
	// The observed side is matched against the gate name when there is one, and
	// against the literal "accept" when the pull was accepted. A waiver that could
	// not name an acceptance would be unable to cover the case that matters most:
	// a specified refusal that did not happen.
	obs := r.Gate
	if r.Outcome == Accept {
		obs = "accept"
	}
	for i := range Waivers() {
		w := Waivers()[i]
		if sc.P.Adv == w.Adv && r.Step.Expect.Gate == w.Expected && obs == w.Observed {
			return &w
		}
	}
	return nil
}

// WaivedViolations splits invariant violations the same way conflicts are split.
// The report prints both counts beside the waiver register.
func (rep Report) WaivedViolations() (waived, unwaived int) {
	for _, r := range rep.Results {
		for _, v := range r.Violations {
			hit := false
			for _, w := range Waivers() {
				if w.Invariant != "" && r.Scenario.P.Adv == w.Adv && v.Invariant == w.Invariant {
					hit = true
					break
				}
			}
			if hit {
				waived++
			} else {
				unwaived++
			}
		}
	}
	return
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
	wv, uv := rep.WaivedViolations()
	fmt.Fprintf(w, "  %d conflict(s) waived, %d not waived; %d invariant violation(s) waived, %d not.\n",
		waived, unwaived, wv, uv)
	fmt.Fprintf(w, "  A waived finding is COUNTED and\n")
	fmt.Fprintf(w, "  reported; it does not fail the gate. It is not the same as a step that was\n")
	fmt.Fprintf(w, "  never compared: change what the binary does here and the waiver stops\n")
	fmt.Fprintf(w, "  matching, and the conflict fails the run again.\n")
}
