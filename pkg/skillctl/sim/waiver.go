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

	// Kind restricts the waiver to one action. Without it the match was on the
	// adversary dimension plus an expected gate plus an observed outcome, and an
	// EMPTY expected gate matches every step of that dimension's scenarios whose
	// prediction carries no gate name: pack, admit, attest, pin. So a waiver for a
	// defect in the PULL also covered the admit and the attestation beside it, and
	// a regression in either would have been swallowed under a finding that has
	// nothing to do with them.
	//
	// The reach was bounded by the adversary dimension and never crossed into
	// another one; an earlier note here claimed it reached the verify-sig steps,
	// and that was wrong, because those belong to AdvTransitChecked and the
	// dimension is compared first. Complete within one dimension is bad enough:
	// the register's whole purpose is that an accepted disagreement stays the size
	// it was accepted at.
	//
	// Found by the MEASURED lines below, on their first run: eighteen where one
	// was expected. The over-match had been silent for as long as it existed and
	// became visible the moment something had to print what it covered.
	//
	// Required, so a new waiver cannot be written without saying where it applies.
	Kind ActionKind
}

// Waivers is the register. Empty is the goal, and it now holds one entry, not two.
//
// The FR-0121 entry is GONE, and its removal is the substance of this change
// rather than housekeeping. It waived the case "model says gate 3, binary says
// accept" and described it as an unstable measurement owing one clean re-run.
// The re-run happened on 2026-09-06 and found a cause: the adversary move edited
// the detached "<bundle>.<digest>.author.sig" file, which the trust-mode pull
// path never opens. Gate 3 was never reached, so the acceptance was correct behaviour
// against a case that did not test it, and the disagreement was the MODEL's. With
// a move that reaches the gate (see ForgeBundleSignatures) the prediction holds
// and there is nothing left to waive.
//
// What remains is BUG-0217, and it is a different animal: a measured violation of
// a written requirement, waived so the gate stays usable while the fix is decided.
// Keeping the two apart is the point of the register. One was a defect in the
// instrument, the other is a defect in the product, and a register that cannot
// tell them apart will eventually be used to hide the second behind the first.
func Waivers() []Waiver {
	return []Waiver{
		{
			Adv: AdvStaleChecksums, Kind: ActPull, Expected: "", Observed: "accept",
			Finding:   "BUG-0217",
			Invariant: InvAcceptDelivers,
			Why: "A DEFECT, not an open question, and the line above is the measurement of it. " +
				"SPEC-0188 §7 step 8 verifies " +
				"the CHECKSUMS file inside the bundle and says any failure in steps 3 to 8 means " +
				"no write. The trust-mode pull path extracts without that check (extractSkb does " +
				"not validate; the other install path does), and a bundle whose internal manifest " +
				"no longer describes its contents is installed. Waived so the gate stays usable " +
				"while the fix is decided; it is a defect, not a naming question",
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
		if w.Kind == "" {
			// A waiver without an action would match across the whole scenario.
			// Refusing it here is cheaper than discovering later which unrelated
			// step it swallowed.
			continue
		}
		if sc.P.Adv == w.Adv && r.Step.Action.Kind == w.Kind &&
			r.Step.Expect.Gate == w.Expected && obs == w.Observed {
			return &w
		}
	}
	return nil
}

// waiverEvidence returns what the run actually observed at the steps this waiver
// covers: scenario, outcome, exit code and gate, verbatim from the comparison.
//
// It exists because the register's own Expected and Observed fields are AUTHOR
// input, not measurement. A waiver whose fields drift from the behaviour will
// simply stop matching, which is the safety net, but the fields still describe
// the case in the author's words. Printing the run's values beside them means a
// wrong description is visible next to what it describes rather than three
// sections away.
func (rep Report) waiverEvidence(x Waiver) []string {
	var out []string
	seen := map[string]bool{}
	for _, r := range rep.Results {
		for i := range r.Steps {
			// Only the steps this waiver actually SUPPRESSED. Listing every step
			// it merely matches would bury the one line that matters under the
			// scenario's ordinary accepts, which is how the last misleading
			// waiver stayed readable for two days.
			if i >= len(r.Verdicts) || r.Verdicts[i] != VerdictConflict {
				continue
			}
			if waiverFor(r.Scenario, r.Steps[i]) == nil || r.Scenario.P.Adv != x.Adv {
				continue
			}
			st := r.Steps[i]
			gate := st.Gate
			if gate == "" {
				gate = "no gate named"
			}
			line := fmt.Sprintf("%s step %d: %s exit=%d gate=%q",
				r.Scenario.ID, i+1, st.Outcome, st.ExitCode, gate)
			if seen[line] {
				continue
			}
			seen[line] = true
			out = append(out, line)
		}
	}
	sort.Strings(out)
	if len(out) > 3 {
		rest := len(out) - 3
		out = append(out[:3], fmt.Sprintf("(and %d more step(s) with the same shape)", rest))
	}
	return out
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

// WriteWaivers prints the register beside the numbers it modifies, and marks its
// prose as prose.
//
// The marking is not decoration. On 2026-09-05 this section carried the sentence
// "The control is live: disabling gate 3 flips this pull from refuse to accept."
// Nobody had measured that. It was an author's explanation, printed every run in
// the same column as measured counts, and two readers in two different sessions
// quoted it back as though it were output. One of them used it to contradict a
// measurement, and was reasoning from the report exactly as the report invited.
//
// A number in this report comes from the run. Everything after "WHY (not measured)"
// comes from whoever wrote the waiver, and it is only as good as the argument it
// makes. Same page, different epistemic status, so the page has to say which is
// which.
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
		exp := x.Expected
		if exp == "" {
			exp = "no refusal at all"
		}
		fmt.Fprintf(w, "  %s  %s: model says %s, binary says %s\n", x.Finding, x.Adv, exp, obs)
		for _, ln := range rep.waiverEvidence(x) {
			fmt.Fprintf(w, "      MEASURED  %s\n", ln)
		}
		fmt.Fprintf(w, "      WHY (not measured, this is the waiver author's argument):\n")
		fmt.Fprintf(w, "      %s\n", x.Why)
	}
	wv, uv := rep.WaivedViolations()
	fmt.Fprintf(w, "  %d conflict(s) waived, %d not waived; %d invariant violation(s) waived, %d not.\n",
		waived, unwaived, wv, uv)
	fmt.Fprintf(w, "  The MEASURED lines come from this run. The WHY beneath them does not: it is\n")
	fmt.Fprintf(w, "  the argument of whoever wrote the waiver, and it is only as good as that\n")
	fmt.Fprintf(w, "  argument. They are printed adjacently so a WHY that contradicts the values\n")
	fmt.Fprintf(w, "  beside it refutes itself at a glance. The one this register used to carry did\n")
	fmt.Fprintf(w, "  exactly that, and it survived two days because the contradiction sat three\n")
	fmt.Fprintf(w, "  sections apart and had to be held in a reader's head.\n")
	fmt.Fprintf(w, "  A waived finding is COUNTED and\n")
	fmt.Fprintf(w, "  reported; it does not fail the gate. It is not the same as a step that was\n")
	fmt.Fprintf(w, "  never compared: change what the binary does here and the waiver stops\n")
	fmt.Fprintf(w, "  matching, and the conflict fails the run again.\n")
}
