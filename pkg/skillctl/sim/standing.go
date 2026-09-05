package sim

// standing.go says what this run IS, before it says what it found.
//
// An IEEE 1012 review starts by asking three questions that no amount of measured
// detail can answer afterwards: what integrity level is claimed, is this
// verification or validation, and who checked whom. Until 2026-09-05 this package
// answered none of them, and the poster built on it called itself an "empirische
// Validierung" while doing verification. That is not a wording slip: the two words
// name different evidence, and only one of them was produced.
//
// The block below prints first in every report, on purpose. A reader who stops
// after it has still learned the most important thing.

import (
	"fmt"
	"io"
)

// WriteStanding prints scope, integrity level, independence and the explicit
// non-claims.
func (rep Report) WriteStanding(w io.Writer) {
	fmt.Fprintf(w, "\nwhat this run is, before what it found\n")

	fmt.Fprintf(w, "\n  VERIFICATION, NOT VALIDATION.\n")
	fmt.Fprintf(w, "  IEEE 1012 separates two questions. Verification asks whether the product\n")
	fmt.Fprintf(w, "  meets its SPECIFIED requirements; validation asks whether it meets the\n")
	fmt.Fprintf(w, "  requirements of its INTENDED USE, with its users, in its environment.\n")
	fmt.Fprintf(w, "  This run does the first. It compares the shipped binary against a model\n")
	fmt.Fprintf(w, "  derived from SPEC-0188 and SPEC-0359, and it calibrates its own ability to\n")
	fmt.Fprintf(w, "  see a defect. It does not do the second, and nothing here should be read\n")
	fmt.Fprintf(w, "  as if it did.\n")

	fmt.Fprintf(w, "\n  INTEGRITY LEVEL: high, claimed and not yet independently agreed.\n")
	fmt.Fprintf(w, "  A defect in this component permits installation of software the operator\n")
	fmt.Fprintf(w, "  did not authorise. IEEE 1012 scales the required rigour with the integrity\n")
	fmt.Fprintf(w, "  level, so claiming a high one means claiming obligations, not credit. Two\n")
	fmt.Fprintf(w, "  of those obligations are not met today: independence (below) and coverage\n")
	fmt.Fprintf(w, "  of the operational environment (below).\n")

	fmt.Fprintf(w, "\n  INDEPENDENCE: none.\n")
	fmt.Fprintf(w, "  One author read the specification, built the model, generated the corpus,\n")
	fmt.Fprintf(w, "  wrote the oracle and produced this report. Adversarial reviews found real\n")
	fmt.Fprintf(w, "  defects, including four in the instrument itself, but they were commissioned\n")
	fmt.Fprintf(w, "  by the same author and are not independent in any sense IEEE 1012 uses.\n")
	fmt.Fprintf(w, "  What would change this: a reviewer who does not know the implementation\n")
	fmt.Fprintf(w, "  checking the model against the specification.\n")

	fmt.Fprintf(w, "\n  NOT CLAIMED, explicitly.\n")
	fmt.Fprintf(w, "    A failure rate. There is no operational profile, so no reliability\n")
	fmt.Fprintf(w, "      statement follows from any number here. Residual zero is not a field\n")
	fmt.Fprintf(w, "      quality claim.\n")
	fmt.Fprintf(w, "    The operational environment. Every scenario runs against a bare local git\n")
	fmt.Fprintf(w, "      repository created inside the run. The intended use includes github://,\n")
	fmt.Fprintf(w, "      gitlab:// and ER1 backends and Windows clients. That those behave the\n")
	fmt.Fprintf(w, "      same is an ASSUMPTION and is untested.\n")
	fmt.Fprintf(w, "    Human understanding. Whether a person reads a refusal correctly is not\n")
	fmt.Fprintf(w, "      measured, and no arrangement of machine checks measures it.\n")
	fmt.Fprintf(w, "    That the tested binary is the shipped artifact. The hash below identifies\n")
	fmt.Fprintf(w, "      what ran, not what is released.\n")
}

// OutputCoverage is the second coverage measure, and the one that answers the
// question the first cannot.
//
// Pairwise coverage of the FACTORS says the corpus is broad on its inputs. It says
// nothing about whether each decision the specification declares was ever seen,
// and the two came apart in practice: after one model change no row reached the
// digest gate any more while input coverage stayed at 100 percent. So the outcomes
// get their own measure, with a target declared before the run rather than read off
// it afterwards.
type OutputCoverage struct {
	Declared []string       // every decision the specification declares
	Seen     map[string]int // how often each was observed
	Target   int            // the minimum observations per decision this run demands

	// Unlabelled counts claimed refusals that named no gate at all. They are not
	// silently folded into any decision: a refusal a caller cannot attribute is
	// its own result and is reported as one.
	Unlabelled int
}

// OutcomeTarget is the declared adequacy criterion: every gate the specification
// names must be observed at least this often, or the run says which one was not.
//
// One is a low bar and it is deliberately a bar rather than a wish: the value of
// naming it is that "gate 3: 0" becomes a stated failure of coverage instead of a
// number nobody promised anything about.
const OutcomeTarget = 1

// OutputCoverage computes the measure for this run.
func (rep Report) OutputCoverage() OutputCoverage {
	// ONE POPULATION for the whole table: pull steps whose outcome the model
	// CLAIMS. An IEEE 1012 reviewer found two defects here on 2026-09-05 and both
	// were real. The gate rows were counted over every step while the accept row
	// was counted over pulls, so a table with two denominators reported gate 5 as
	// 11 while the histogram beside it reported 10. And the accept row counted
	// steps the same report lists as out of model, which cannot be evidence and a
	// disclaimer at once.
	oc := OutputCoverage{
		Declared: []string{"gate 1", "gate 2", "gate 3", "gate 4", "gate 5", "accept"},
		Seen:     map[string]int{},
		Target:   OutcomeTarget,
	}
	for _, d := range oc.Declared {
		oc.Seen[d] = 0
	}
	for _, r := range rep.Results {
		for _, s := range r.Steps {
			if s.Step.Action.Kind != ActPull || !s.Step.Expect.Claimed {
				continue
			}
			switch {
			case s.Outcome == Accept:
				oc.Seen["accept"]++
			case s.Gate != "":
				oc.Seen[s.Gate]++
			default:
				oc.Unlabelled++
			}
		}
	}
	return oc
}

// Short returns the decisions that fell below the declared target.
func (oc OutputCoverage) Short() []string {
	var out []string
	for _, d := range oc.Declared {
		if oc.Seen[d] < oc.Target {
			out = append(out, d)
		}
	}
	return out
}

// WriteOutputCoverage prints it, including the shortfall.
func (rep Report) WriteOutputCoverage(w io.Writer) {
	oc := rep.OutputCoverage()
	fmt.Fprintf(w, "\ncoverage of OUTCOMES, against a target declared before the run\n")
	fmt.Fprintf(w, "  target: every declared decision observed at least %d time(s)\n", oc.Target)
	for _, d := range oc.Declared {
		mark := ""
		if oc.Seen[d] < oc.Target {
			mark = "   <-- BELOW TARGET"
		}
		fmt.Fprintf(w, "    %-10s %4d%s\n", d, oc.Seen[d], mark)
	}
	if oc.Unlabelled > 0 {
		fmt.Fprintf(w, "    %-10s %4d   (claimed refusals that named no gate; see FR-0120)\n",
			"unlabelled", oc.Unlabelled)
	}
	fmt.Fprintf(w, "  Population: pull steps whose outcome the model claims. One denominator for\n")
	fmt.Fprintf(w, "  the whole table, so these rows and the histogram below are the same quantity.\n")
	if s := oc.Short(); len(s) > 0 {
		fmt.Fprintf(w, "  %d declared decision(s) below target. Input coverage cannot substitute:\n", len(s))
		fmt.Fprintf(w, "  a corpus can cover every pair of inputs and still never reach a gate.\n")
	} else {
		fmt.Fprintf(w, "  Every declared decision was observed at least once.\n")
	}
}
