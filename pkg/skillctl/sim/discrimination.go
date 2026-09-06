package sim

// discrimination.go measures something the run asserted without measuring: can a
// CALLER tell why a pull was refused?
//
// A software validation reviewer put it on 2026-09-05, and the code confirms it:
// pkg/skillctl/exitcode/registry.go defines typed codes with stable reason keys
// (digest_mismatch, governance_below_min, registry_not_trusted, and more), and
// cmd/skillctl/pull_cmds.go returns a bare 1 on every rejection path. The registry
// header calls this out as its own unfinished phase 3, "migrate all os.Exit call
// sites so the registry is the only source of truth".
//
// The consequence is not cosmetic. A reviewer scripting around skillctl, an audit
// record, and any automated policy all need the cause as DATA. Today they get one
// bit: it failed.
//
// So this file counts, per run: how many distinct causes the model says occurred,
// and how many distinct signals a caller could actually observe. When the second
// number is smaller, the difference is the discrimination that was lost, and it is
// reported as a number instead of an opinion.

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// CauseSignal is what a caller can observe about a refusal without parsing prose.
type CauseSignal struct {
	Exit int
	Gate string
}

// Discrimination is the measure.
type Discrimination struct {
	Causes  map[string][]CauseSignal // predicted cause -> signals observed for it
	Signals map[CauseSignal][]string // signal -> causes that produced it
	Where   map[string]string        // cause -> a scenario that produced it, so a collapse is locatable
}

// Discrimination computes it over the pull steps of a run.
func (rep Report) Discrimination() Discrimination {
	d := Discrimination{
		Causes:  map[string][]CauseSignal{},
		Signals: map[CauseSignal][]string{},
		Where:   map[string]string{},
	}
	seen := map[string]map[CauseSignal]bool{}
	for _, r := range rep.Results {
		for _, s := range r.Steps {
			if s.Step.Action.Kind != ActPull || s.Outcome != Refuse {
				continue
			}
			// The cause according to the model, which is what the specification
			// says happened. The signal is what the process actually emitted.
			cause := s.Step.Expect.Gate
			if cause == "" {
				cause = "refusal without a modelled gate"
			}
			sig := CauseSignal{Exit: s.ExitCode, Gate: s.Gate}
			if _, ok := d.Where[cause]; !ok {
				d.Where[cause] = r.Scenario.ID
			}
			if seen[cause] == nil {
				seen[cause] = map[CauseSignal]bool{}
			}
			if !seen[cause][sig] {
				seen[cause][sig] = true
				d.Causes[cause] = append(d.Causes[cause], sig)
			}
			found := false
			for _, c := range d.Signals[sig] {
				if c == cause {
					found = true
					break
				}
			}
			if !found {
				d.Signals[sig] = append(d.Signals[sig], cause)
			}
		}
	}
	return d
}

// Collapsed lists the signals that stand for more than one cause. Each one is a
// place where a caller cannot tell two different situations apart.
func (d Discrimination) Collapsed() []CauseSignal {
	var out []CauseSignal
	for sig, causes := range d.Signals {
		if len(causes) > 1 {
			out = append(out, sig)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Exit != out[j].Exit {
			return out[i].Exit < out[j].Exit
		}
		return out[i].Gate < out[j].Gate
	})
	return out
}

// WriteUnlabelled shows what an unlabelled refusal actually said.
//
// It exists because of a mistake this project made and then repeated in a filed
// finding. FR-0121 recorded that "gate 3 fires but carries no label". When the
// missing gate-3 mutant was finally built, on an IEEE reviewer's insistence,
// disabling gate 3 changed nothing: the corpus stayed green. So the refusal was
// never gate 3. Something else refuses, and nobody had looked, because the report
// showed the ABSENCE of a label and not the message that was there instead.
//
// Looking, on 2026-09-06, ended it: there was no refusal. The step was ACCEPTED,
// exit 0, printed three sections below the waiver that described it as a refusal.
// The adversary move edited a detached signature file the pull path never reads.
// This function is kept because the same shape can recur at any gate: whenever a
// label is missing, print what was actually said before explaining the absence.
//
// A refusal a reader cannot attribute is not a detail. It is the case where the
// tool and the specification have drifted apart without anybody noticing.
func (rep Report) WriteUnlabelled(w io.Writer) {
	type sample struct{ scenario, text string }
	var samples []sample
	seen := map[string]bool{}
	for _, r := range rep.Results {
		for _, s := range r.Steps {
			if s.Step.Action.Kind != ActPull || s.Outcome != Refuse || s.Gate != "" {
				continue
			}
			line := firstMeaningfulLine(s.Stdout + "\n" + s.Stderr)
			if line == "" || seen[line] {
				continue
			}
			seen[line] = true
			samples = append(samples, sample{r.Scenario.ID, line})
		}
	}
	if len(samples) == 0 {
		return
	}
	fmt.Fprintf(w, "\nrefusals that named no gate (%d distinct message(s))\n", len(samples))
	for _, s := range samples {
		fmt.Fprintf(w, "  %s\n    %s\n", s.scenario, s.text)
	}
	fmt.Fprintf(w, "  These are refusals, and correct ones. What is missing is the attribution:\n")
	fmt.Fprintf(w, "  a caller cannot tell WHICH control refused, and neither could this report\n")
	fmt.Fprintf(w, "  until it started printing the message instead of noting its absence.\n")
}

// firstMeaningfulLine picks the line that carries the refusal, not the line that
// happens to come first.
//
// The first attempt returned the command echo, which is the shape of mistake this
// whole file is about: it reported something true and useless while the answer sat
// three lines lower. It now looks for the vocabulary a refusal uses and falls back
// to the last non-empty line, which is where a CLI usually puts its verdict.
func firstMeaningfulLine(s string) string {
	markers := []string{"refus", "skip", "not trusted", "invalid", "fail", "error",
		"cannot", "no ", "reject", "gate"}
	var lines []string
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "==>") || strings.HasPrefix(ln, "...") {
			continue
		}
		lines = append(lines, ln)
	}
	pick := func(ln string) string {
		if len(ln) > 150 {
			return ln[:150] + " ..."
		}
		return ln
	}
	for _, ln := range lines {
		low := strings.ToLower(ln)
		for _, m := range markers {
			if strings.Contains(low, m) {
				return pick(ln)
			}
		}
	}
	if len(lines) > 0 {
		return pick(lines[len(lines)-1])
	}
	return ""
}

// WriteDiscrimination prints the measure.
func (rep Report) WriteDiscrimination(w io.Writer) {
	d := rep.Discrimination()
	if len(d.Causes) == 0 {
		return
	}
	fmt.Fprintf(w, "\ncause discrimination: can a CALLER tell why a pull was refused?\n")
	fmt.Fprintf(w, "  %d distinct cause(s) produced %d distinct observable signal(s)\n",
		len(d.Causes), len(d.Signals))

	collapsed := d.Collapsed()
	if len(collapsed) == 0 {
		fmt.Fprintf(w, "  Every cause has its own signal.\n")
		return
	}
	for _, sig := range collapsed {
		gate := sig.Gate
		if gate == "" {
			gate = "no gate label"
		}
		causes := append([]string(nil), d.Signals[sig]...)
		sort.Strings(causes)
		fmt.Fprintf(w, "  exit %d / %-14s stands for %d different causes:\n", sig.Exit, gate, len(causes))
		for _, c := range causes {
			fmt.Fprintf(w, "      %-34s first seen in %s\n", c, d.Where[c])
		}
	}
	fmt.Fprintf(w, "  A caller, an audit record and any automated policy see the SIGNAL, not the\n")
	fmt.Fprintf(w, "  cause. Where one signal stands for several causes, they cannot tell them\n")
	fmt.Fprintf(w, "  apart. Since FR-0122 was implemented on 2026-09-06 the pull path reports a\n")
	fmt.Fprintf(w, "  typed code per gate (12, 10, 11, 13, 20), so an overload left here is no\n")
	fmt.Fprintf(w, "  longer a missing code. Read the remaining ones as questions about the\n")
	fmt.Fprintf(w, "  THREAT MODEL: a suppressed revoke makes a bundle ungoverned, and gate 4 is\n")
	fmt.Fprintf(w, "  then the honest answer, because nothing in a plain git registry can tell a\n")
	fmt.Fprintf(w, "  deleted event from one that was never written.\n")
	fmt.Fprintf(w, "  This is a measurement of the OUTPUT CONTRACT. It says nothing about whether\n")
	fmt.Fprintf(w, "  a human understands the message, which is not measured anywhere here.\n")
}
