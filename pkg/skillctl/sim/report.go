package sim

// report.go turns a run into something a human can act on. It leads with what was
// NOT covered, because that is the number a benchmark tries hardest to hide.

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// Report is the aggregate of one corpus run.
type Report struct {
	Results  []ScenarioResult
	BinaryID string         // sha256 prefix of the binary under test (EV-1)
	Design   *CoverageStats // set when the corpus came from a covering array

	// Provenance. ISO/IEC/IEEE 29119-3 wants a test report to identify the items
	// under test with their versions, the environment and the configuration. The
	// terminal output carried three hashes; the Markdown export, which is the
	// artifact a release would keep, carried none of it. An external reviewer read
	// a branch on which the documented commands did not exist. The fix is not more
	// hashes, it is naming the commit.
	Commit     string // the HARNESS source tree, not the binary under test
	SUTVersion string // what the binary under test reports about itself
	BinaryPath string
	Platform   string
	StartedAt  string
	Config     string
}

// Summary counts the verdicts.
func (rep Report) Summary() (match, conflict, unclaimed, skipped int) {
	for _, r := range rep.Results {
		for _, v := range r.Verdicts {
			switch v {
			case VerdictMatch:
				match++
			case VerdictConflict:
				conflict++
			case VerdictUnclaimed:
				unclaimed++
			case VerdictSkipped:
				skipped++
			}
		}
	}
	return
}

// Coverage reports which decision points the corpus actually reached: the gates
// that refused, and the exit codes observed. A gate that never appears is a hole
// in the corpus, not a property of the system.
// Coverage counts gates over CLAIMED PULL steps and exits over every step that
// actually ran a process.
//
// The gate half used to count every step, while the outcome table beside it
// counted pulls, so the same named quantity appeared twice with different values
// (gate 4 as 36 here and 30 there). A validation reviewer called that unusable on
// 2026-09-05 and was right: a document that gives one measurement two values is
// not evidence at that point, whichever value is correct.
//
// The two halves still have different populations, because they answer different
// questions, and the report now says so where each is printed.
func (rep Report) Coverage() (gates map[string]int, exits map[int]int) {
	gates = map[string]int{}
	exits = map[int]int{}
	for _, r := range rep.Results {
		for _, s := range r.Steps {
			if s.Gate != "" && s.Step.Action.Kind == ActPull && s.Step.Expect.Claimed {
				gates[s.Gate]++
			}
			if s.ExitCode >= 0 {
				exits[s.ExitCode]++
			}
		}
	}
	return
}

// ExitsByAction attributes process exits to the verb that produced them, so no
// observed exit code is left without an owner. A trust tool with documented exit
// codes that reports an unattributed one in its own evidence has an open point,
// not a rounding error.
func (rep Report) ExitsByAction() map[int]map[string]int {
	out := map[int]map[string]int{}
	for _, r := range rep.Results {
		for _, s := range r.Steps {
			if s.ExitCode < 0 {
				continue
			}
			if out[s.ExitCode] == nil {
				out[s.ExitCode] = map[string]int{}
			}
			out[s.ExitCode][string(s.Step.Action.Kind)]++
		}
	}
	return out
}

// HarnessFailures collects the runs that produced no evidence: a scenario that
// never started, and a step whose action errored before the system under test
// could answer. It is listed FIRST and it fails the run, because the alternative
// is the worst outcome a benchmark can have. A harness that cannot execute
// reports zero conflicts, and zero conflicts reads as success.
//
// This is not hypothetical. With the binary path passed relative, every exec
// failed, all 100 scenarios were abandoned before their first step, and the run
// printed "conflicts: none" and exited 0. The residual said 121 on the same page.
func (rep Report) HarnessFailures() []string {
	var out []string
	for _, r := range rep.Results {
		if r.Err != "" {
			out = append(out, fmt.Sprintf("%s: the scenario never started: %s", r.Scenario.ID, r.Err))
		}
		for i, v := range r.Verdicts {
			if v != VerdictSkipped || i >= len(r.Steps) {
				continue
			}
			out = append(out, fmt.Sprintf("%s step %d %s: the action failed, so nothing was measured: %s",
				r.Scenario.ID, i, r.Steps[i].Step.Action.Kind,
				strings.TrimSpace(firstLine(r.Steps[i].Stderr))))
		}
	}
	return out
}

// firstLine keeps the harness list readable: the cause is on line one, and a git
// error carries a paragraph of branch status after it.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// Violations collects every invariant breach across the corpus. These outrank
// exit-code conflicts: a conflict is usually drift between docs and code, a
// violation is a hole in the trust model.
func (rep Report) Violations() []string {
	var out []string
	for _, r := range rep.Results {
		for _, v := range r.Violations {
			out = append(out, fmt.Sprintf("%s  step %d  %s: %s", r.Scenario.ID, v.Step, v.Invariant, v.Detail))
		}
	}
	sort.Strings(out)
	return out
}

// Conflicts lists the steps where theory and reality disagreed, with the SPEC
// clause the prediction came from, so the reader can decide which side is wrong.
func (rep Report) Conflicts() []string {
	var out []string
	for _, r := range rep.Results {
		for i, v := range r.Verdicts {
			if v != VerdictConflict {
				continue
			}
			s := r.Steps[i]
			out = append(out, fmt.Sprintf(
				"%s  step %d  %s\n     theory:   %s exit=%d gate=%q\n     observed: %s exit=%d gate=%q\n     rule:     %s",
				r.Scenario.ID, i, s.Step.Action,
				s.Step.Expect.Outcome, s.Step.Expect.Exit, s.Step.Expect.Gate,
				s.Outcome, s.ExitCode, s.Gate, s.Step.Expect.Why))
		}
	}
	sort.Strings(out)
	return out
}

// Limits lists the scenarios that exercised an attack the model does NOT claim to
// stop, together with what actually happened. Printing this is not a weakness, it
// is the difference between evidence and a brochure.
func (rep Report) Limits() []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range rep.Results {
		for i, v := range r.Verdicts {
			if v != VerdictUnclaimed {
				continue
			}
			s := r.Steps[i]
			key := string(r.Scenario.P.Adv) + "/" + string(s.Step.Action.Kind)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, fmt.Sprintf("%-18s %-12s observed: %s (exit %d)\n     %s",
				r.Scenario.P.Adv, s.Step.Action.Kind, s.Outcome, s.ExitCode, s.Step.Expect.Why))
		}
	}
	sort.Strings(out)
	return out
}

// Write renders the whole report.
func (rep Report) Write(w io.Writer) {
	match, conflict, unclaimed, skipped := rep.Summary()
	gates, exits := rep.Coverage()

	fmt.Fprintf(w, "\nskillctl trust-plane simulation\n")
	// EV-1: the pre-registration line. Two reports with the same model and corpus
	// hash made the same prediction; a changed hash means the theory moved, and
	// that has to be visible before anyone compares the numbers.
	var corpus []Scenario
	for _, r := range rep.Results {
		corpus = append(corpus, r.Scenario)
	}
	fmt.Fprintf(w, "  model %s  corpus %s  binary %s\n", ModelHash(), CorpusHash(corpus), rep.BinaryID)
	fmt.Fprintf(w, "  scenarios : %d\n", len(rep.Results))
	fmt.Fprintf(w, "  steps     : %d matched, %d conflicts, %d out-of-model, %d skipped\n",
		match, conflict, unclaimed, skipped)

	// Listed before any coverage or experiment number, because those numbers are
	// only meaningful if the corpus actually ran. A reader who sees this section
	// should stop reading the rest.
	if hf := rep.HarnessFailures(); len(hf) > 0 {
		fmt.Fprintf(w, "\nHARNESS FAILURES (%d): these steps produced NO evidence\n", len(hf))
		fmt.Fprintf(w, "  Every number below is computed over a corpus that did not fully run.\n")
		for _, f := range hf {
			fmt.Fprintf(w, "  %s\n", f)
		}
	}

	fmt.Fprintf(w, "\ncoverage: which gate actually refused (claimed pull steps)\n")
	if len(gates) == 0 {
		fmt.Fprintf(w, "  (none: the corpus never reached a refusal, which is itself a finding)\n")
	}
	for _, g := range sortedKeys(gates) {
		fmt.Fprintf(w, "  %-8s %d time(s)\n", g, gates[g])
	}
	fmt.Fprintf(w, "\ncoverage: observed process exits, by the verb that produced them\n")
	steps := 0
	noProc := 0
	for _, r := range rep.Results {
		for _, st := range r.Steps {
			steps++
			if st.ExitCode < 0 {
				noProc++
			}
		}
	}
	ran := 0
	for _, n := range exits {
		ran += n
	}
	fmt.Fprintf(w, "  Population: every step that ran a process.\n")
	fmt.Fprintf(w, "  Bridge to the step count: %d steps = %d that ran a process + %d world\n", steps, ran, noProc)
	fmt.Fprintf(w, "  mutations that ran none. Without this line a reader has to rebuild the\n")
	fmt.Fprintf(w, "  arithmetic from the source, which is not a reader's job.\n")
	var codes []int
	for c := range exits {
		codes = append(codes, c)
	}
	sort.Ints(codes)
	for _, c := range codes {
		byAct := rep.ExitsByAction()[c]
		var verbs []string
		for _, v := range sortedKeys(byAct) {
			verbs = append(verbs, fmt.Sprintf("%s x%d", v, byAct[v]))
		}
		fmt.Fprintf(w, "  exit %-3d %3d time(s)   %s\n", c, exits[c], strings.Join(verbs, ", "))
	}

	rep.WriteProvenance(w)
	rep.WriteStanding(w)
	rep.WriteTraceability(w)
	rep.WriteOutputCoverage(w)
	rep.WriteWaivers(w)
	rep.WriteUnlabelled(w)
	rep.WriteDiscrimination(w)
	rep.WriteOpenDiagnostics(w)
	rep.WriteExperiment(w)
	rep.WriteMixture(w)

	if vs := rep.Violations(); len(vs) > 0 {
		fmt.Fprintf(w, "\nINVARIANT VIOLATIONS (%d), the findings that matter\n", len(vs))
		for _, v := range vs {
			fmt.Fprintf(w, "  %s\n", v)
		}
	} else {
		fmt.Fprintf(w, "\ninvariants: no violation across the corpus\n")
	}

	if cs := rep.Conflicts(); len(cs) > 0 {
		fmt.Fprintf(w, "\nCONFLICTS theory vs reality (%d). One of the two is wrong; a human decides.\n", len(cs))
		for _, c := range cs {
			fmt.Fprintf(w, "  %s\n", c)
		}
	} else {
		fmt.Fprintf(w, "\nconflicts: none, the specification predicted every claimed outcome\n")
	}

	if ls := rep.Limits(); len(ls) > 0 {
		fmt.Fprintf(w, "\nOUT OF MODEL (%d distinct): attacks this design does NOT claim to stop\n", len(ls))
		for _, l := range ls {
			fmt.Fprintf(w, "  %s\n", l)
		}
	}
	fmt.Fprintln(w)
}

func sortedKeys(m map[string]int) []string {
	var k []string
	for s := range m {
		k = append(k, s)
	}
	sort.Strings(k)
	return k
}

// Markdown renders the same report as a document that can be attached to a
// release, so the benchmark's output is an artifact and not a terminal scroll.
func (rep Report) Markdown() string {
	var b strings.Builder
	match, conflict, unclaimed, skipped := rep.Summary()
	gates, _ := rep.Coverage()
	fmt.Fprintf(&b, "# skillctl trust-plane verification run\n\n")

	// The heading says verification, not validation, and that is the first thing a
	// reader should see. IEEE 1012 separates conformance to specified requirements
	// from fitness for the intended use; this document produces the first kind of
	// evidence only. It used to be titled "simulation" and read as if it produced
	// both.
	fmt.Fprintf(&b, "> **Scope: verification, not validation.** This run compares the shipped\n")
	fmt.Fprintf(&b, "> binary against a model derived from SPEC-0188 and SPEC-0359, and calibrates\n")
	fmt.Fprintf(&b, "> its own ability to see a defect. It says nothing about fitness for the\n")
	fmt.Fprintf(&b, "> intended use, the operational environment (github://, gitlab://, ER1,\n")
	fmt.Fprintf(&b, "> Windows), human understanding of the output, or field failure rates.\n")
	fmt.Fprintf(&b, "> Integrity level: the component warrants **high**; this V&V supports **medium**\n")
	fmt.Fprintf(&b, "> at most. Independence: **none**, one author read the specification, built the\n")
	fmt.Fprintf(&b, "> model, wrote the oracle and produced this report. Gate 3 of five is\n")
	fmt.Fprintf(&b, "> **unverified and uncalibrated**.\n\n")

	fmt.Fprintf(&b, "## Provenance\n\n| | |\n|---|---|\n")
	for _, kv := range rep.Provenance() {
		fmt.Fprintf(&b, "| %s | `%s` |\n", kv[0], kv[1])
	}
	fmt.Fprintf(&b, "\n## Result\n\n")
	fmt.Fprintf(&b, "| | |\n|---|---|\n")
	fmt.Fprintf(&b, "| scenarios | %d |\n", len(rep.Results))
	fmt.Fprintf(&b, "| steps matched | %d |\n", match)
	fmt.Fprintf(&b, "| conflicts | %d |\n", conflict)
	fmt.Fprintf(&b, "| out of model | %d |\n", unclaimed)
	fmt.Fprintf(&b, "| skipped | %d |\n", skipped)
	fmt.Fprintf(&b, "| invariant violations | %d |\n\n", len(rep.Violations()))
	if hf := rep.HarnessFailures(); len(hf) > 0 {
		fmt.Fprintf(&b, "## Harness failures (%d): no evidence was produced\n\n", len(hf))
		fmt.Fprintf(&b, "Every number in this document is computed over a corpus that did not fully run.\n\n")
		for _, f := range hf {
			fmt.Fprintf(&b, "- %s\n", f)
		}
		fmt.Fprintf(&b, "\n")
	}
	// Traceability. The table an IEEE 1012 reviewer asks for first: every claim
	// with its origin and whether this run exercised it.
	fmt.Fprintf(&b, "## Traceability\n\n")
	// The legend defines every mark the table can carry, and only those. It once
	// defined a mark that never appeared and omitted one that appeared twice, which
	// a reviewer found before any reader did.
	fmt.Fprintf(&b, "`normativ` = written in a specification · `abgeleitet` = derived, and the\n")
	fmt.Fprintf(&b, "derivation is part of the evidence · `uebernommen` = binds here, accepted from\n")
	fmt.Fprintf(&b, "a review, with no specification clause behind it · `beobachtet` = read off the\n")
	fmt.Fprintf(&b, "running system, so a failure means CHANGED and not WRONG · `ungeklaert` =\n")
	fmt.Fprintf(&b, "checked, meaning still open.\n\n")
	fmt.Fprintf(&b, "| claim | provenance | observed | source | note |\n|---|---|---|---|---|\n")
	gv := map[string]int{}
	for _, v := range rep.Violations() {
		for _, item := range TraceMatrix() {
			if strings.Contains(v, item.ID) {
				gv[item.ID]++
				break
			}
		}
	}
	for _, it := range TraceMatrix() {
		obs := "n/a"
		if n, ok := gates[it.ID]; ok {
			obs = fmt.Sprintf("%d", n)
		} else if strings.HasPrefix(it.ID, "gate ") {
			obs = "0"
		} else if strings.HasPrefix(it.ID, "INV-") {
			obs = fmt.Sprintf("%d viol", gv[it.ID])
		}
		note := it.Note
		if note == "" {
			note = "n/a"
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s |\n", it.ID, it.Prov, obs, it.Source, note)
	}

	// Outcome coverage against a target declared before the run. Input coverage
	// cannot substitute for it: a corpus can cover every pair of factor levels and
	// still never reach a gate, which is exactly what happened once.
	oc := rep.OutputCoverage()
	fmt.Fprintf(&b, "\n## Coverage of outcomes\n\n")
	fmt.Fprintf(&b, "Target, declared before the run: every specified decision observed at least %d time(s).\n\n", oc.Target)
	fmt.Fprintf(&b, "| decision | observed | |\n|---|---|---|\n")
	for _, d := range oc.Declared {
		mark := "n/a"
		if oc.Seen[d] < oc.Target {
			mark = "**below target**"
		}
		fmt.Fprintf(&b, "| `%s` | %d | %s |\n", d, oc.Seen[d], mark)
	}

	// Theory against measurement, with the residual per bin.
	var corpus []Scenario
	for _, r := range rep.Results {
		corpus = append(corpus, r.Scenario)
	}
	pred, obs := PredictHistogram(corpus), rep.MeasureHistogram()
	fmt.Fprintf(&b, "\n## Prediction versus measurement\n\n")
	fmt.Fprintf(&b, "| bin | predicted | observed | residual |\n|---|---|---|---|\n")
	for _, bin := range Bins(pred, obs) {
		fmt.Fprintf(&b, "| `%s` | %d | %d | %+d |\n", bin, pred[bin], obs[bin], obs[bin]-pred[bin])
	}
	fmt.Fprintf(&b, "| **total** | | | **%d** |\n\n", rep.Residual())
	fmt.Fprintf(&b, "A residual of zero means the closed form reproduced the measured\n")
	fmt.Fprintf(&b, "DISTRIBUTION. The per-step comparison above is what decides behavioural\n")
	fmt.Fprintf(&b, "conformance; equal histograms are not equal behaviour.\n\n")

	fmt.Fprintf(&b, "## Gates reached\n\n")
	for _, g := range sortedKeys(gates) {
		fmt.Fprintf(&b, "- `%s`: %d\n", g, gates[g])
	}
	if vs := rep.Violations(); len(vs) > 0 {
		fmt.Fprintf(&b, "\n## Invariant violations\n\n")
		for _, v := range vs {
			fmt.Fprintf(&b, "- %s\n", v)
		}
	}
	if ls := rep.Limits(); len(ls) > 0 {
		fmt.Fprintf(&b, "\n## Out of model, stated on purpose\n\n")
		for _, l := range ls {
			fmt.Fprintf(&b, "- %s\n", strings.ReplaceAll(l, "\n", " "))
		}
	}
	return b.String()
}

// --- how to judge the MIXTURE, not just the count -------------------------
//
// "100 scenarios" is a number that can be inflated at will. These three views
// make the composition of a corpus arguable instead of impressive:
//
//  1. MARGINALS: how the runs distribute over each axis. A corpus that is 80
//     percent one cast is not broad, whatever its total.
//  2. YIELD: how many DISTINCT decision paths those runs produced. Two scenarios
//     that refuse at the same gate for the same reason taught one thing, not two.
//     Yield is the honest denominator: distinct paths per scenario.
//  3. HOLES: which declared decision points the corpus never reached. This is the
//     number a benchmark hides, so the report prints it first among the three.

// declaredGates is the set of refusals the pull gauntlet can produce. Listing it
// by hand, from the specification, is deliberate: a list derived from what the
// corpus happened to hit could never reveal a hole.
var declaredGates = []string{
	"gate 1", // envelope signature
	"gate 2", // digest mismatch
	"gate 3", // bundle signatures
	"gate 4", // governance floor
	"gate 5", // revoked
}

// Mixture describes the composition of a corpus run.
type Mixture struct {
	Marginals  map[string]map[string]int // axis -> value -> scenarios
	Paths      map[string]int            // decision signature -> scenarios sharing it
	Scenarios  int
	MissedGate []string
}

// Compose computes the mixture view.
func (rep Report) Compose() Mixture {
	m := Mixture{
		Marginals: map[string]map[string]int{},
		Paths:     map[string]int{},
		Scenarios: len(rep.Results),
	}
	add := func(axis, val string) {
		if m.Marginals[axis] == nil {
			m.Marginals[axis] = map[string]int{}
		}
		m.Marginals[axis][val]++
	}
	seenGate := map[string]bool{}
	for _, r := range rep.Results {
		p := r.Scenario.P
		add("cast", string(p.Cast))
		add("reviewer key", string(p.Key))
		add("governance", string(p.Gov))
		add("adversary", string(p.Adv))
		add("revoke", fmt.Sprintf("%t", p.Revoke))

		// The decision signature is what the run actually DECIDED: for each step,
		// the action, the outcome, and the gate that spoke. Two scenarios with the
		// same signature exercised the same path through the system.
		var sig []string
		for _, s := range r.Steps {
			sig = append(sig, fmt.Sprintf("%s:%s:%s", s.Step.Action.Kind, s.Outcome, s.Gate))
			if s.Gate != "" {
				seenGate[s.Gate] = true
			}
		}
		m.Paths[strings.Join(sig, "|")]++
	}
	for _, g := range declaredGates {
		if !seenGate[g] {
			m.MissedGate = append(m.MissedGate, g)
		}
	}
	return m
}

// WriteMixture renders the composition view.
func (rep Report) WriteMixture(w io.Writer) {
	m := rep.Compose()
	fmt.Fprintf(w, "\nmixture: is this corpus broad, or just long?\n")
	if rep.Design != nil {
		d := rep.Design
		fmt.Fprintf(w, "\n  design: covering array of strength t=%d over %s\n", d.Strength, DesignAxes())
		fmt.Fprintf(w, "  %d rows instead of %d exhaustive: EVERY admissible %d-way combination appears\n",
			d.Rows, d.FullEnumeration, d.Strength)
		fmt.Fprintf(w, "  %d combinations covered; %d of the %d in the unconstrained space are not\n",
			d.Admissible, d.Uncoverable, d.Total)
		fmt.Fprintf(w, "  covered, and they are NOT all the same kind. Point census over the factor\n")
		c := Census()
		fmt.Fprintf(w, "  space: %d admissible, %d impossible (the world cannot produce them),\n",
			c.Admissible, c.Impossible)
		fmt.Fprintf(w, "  %d left out for economy (the world CAN produce them; the corpus judges\n", c.Economy)
		fmt.Fprintf(w, "  them redundant, and that judgement can be wrong).\n")
		for _, r := range sortedKeys(c.ByRule) {
			fmt.Fprintf(w, "    %-52s %d\n", r, c.ByRule[r])
		}
		fmt.Fprintf(w, "  An earlier version of this line called all of them \"not coverable, not\n")
		fmt.Fprintf(w, "  missing\". For the economy share that was false, and reporting a judgement\n")
		fmt.Fprintf(w, "  as an impossibility is the more expensive of the two mistakes.\n")
	}

	fmt.Fprintf(w, "\n  distinct decision paths: %d over %d scenarios (yield %.2f)\n",
		len(m.Paths), m.Scenarios, float64(len(m.Paths))/float64(max(m.Scenarios, 1)))
	fmt.Fprintf(w, "  A yield near 1.0 means almost every scenario taught something new.\n")
	fmt.Fprintf(w, "  A yield near 0.1 means the corpus is padding: ten runs per lesson.\n")

	// The most-repeated path is the one worth questioning: it is where the corpus
	// spends its runtime without learning.
	top, topN := "", 0
	for sig, n := range m.Paths {
		if n > topN {
			top, topN = sig, n
		}
	}
	if topN > 1 {
		short := top
		if len(short) > 100 {
			short = short[:100] + "..."
		}
		fmt.Fprintf(w, "  most repeated path (%d scenarios): %s\n", topN, short)
	}

	if len(m.MissedGate) > 0 {
		fmt.Fprintf(w, "\n  HOLES: declared gates never seen BY NAME in this corpus: %s\n", strings.Join(m.MissedGate, ", "))
		fmt.Fprintf(w, "  Gate 3 is on this list, and it is not merely a naming question. Its mutant\n")
		fmt.Fprintf(w, "  is indistinguishable from the unmutated baseline, so no scenario here\n")
		fmt.Fprintf(w, "  depends on it.\n")
		fmt.Fprintf(w, "  This paragraph has now been wrong in three directions: the gate fires\n")
		fmt.Fprintf(w, "  unnamed, then the case is not constructible, then the control is live. All\n")
		fmt.Fprintf(w, "  three were artefacts of how the case was scored. What holds is the\n")
		fmt.Fprintf(w, "  measurement: unverified, and its mutant undetectable (FR-0121).\n")
		fmt.Fprintf(w, "  A gate on this list is a decision the simulation says nothing about.\n")
	} else {
		fmt.Fprintf(w, "\n  every declared gate was reached at least once\n")
	}

	fmt.Fprintf(w, "\n  distribution per axis\n")
	for _, axis := range []string{"cast", "reviewer key", "governance", "adversary", "revoke"} {
		vals := m.Marginals[axis]
		if vals == nil {
			continue
		}
		fmt.Fprintf(w, "    %-13s", axis)
		for _, k := range sortedKeys(vals) {
			fmt.Fprintf(w, " %s=%d", k, vals[k])
		}
		fmt.Fprintln(w)
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// WriteOpenDiagnostics names every adversary move whose security behaviour is
// scored but whose error LABEL is under an open finding. It prints on every run,
// green ones included, because an exemption that stops being mentioned is
// indistinguishable from a check that was never written.
func (rep Report) WriteOpenDiagnostics(w io.Writer) {
	q := OpenDiagnostics()
	if len(q) == 0 {
		return
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, string(k))
	}
	sort.Strings(keys)
	fmt.Fprintf(w, "\nopen diagnostic findings (%d): the DECISION is scored, the LABEL is not\n", len(q))
	for _, k := range keys {
		fmt.Fprintf(w, "  %-22s %s\n", k, q[AdvKind(k)])
	}
	fmt.Fprintf(w, "  These moves stay in the blocking corpus. Refusal, exit code and the\n")
	fmt.Fprintf(w, "  untouched install target are all still asserted; only the gate name is\n")
	fmt.Fprintf(w, "  left uncompared until somebody rules on the finding.\n")
}

// Residual is the total disagreement between the closed form and the measurement,
// summed over the bins. Zero means the analytical model describes the running
// binary exactly on this corpus.
//
// It is exported and checked separately from the conflict count because the two
// can come apart: a step-level conflict is a named scenario failing, while a
// residual is a shift in the DISTRIBUTION, and a defect that moves four pulls out
// of one bin and into another can in principle do so without any single step being
// judged a conflict. The operator set the pass condition as "residual zero" on
// 2026-09-05, so the exit code has to read this number and not a proxy for it.
func (rep Report) Residual() int {
	var corpus []Scenario
	for _, r := range rep.Results {
		corpus = append(corpus, r.Scenario)
	}
	pred := PredictHistogram(corpus)
	obs := rep.MeasureHistogram()
	total := 0
	for _, b := range Bins(pred, obs) {
		total += abs(obs[b] - pred[b])
	}
	return total
}

// WriteExperiment is the theory-versus-measurement comparison: the analytically
// predicted histogram of pull outcomes next to the measured one, with the residual
// per bin. A residual of zero everywhere means the closed form describes the
// running system. Any other number names a bin where either the code or the theory
// is wrong, and the size of the residual says how much of the corpus is affected.
func (rep Report) WriteExperiment(w io.Writer) {
	var corpus []Scenario
	for _, r := range rep.Results {
		corpus = append(corpus, r.Scenario)
	}
	pred := PredictHistogram(corpus)
	obs := rep.MeasureHistogram()

	fmt.Fprintf(w, "\nwhat each comparison is worth\n")
	fmt.Fprintf(w, "  Three different test goals live in this report and they rest on different\n")
	fmt.Fprintf(w, "  ground. Reading them as one number is how a characterisation test gets\n")
	fmt.Fprintf(w, "  mistaken for a specification proof.\n")
	fmt.Fprintf(w, "    may this bundle install?    SECURITY: independent requirement, binding\n")
	fmt.Fprintf(w, "    which gate is reported?     MIXED, since FR-0119 was decided on 2026-09-05.\n")
	fmt.Fprintf(w, "                                Gate 5 before gate 4, and gate 2 before gate 3,\n")
	fmt.Fprintf(w, "                                are now a binding DIAGNOSIS CONTRACT (D2): the\n")
	fmt.Fprintf(w, "                                revoke is the more actionable statement, and the\n")
	fmt.Fprintf(w, "                                cause comes before the consequence.\n")
	fmt.Fprintf(w, "                                The PHASE BOUNDARIES that put gate 1 first and the\n")
	fmt.Fprintf(w, "                                metadata gates before the byte gates are derived\n")
	fmt.Fprintf(w, "                                but not yet normative (D1 open), so they are still\n")
	fmt.Fprintf(w, "                                checked as CHARACTERISATION.\n")
	fmt.Fprintf(w, "    was anything written?       SIDE EFFECT: independent requirement, binding\n")
	fmt.Fprintf(w, "    were bytes fetched at all?  SIDE EFFECT: binding since FR-0119 D3. A pull must\n")
	fmt.Fprintf(w, "                                not fetch from an untrusted backend once it has\n")
	fmt.Fprintf(w, "                                decided against the bundle from signed metadata.\n")
	fmt.Fprintf(w, "                                Measured by withholding the artifact: INV-8.\n")
	fmt.Fprintf(w, "  For a side-effect-free conjunction the order changes the first error LABEL,\n")
	fmt.Fprintf(w, "  not the accept condition. Once a check processes data or writes, its order\n")
	fmt.Fprintf(w, "  becomes security-relevant too, and INV-6 is what watches for that.\n")

	fmt.Fprintf(w, "\nexperiment: analytical prediction vs measurement (pull outcomes)\n")
	fmt.Fprintf(w, "  %-26s %9s %9s %9s\n", "bin", "predicted", "observed", "residual")
	total := 0
	for _, b := range Bins(pred, obs) {
		r := obs[b] - pred[b]
		mark := ""
		if r != 0 {
			mark = "  <-- disagreement"
		}
		total += abs(r)
		fmt.Fprintf(w, "  %-26s %9d %9d %+9d%s\n", b, pred[b], obs[b], r, mark)
	}
	fmt.Fprintf(w, "  %-26s %9s %9s %9d\n", "sum |residual|", "", "", total)
	if total == 0 {
		fmt.Fprintf(w, "  The closed form describes the running system exactly on this corpus.\n")
	} else {
		fmt.Fprintf(w, "  Non-zero: the model and the binary disagree somewhere. The conflict list below\n")
		fmt.Fprintf(w, "  names the scenarios; a human decides which of the two is wrong.\n")
	}
}

func abs(i int) int {
	if i < 0 {
		return -i
	}
	return i
}
