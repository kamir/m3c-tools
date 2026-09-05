package sim

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// The defect these tests pin: a run in which NOTHING executed reported
// "conflicts: none" and exited 0. The binary path was passed relative, every
// exec failed inside the per-scenario world, all 100 scenarios were abandoned
// before their first step, and the summary read like a pass. A benchmark that
// cannot fail is not an instrument, so the absence of evidence must never be
// reported as evidence of absence.

// A scenario that never started has to be named, not dropped.
func TestScenarioErrorIsAHarnessFailure(t *testing.T) {
	rep := Report{Results: []ScenarioResult{
		{Scenario: Scenario{ID: "S-x"}, Err: "world: registry init: fork/exec ./build/skillctl: no such file or directory"},
	}}
	hf := rep.HarnessFailures()
	if len(hf) != 1 {
		t.Fatalf("a scenario that never started must be reported, got %d entries: %v", len(hf), hf)
	}
	if !strings.Contains(hf[0], "S-x") || !strings.Contains(hf[0], "never started") {
		t.Errorf("the entry must name the scenario and say it never ran, got %q", hf[0])
	}
	// And it must not read as a clean run.
	if _, conflicts, _, _ := rep.Summary(); conflicts != 0 {
		t.Fatalf("precondition: this fixture has no conflicts, got %d", conflicts)
	}
}

// A step whose ACTION errored produced no observation either.
func TestSkippedStepIsAHarnessFailure(t *testing.T) {
	rep := Report{Results: []ScenarioResult{{
		Scenario: Scenario{ID: "S-y"},
		Steps: []StepResult{{
			Step:   Step{Action: Action{Kind: ActStripRevoke}},
			Stderr: "commit: exit status 1: nothing to commit\nbranch is up to date",
		}},
		Verdicts: []Verdict{VerdictSkipped},
	}}}
	hf := rep.HarnessFailures()
	if len(hf) != 1 {
		t.Fatalf("a skipped step must be reported, got %v", hf)
	}
	if !strings.Contains(hf[0], "nothing was measured") {
		t.Errorf("the entry must say no measurement happened, got %q", hf[0])
	}
	// Only the first line of a git error: the rest is branch status.
	if strings.Contains(hf[0], "branch is up to date") {
		t.Errorf("the entry should keep only the cause line, got %q", hf[0])
	}
}

// The section has to appear BEFORE the numbers it invalidates.
func TestWriteLeadsWithHarnessFailures(t *testing.T) {
	rep := Report{Results: []ScenarioResult{{Scenario: Scenario{ID: "S-z"}, Err: "boom"}}}
	var b bytes.Buffer
	rep.Write(&b)
	out := b.String()
	iHarness := strings.Index(out, "HARNESS FAILURES")
	iCoverage := strings.Index(out, "coverage: which gate actually refused")
	if iHarness < 0 {
		t.Fatalf("the report must announce harness failures, got:\n%s", out)
	}
	if iCoverage >= 0 && iHarness > iCoverage {
		t.Error("harness failures must be printed before the coverage numbers they invalidate")
	}
	if !strings.Contains(rep.Markdown(), "Harness failures") {
		t.Error("the Markdown report must carry the same warning")
	}
}

// A clean report must stay silent, otherwise the warning becomes noise.
func TestNoHarnessFailuresOnACleanRun(t *testing.T) {
	rep := Report{Results: []ScenarioResult{{
		Scenario: Scenario{ID: "S-ok"},
		Steps:    []StepResult{{Step: Step{Action: Action{Kind: ActPull}}, Outcome: Accept}},
		Verdicts: []Verdict{VerdictMatch},
	}}}
	if hf := rep.HarnessFailures(); len(hf) != 0 {
		t.Errorf("a clean run must report no harness failure, got %v", hf)
	}
	var b bytes.Buffer
	rep.Write(&b)
	if strings.Contains(b.String(), "HARNESS FAILURES") {
		t.Error("a clean run must not print the harness warning")
	}
}

// End to end: point Execute at a binary that does not exist. This is exactly the
// shape of the original defect, and it must surface as a harness failure rather
// than as a quiet zero.
func TestExecuteWithAMissingBinaryIsAHarnessFailure(t *testing.T) {
	corpus := Generate(1)
	if len(corpus) == 0 {
		t.Skip("empty corpus")
	}
	root, err := os.MkdirTemp("", "sim-harness-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)

	res := Execute(root+"/does-not-exist-skillctl", root, corpus[0])
	rep := Report{Results: []ScenarioResult{res}}
	if len(rep.HarnessFailures()) == 0 {
		t.Fatal("a missing binary must be reported as a harness failure, not as a clean run")
	}
	// The trap: no conflicts and no violations, which is what used to make this
	// exit 0.
	_, conflicts, _, _ := rep.Summary()
	if conflicts == 0 && len(rep.Violations()) == 0 && len(rep.HarnessFailures()) == 0 {
		t.Fatal("this run would be scored as a success")
	}
}

// An errored step must not leave a phantom "exit 0" in the coverage table: the
// zero value of ExitCode used to be counted as an observed successful exit.
func TestHarnessErrorDoesNotForgeAnExitCode(t *testing.T) {
	rep := Report{Results: []ScenarioResult{{
		Scenario: Scenario{ID: "S-e"},
		Steps:    []StepResult{{Step: Step{Action: Action{Kind: ActStripRevoke}}, ExitCode: -1, Stderr: "boom"}},
		Verdicts: []Verdict{VerdictSkipped},
	}}}
	_, exits := rep.Coverage()
	if n, ok := exits[0]; ok {
		t.Errorf("a step that never ran must not count as exit 0, got %d", n)
	}
}
