package main

// Coach-loop tests. The primary tests use a STUBBED runner so they run offline
// and fast (no skillctl, no stdin). A second, guarded test exercises the REAL
// runner + hermetic sandbox for K1 and skips cleanly when skillctl isn't built.

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// stubRunner is a kataRunner that returns a fixed result without spawning a
// process. It records how many times it was invoked.
type stubRunner struct {
	result RunResult
	calls  int
}

func (s *stubRunner) Run(emit func(stream, line string), stdin string, args ...string) RunResult {
	s.calls++
	if emit != nil {
		emit("stdout", "stub output")
	}
	r := s.result
	r.Args = args
	return r
}

// testKata is a minimal Kata whose setup needs no sandbox and whose experiment
// observes the runner's process exit — so runRep can be driven with a stub.
func testKata(target, required int) *Kata {
	return &Kata{
		ID: "KT", Title: "test kata", Target: "t", TargetExit: target, RequiredReps: required,
		ExperimentCmd: "skillctl noop",
		setup: func(sb *Sandbox, run kataRunner, narrate func(Event), nonce string) (repPlan, error) {
			return repPlan{Args: []string{"noop"}, Cmd: "skillctl noop", Artifact: nonce}, nil
		},
		observe: func(res RunResult) int { return res.ExitCode },
	}
}

func newTestCoach(t *testing.T, run kataRunner) *Coach {
	t.Helper()
	store := NewKataStore(filepath.Join(t.TempDir(), "p.json"))
	return NewCoach(nil, run, NewBus(nil), store, nil, 5)
}

func TestRunRep_RecordsBeatOnMatch(t *testing.T) {
	run := &stubRunner{result: RunResult{ExitCode: 0}}
	c := newTestCoach(t, run)
	k := testKata(0, 2)
	predictTarget := func(k *Kata) int { return k.TargetExit }

	beat, added, err := c.runRep(k, "nonce-1", predictTarget)
	if err != nil {
		t.Fatalf("runRep: %v", err)
	}
	if !added {
		t.Fatal("first matching rep was not recorded as a new distinct beat")
	}
	if beat.Observed != 0 || !beat.OK() {
		t.Fatalf("beat = %+v; want observed 0 OK", beat)
	}
	if d := c.store.Distinct("KT"); d != 1 {
		t.Fatalf("distinct = %d; want 1", d)
	}
	if run.calls == 0 {
		t.Fatal("stub runner was never invoked")
	}
}

func TestRunRep_NoBeatOnMismatch(t *testing.T) {
	// The runner returns exit 1 but the Kata target is 0 → honesty: no beat.
	run := &stubRunner{result: RunResult{ExitCode: 1}}
	c := newTestCoach(t, run)
	k := testKata(0, 2)

	_, added, err := c.runRep(k, "nonce-x", func(k *Kata) int { return 0 })
	if err != nil {
		t.Fatalf("runRep: %v", err)
	}
	if added {
		t.Fatal("a non-matching run was recorded as a beat")
	}
	if d := c.store.Distinct("KT"); d != 0 {
		t.Fatalf("distinct after mismatch = %d; want 0", d)
	}
}

func TestRunRep_DedupAndProgressToSitzt(t *testing.T) {
	run := &stubRunner{result: RunResult{ExitCode: 0}}
	c := newTestCoach(t, run)
	k := testKata(0, 2)
	predict := func(k *Kata) int { return k.TargetExit }

	// Two runs with the SAME nonce → same signature → only one distinct rep.
	c.runRep(k, "same", predict)
	c.runRep(k, "same", predict)
	if d := c.store.Distinct("KT"); d != 1 {
		t.Fatalf("distinct after identical reps = %d; want 1", d)
	}
	if st, _ := c.store.State("KT", k.RequiredReps, c.stallDays, nowForTest()); st == StateGruen {
		t.Fatal("reached sitzt on a single distinct rep (spammed identical artifact)")
	}

	// A genuinely distinct rep reaches the 2/2 target → grün.
	c.runRep(k, "different", predict)
	if d := c.store.Distinct("KT"); d != 2 {
		t.Fatalf("distinct = %d; want 2", d)
	}
	if st, _ := c.store.State("KT", k.RequiredReps, c.stallDays, nowForTest()); st != StateGruen {
		t.Fatalf("state after 2 distinct reps = %s; want gruen", st)
	}
}

// TestRunRep_RealSkillctl_K1 exercises the real runner + hermetic sandbox for
// K1 (verify --bundle → exit 0). Skips when skillctl isn't built/available.
func TestRunRep_RealSkillctl_K1(t *testing.T) {
	skctl := findSkillctlForTest()
	if skctl == "" {
		t.Skip("skillctl binary not found; build ./build/skillctl or set M3C_KATA_SKILLCTL")
	}
	sb, err := NewSandbox()
	if err != nil {
		t.Fatalf("sandbox: %v", err)
	}
	defer sb.Cleanup()

	store := NewKataStore(filepath.Join(t.TempDir(), "p.json"))
	c := NewCoach(sb, &Runner{Skillctl: skctl, Home: sb.Home}, NewBus(nil), store, nil, 5)
	k := KataByID("K1")
	if k == nil {
		t.Fatal("K1 not found")
	}
	beat, added, err := c.runRep(k, "real-nonce", func(k *Kata) int { return k.TargetExit })
	if err != nil {
		t.Fatalf("runRep(K1): %v", err)
	}
	if beat.Observed != 0 {
		t.Fatalf("K1 real observed exit = %d; want 0", beat.Observed)
	}
	if !added || store.Distinct("K1") != 1 {
		t.Fatalf("K1 real beat not recorded (added=%v distinct=%d)", added, store.Distinct("K1"))
	}
}

// findSkillctlForTest locates a real skillctl for the guarded test: an explicit
// override, then the repo-root build output, then the standard resolution.
func findSkillctlForTest() string {
	if p := os.Getenv("M3C_KATA_SKILLCTL"); p != "" {
		if fileExists(p) {
			return p
		}
	}
	for _, cand := range []string{
		filepath.Join("..", "..", "build", "skillctl"),
		filepath.Join("..", "..", "build", "skillctl.exe"),
	} {
		if fileExists(cand) {
			if abs, err := filepath.Abs(cand); err == nil {
				return abs
			}
			return cand
		}
	}
	if p, err := resolveSkillctl(""); err == nil {
		return p
	}
	return ""
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func nowForTest() time.Time { return time.Now() }
