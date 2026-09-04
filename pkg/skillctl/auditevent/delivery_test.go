package auditevent

import (
	"errors"
	"testing"
)

// flakySink fails its first failFirst writes, then succeeds. It lets a test tell
// a retrying (durable) Dispatcher apart from a single-shot (best-effort) one.
type flakySink struct {
	name      string
	failFirst int
	writes    int
	landed    int
}

func (f *flakySink) Name() string { return f.name }
func (f *flakySink) Close() error { return nil }
func (f *flakySink) Write(*Event) error {
	f.writes++
	if f.writes <= f.failFirst {
		return errors.New("transient")
	}
	f.landed++
	return nil
}

// Durable mode rides out a bounded number of transient sink failures.
func TestDurableModeRetriesTransientFailure(t *testing.T) {
	fs := &flakySink{name: "flaky", failFirst: 2}
	d := NewDispatcherMode(ModeDurable, Redactor{}, fs).WithDurableRetries(3)
	if d.Mode() != ModeDurable {
		t.Fatalf("mode=%s, want durable", d.Mode())
	}
	e := New(EventPolicyAllow, OutcomeSuccess, SeverityInfo, "skillctl/x")
	if err := d.Dispatch(e); err != nil {
		t.Fatalf("durable dispatch should ride out %d transient failures: %v", fs.failFirst, err)
	}
	if fs.writes != 3 || fs.landed != 1 {
		t.Fatalf("want 3 attempts and 1 landed, got writes=%d landed=%d", fs.writes, fs.landed)
	}
}

// Best-effort mode attempts exactly once and surfaces the error advisory (this is
// the landed gate-hot-path behavior, REQ-6.4).
func TestBestEffortModeDoesNotRetry(t *testing.T) {
	fs := &flakySink{name: "flaky", failFirst: 1}
	d := NewDispatcher(Redactor{}, fs) // best-effort default
	if d.Mode() != ModeBestEffort {
		t.Fatalf("mode=%s, want best-effort", d.Mode())
	}
	e := New(EventPolicyAllow, OutcomeSuccess, SeverityInfo, "skillctl/x")
	if err := d.Dispatch(e); err == nil {
		t.Fatalf("best-effort must surface the sink error")
	}
	if fs.writes != 1 || fs.landed != 0 {
		t.Fatalf("best-effort must attempt exactly once, got writes=%d landed=%d", fs.writes, fs.landed)
	}
}

// FR-0110a must NOT fail-close anywhere: required is a valid, named mode that (for
// now) behaves like durable and only ever returns an ADVISORY error. Its hot-path
// enforcement is FR-0110b.
func TestRequiredModeIsNotFailClosedInFR0110a(t *testing.T) {
	if !ModeRequired.Valid() {
		t.Fatal("required must be a valid mode so FR-0110b can slot in")
	}
	// A permanently failing sink returns an advisory error, never a panic.
	fail := &failingSink{}
	d := NewDispatcherMode(ModeRequired, Redactor{}, fail)
	if d.Mode() != ModeRequired {
		t.Fatalf("mode=%s, want required", d.Mode())
	}
	if err := d.Dispatch(New(EventPolicyAllow, OutcomeSuccess, SeverityInfo, "skillctl/x")); err == nil {
		t.Fatal("a failing sink under required should surface an advisory error")
	}
	// A transient failure is ridden out (durable-equivalent): defaultDurableRetries
	// is 3, so a sink failing twice then succeeding lands.
	fs := &flakySink{name: "flaky", failFirst: 2}
	d2 := NewDispatcherMode(ModeRequired, Redactor{}, fs)
	if err := d2.Dispatch(New(EventPolicyAllow, OutcomeSuccess, SeverityInfo, "skillctl/x")); err != nil {
		t.Fatalf("required (durable-equivalent) should ride out transient failures: %v", err)
	}
	if fs.landed != 1 {
		t.Fatalf("event did not land under required, landed=%d", fs.landed)
	}
}

// An unknown or empty mode falls back to best-effort (fail-safe: never silently
// stricter than the landed default).
func TestUnknownModeFallsBackToBestEffort(t *testing.T) {
	rec := &recordingSink{name: "rec"}
	d := NewDispatcherMode(Mode("teleport"), Redactor{}, rec)
	if d.Mode() != ModeBestEffort {
		t.Fatalf("unknown mode must fall back to best-effort, got %s", d.Mode())
	}
	if err := d.Dispatch(New(EventPolicyAllow, OutcomeSuccess, SeverityInfo, "skillctl/x")); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if len(rec.lines) != 1 {
		t.Fatalf("event should still be delivered once, got %d", len(rec.lines))
	}
}
