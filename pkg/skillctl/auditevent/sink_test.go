package auditevent

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// recordingSink captures the JSON bytes of every event written to it (the state
// AT write time), for assertions.
type recordingSink struct {
	name  string
	lines [][]byte
}

func (r *recordingSink) Name() string { return r.name }
func (r *recordingSink) Write(e *Event) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	r.lines = append(r.lines, b)
	return nil
}
func (r *recordingSink) Close() error { return nil }

// failingSink always fails Write, to prove the Dispatcher collects and continues.
type failingSink struct{ closed bool }

func (f *failingSink) Name() string { return "failing" }
func (f *failingSink) Write(*Event) error {
	return errors.New("boom")
}
func (f *failingSink) Close() error { f.closed = true; return nil }

// failingSink models a full-disk / unwritable LOCAL spool: it is a LocalSink (no
// network) whose Write fails, so it is an accepted sink under NewDispatcherRequired
// (the fail-close comes from the WRITE failing, not from the sink being non-local).
func (f *failingSink) localSink() {}

// TestDispatchFanOutAndErrorCollection proves an event reaches every sink and a
// single sink failure is collected (not swallowed, not fatal to the others).
func TestDispatchFanOutAndErrorCollection(t *testing.T) {
	rec1 := &recordingSink{name: "rec1"}
	rec2 := &recordingSink{name: "rec2"}
	fail := &failingSink{}
	d := NewDispatcher(DefaultRedactor(), rec1, fail, rec2)

	e := New(EventSkillVerify, OutcomeSuccess, SeverityInfo, "skillctl/x")
	err := d.Dispatch(e)
	if err == nil || !strings.Contains(err.Error(), "failing") {
		t.Fatalf("expected a collected error naming the failing sink, got %v", err)
	}
	if len(rec1.lines) != 1 || len(rec2.lines) != 1 {
		t.Fatalf("both healthy sinks must have received the event: rec1=%d rec2=%d",
			len(rec1.lines), len(rec2.lines))
	}
}

// TestDispatchStampsDefaults proves a producer that leaves the envelope basics
// blank still emits a well-formed, valid event (schema/timestamp/event_id filled).
func TestDispatchStampsDefaults(t *testing.T) {
	rec := &recordingSink{name: "rec"}
	d := NewDispatcher(Redactor{}, rec)

	e := &Event{EventType: EventPolicyAllow, Outcome: OutcomeSuccess, Severity: SeverityInfo, Producer: "skillctl/x"}
	if err := d.Dispatch(e); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if e.Schema != SchemaV1 || e.Timestamp == "" || e.EventID == "" {
		t.Fatalf("defaults not stamped: %+v", e)
	}
	var got Event
	if err := json.Unmarshal(rec.lines[0], &got); err != nil {
		t.Fatalf("unmarshal recorded line: %v", err)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("recorded event is not valid: %v", err)
	}
}

// TestDispatchRedactsBeforeWrite proves redaction happens BEFORE any sink sees
// the event: a secret placed in a sensitive ext field never reaches a sink.
func TestDispatchRedactsBeforeWrite(t *testing.T) {
	rec := &recordingSink{name: "rec"}
	d := NewDispatcher(DefaultRedactor(), rec)

	e := New(EventPolicyAllow, OutcomeSuccess, SeverityInfo, "skillctl/x")
	if err := e.SetExt("authorization", "Bearer top-secret-xyz"); err != nil {
		t.Fatalf("SetExt: %v", err)
	}
	if err := d.Dispatch(e); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if strings.Contains(string(rec.lines[0]), "top-secret-xyz") {
		t.Fatalf("secret reached the sink un-redacted: %s", rec.lines[0])
	}
}

// TestDispatchRejectsInvalidWithoutWriting proves an invalid event is rejected
// and NO sink is written (validation precedes fan-out).
func TestDispatchRejectsInvalidWithoutWriting(t *testing.T) {
	rec := &recordingSink{name: "rec"}
	d := NewDispatcher(Redactor{}, rec)

	e := &Event{EventType: "skill.teleport", Outcome: OutcomeSuccess, Severity: SeverityInfo, Producer: "skillctl/x"}
	err := d.Dispatch(e)
	if !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("expected ErrInvalidEvent, got %v", err)
	}
	if len(rec.lines) != 0 {
		t.Fatalf("no sink should be written for an invalid event; got %d", len(rec.lines))
	}
}

// TestDispatchNil covers the nil-event guard.
func TestDispatchNil(t *testing.T) {
	d := NewDispatcher(Redactor{})
	if err := d.Dispatch(nil); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("nil event must error: %v", err)
	}
}

// TestDispatcherCloseClosesAllSinks proves Close reaches every sink even past a
// failure.
func TestDispatcherCloseClosesAllSinks(t *testing.T) {
	fail := &failingSink{}
	rec := &recordingSink{name: "rec"}
	d := NewDispatcher(Redactor{}, fail, rec)
	if err := d.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if !fail.closed {
		t.Fatalf("Close did not reach the failing sink")
	}
}
