package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
	tkafka "github.com/kamir/m3c-tools/internal/thinking/kafka"
	"github.com/kamir/m3c-tools/internal/thinking/schema"
)

// syncBuffer is bytes.Buffer + mutex so the test can read concurrently
// with the sink's emitLine.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// testHash returns a deterministic ctx hash for assertions.
func testHash(t *testing.T) mctx.Hash {
	t.Helper()
	r, err := mctx.NewRaw("observability-test")
	if err != nil {
		t.Fatal(err)
	}
	return r.Hash()
}

// newTestSink wires a fresh sink + in-memory bus + capturing buffer.
// Returns the sink, a producer function that emits events to the
// engine's own process.events topic, and the captured-lines buffer.
func newTestSink(t *testing.T, metrics Metrics) (*EventsSink, func(schema.ProcessEvent), *syncBuffer) {
	t.Helper()
	h := testHash(t)
	inner := tkafka.NewMemBus(h)
	bus, err := tkafka.NewValidatingBus(inner, nil)
	if err != nil {
		t.Fatal(err)
	}
	buf := &syncBuffer{}
	silent := log.New(buf, "", 0) // unused when Out is set; kept for defaults
	sink, err := NewEventsSink(SinkConfig{
		Hash:    h,
		Bus:     bus,
		Logger:  silent,
		Out:     buf,
		Metrics: metrics,
		Now:     func() time.Time { return time.Unix(0, 0).UTC() },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sink.Stop)

	topic := tkafka.TopicName(h, tkafka.TopicProcessEvents)
	produce := func(ev schema.ProcessEvent) {
		ev.SchemaVer = schema.CurrentSchemaVer
		if ev.Timestamp.IsZero() {
			ev.Timestamp = time.Unix(0, 0).UTC()
		}
		if err := bus.Produce(context.Background(), topic, "k", ev); err != nil {
			t.Fatalf("produce: %v", err)
		}
	}
	return sink, produce, buf
}

// waitForLine returns when buf.String() contains substr or fails after
// timeout. Used to synchronise with the bus's async dispatch.
func waitForLine(t *testing.T, buf *syncBuffer, substr string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		s := buf.String()
		if strings.Contains(s, substr) {
			return s
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %q in sink output\n---BUF---\n%s", substr, buf.String())
	return ""
}

// recordingMetrics captures every hook call for later assertion.
type recordingMetrics struct {
	mu            sync.Mutex
	stepFails     []string
	procFails     []string
	fires         []string
	skips         []string
	budgetPauses  int
	artifacts     []string
	er1Failures   int
	llmCalls      int
	hmacRotations int
}

func (r *recordingMetrics) RecordLLMCall(model, layer, strategy string, in, out int, lat time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.llmCalls++
}
func (r *recordingMetrics) RecordStepFailure(layer, strategy, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stepFails = append(r.stepFails, layer+"/"+strategy+"/"+reason)
}
func (r *recordingMetrics) RecordProcessFailure(mode string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.procFails = append(r.procFails, mode)
}
func (r *recordingMetrics) RecordAutoReflectFire(reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fires = append(r.fires, reason)
}
func (r *recordingMetrics) RecordAutoReflectSkip(reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.skips = append(r.skips, reason)
}
func (r *recordingMetrics) RecordBudgetPause() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.budgetPauses++
}
func (r *recordingMetrics) RecordArtifactCreated(format string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.artifacts = append(r.artifacts, format)
}
func (r *recordingMetrics) RecordER1SinkFailure() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.er1Failures++
}
func (r *recordingMetrics) RecordHMACRotation() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hmacRotations++
}

// TestEventMatcherFilter verifies matches() returns true for the
// documented event types and false for the ignored lifecycle ones.
func TestEventMatcherFilter(t *testing.T) {
	s := &EventsSink{}
	for _, name := range []string{
		"StepFailed", "ProcessFailed", "ArtifactPersistenceFailed",
		"SchemaValidationError",
		"AutoReflectTriggered", "AutoReflectSkipped", "AutoReflectBudgetPaused",
	} {
		if !s.matches(name) {
			t.Errorf("matches(%q) = false, want true", name)
		}
	}
	for _, name := range []string{
		"ProcessStarted", "StepStarted", "StepCompleted", "ProcessCompleted",
		"ArtifactPersisted",
	} {
		if s.matches(name) {
			t.Errorf("matches(%q) = true, want false", name)
		}
	}
}

// TestSeverityMap verifies the severity field per PLAN-0168 §P0.
func TestSeverityMap(t *testing.T) {
	cases := map[string]string{
		"StepFailed":                SeverityError,
		"ProcessFailed":             SeverityError,
		"ArtifactPersistenceFailed": SeverityError,
		"SchemaValidationError":     SeverityError,
		"AutoReflectBudgetPaused":   SeverityWarn,
		"AutoReflectSkipped":        SeverityInfo,
		"AutoReflectTriggered":      SeverityInfo,
	}
	for name, want := range cases {
		if got := severityFor(name); got != want {
			t.Errorf("severityFor(%q) = %q, want %q", name, got, want)
		}
	}
}

// TestStepFailedFlowsToLogAndCounter is the integration gate: a
// StepFailed event produced to the bus lands as a JSON line with
// severity=error AND bumps the step-failure counter.
func TestStepFailedFlowsToLogAndCounter(t *testing.T) {
	rec := &recordingMetrics{}
	_, produce, buf := newTestSink(t, rec)

	layer := schema.LayerR
	produce(schema.ProcessEvent{
		ProcessID: "p1",
		Event:     schema.ProcessEventName("StepFailed"),
		StepLayer: &layer,
		Detail: map[string]interface{}{
			"strategy": "compare",
			"reason":   "llm",
		},
	})

	line := waitForLine(t, buf, `"event_type":"StepFailed"`, time.Second)

	// Verify the emitted line parses as JSON with the expected fields.
	var got map[string]interface{}
	// There may be multiple lines; first one is the event.
	parts := strings.Split(strings.TrimRight(line, "\n"), "\n")
	if err := json.Unmarshal([]byte(parts[0]), &got); err != nil {
		t.Fatalf("first line not JSON: %v\nline: %s", err, parts[0])
	}
	if got["severity"] != "error" {
		t.Errorf("severity = %v, want error", got["severity"])
	}
	if got["event_type"] != "StepFailed" {
		t.Errorf("event_type = %v, want StepFailed", got["event_type"])
	}
	if got["process_id"] != "p1" {
		t.Errorf("process_id = %v, want p1", got["process_id"])
	}
	if got["ctx_hash"] == "" || got["ctx_hash"] == nil {
		t.Errorf("ctx_hash missing")
	}

	// Counter assertion.
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.stepFails) != 1 {
		t.Fatalf("stepFails = %v, want 1 entry", rec.stepFails)
	}
	// schema.LayerR is the string "R" (uppercase) — the events sink
	// pipes ev.StepLayer through to the counter label verbatim.
	if rec.stepFails[0] != "R/compare/llm" {
		t.Errorf("stepFails[0] = %q, want R/compare/llm", rec.stepFails[0])
	}
}

// TestProcessFailedAndArtifactPersistenceFailedFlow verifies the
// other two error-severity pathways.
func TestProcessFailedAndArtifactPersistenceFailedFlow(t *testing.T) {
	rec := &recordingMetrics{}
	_, produce, buf := newTestSink(t, rec)

	produce(schema.ProcessEvent{
		ProcessID: "p1",
		Event:     schema.ProcessEventName("ProcessFailed"),
		Detail:    map[string]interface{}{"mode": "semi_linear", "reason": "boom"},
	})
	produce(schema.ProcessEvent{
		ProcessID: "p2",
		Event:     schema.ProcessEventName("ArtifactPersistenceFailed"),
		Detail:    map[string]interface{}{"artifact_id": "a1"},
	})

	waitForLine(t, buf, `"event_type":"ProcessFailed"`, time.Second)
	waitForLine(t, buf, `"event_type":"ArtifactPersistenceFailed"`, time.Second)

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.procFails) != 1 || rec.procFails[0] != "semi_linear" {
		t.Errorf("procFails = %v, want [semi_linear]", rec.procFails)
	}
	if rec.er1Failures != 1 {
		t.Errorf("er1Failures = %d, want 1", rec.er1Failures)
	}
}

// TestAutoReflectEventsFlow verifies all three autoreflect events
// map correctly to counters + JSON lines.
func TestAutoReflectEventsFlow(t *testing.T) {
	rec := &recordingMetrics{}
	_, produce, buf := newTestSink(t, rec)

	produce(schema.ProcessEvent{
		ProcessID: "proc-42",
		Event:     schema.ProcessEventName("AutoReflectTriggered"),
		Detail:    map[string]interface{}{"reason": "window"},
	})
	produce(schema.ProcessEvent{
		ProcessID: "",
		Event:     schema.ProcessEventName("AutoReflectSkipped"),
		Detail:    map[string]interface{}{"reason": "rate_limit"},
	})
	produce(schema.ProcessEvent{
		ProcessID: "",
		Event:     schema.ProcessEventName("AutoReflectBudgetPaused"),
		Detail:    map[string]interface{}{"reason": "budget"},
	})

	waitForLine(t, buf, `"event_type":"AutoReflectTriggered"`, time.Second)
	waitForLine(t, buf, `"event_type":"AutoReflectSkipped"`, time.Second)
	waitForLine(t, buf, `"event_type":"AutoReflectBudgetPaused"`, time.Second)

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.fires) != 1 || rec.fires[0] != "window" {
		t.Errorf("fires = %v, want [window]", rec.fires)
	}
	if len(rec.skips) != 1 || rec.skips[0] != "rate_limit" {
		t.Errorf("skips = %v, want [rate_limit]", rec.skips)
	}
	if rec.budgetPauses != 1 {
		t.Errorf("budgetPauses = %d, want 1", rec.budgetPauses)
	}
}

// TestNonOperationalEventsAreIgnored verifies lifecycle events like
// ProcessStarted / StepStarted do not produce log lines or counter
// increments.
func TestNonOperationalEventsAreIgnored(t *testing.T) {
	rec := &recordingMetrics{}
	_, produce, buf := newTestSink(t, rec)

	for _, name := range []string{"ProcessStarted", "StepStarted", "StepCompleted", "ProcessCompleted", "ArtifactPersisted"} {
		produce(schema.ProcessEvent{
			ProcessID: "p",
			Event:     schema.ProcessEventName(name),
		})
	}

	// Give the dispatch loop a moment to pump the events.
	time.Sleep(50 * time.Millisecond)

	if s := buf.String(); s != "" {
		t.Errorf("expected empty buffer, got: %s", s)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.stepFails)+len(rec.procFails)+len(rec.fires)+len(rec.skips)+rec.budgetPauses+rec.er1Failures+len(rec.artifacts) != 0 {
		t.Errorf("expected no counter increments, got %+v", rec)
	}
}

// TestSinkNilMetricsSafe verifies the sink still flows log lines when
// Metrics is nil (the observability layer is opt-out per surface).
func TestSinkNilMetricsSafe(t *testing.T) {
	_, produce, buf := newTestSink(t, nil)
	layer := schema.LayerR
	produce(schema.ProcessEvent{
		ProcessID: "p",
		Event:     schema.ProcessEventName("StepFailed"),
		StepLayer: &layer,
	})
	waitForLine(t, buf, `"event_type":"StepFailed"`, time.Second)
}
