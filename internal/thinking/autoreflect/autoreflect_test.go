// autoreflect_test.go — unit tests for the auto-reflect consumer.
//
// Covered invariants (one test per line, see TestXxx names below):
//
//   - Window-count trigger fires on the Nth eligible T and emits
//     AutoReflectTriggered{reason=window}.
//   - Heartbeat with zero new Ts is a no-op (no event, no dispatch).
//   - Heartbeat with at least one new T fires and reports
//     reason=heartbeat.
//   - Rate limiter drops the (N+1)th fire in the same UTC hour and
//     emits AutoReflectSkipped{reason=rate_limit}.
//   - Dedup: the same sorted-id window within 60s emits
//     AutoReflectSkipped{reason=dedup} on the repeat.
//   - Budget: when the Ledger reports <20% remaining, we emit
//     AutoReflectSkipped{reason=budget} and do NOT dispatch.
//   - Placeholder filter: Ts whose content matches a configured
//     regex are dropped from the window. A full-placeholder burst
//     eventually emits AutoReflectSkipped{reason=no_eligible_ts}
//     via forceHeartbeat.
//
// The tests use the in-memory Bus and the in-memory SQLite store so
// they are hermetic and fast (≤ 200ms each on a laptop).
package autoreflect

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"testing"
	"time"

	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
	tkafka "github.com/kamir/m3c-tools/internal/thinking/kafka"
	"github.com/kamir/m3c-tools/internal/thinking/schema"
	"github.com/kamir/m3c-tools/internal/thinking/store"
)

// ----- test doubles -----

// fakeLedger lets each test pick a specific RemainingFraction value
// without touching the real store-backed ledger.
type fakeLedger struct{ remaining float64 }

func (f *fakeLedger) RemainingFraction() (float64, error) { return f.remaining, nil }

// captureDispatcher records Submit calls instead of handing them to
// a real orchestrator. Each test asserts the count and/or the shape
// of the latest spec.
type captureDispatcher struct {
	mu    sync.Mutex
	specs []schema.ProcessSpec
	// injected error, returned from Submit when non-nil.
	err error
}

func (d *captureDispatcher) Submit(_ context.Context, s schema.ProcessSpec) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.err != nil {
		return d.err
	}
	d.specs = append(d.specs, s)
	return nil
}

func (d *captureDispatcher) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.specs)
}

func (d *captureDispatcher) last() (schema.ProcessSpec, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.specs) == 0 {
		return schema.ProcessSpec{}, false
	}
	return d.specs[len(d.specs)-1], true
}

// eventSink subscribes to process.events and stores the parsed
// ProcessEvent values so tests can assert by name.
type eventSink struct {
	mu     sync.Mutex
	events []schema.ProcessEvent
}

func (s *eventSink) hook(_ context.Context, m tkafka.Message) error {
	var ev schema.ProcessEvent
	if err := json.Unmarshal(m.Value, &ev); err != nil {
		return nil
	}
	s.mu.Lock()
	s.events = append(s.events, ev)
	s.mu.Unlock()
	return nil
}

func (s *eventSink) byName(name schema.ProcessEventName) []schema.ProcessEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]schema.ProcessEvent, 0, len(s.events))
	for _, ev := range s.events {
		if ev.Event == name {
			out = append(out, ev)
		}
	}
	return out
}

func (s *eventSink) waitFor(name schema.ProcessEventName, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if len(s.byName(name)) > 0 {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// ----- environment helpers -----

type env struct {
	t       *testing.T
	bus     tkafka.Bus
	hash    mctx.Hash
	store   *store.Store
	sink    *eventSink
	disp    *captureDispatcher
	ledger  *fakeLedger
	cfg     Config
	consumer *Consumer
}

// newEnv builds a Consumer over an in-memory bus + store. The caller
// receives a handle to tweak cfg; call start() once the tweaks are in.
func newEnv(t *testing.T) *env {
	t.Helper()
	raw, err := mctx.NewRaw("auto-reflect-test")
	if err != nil {
		t.Fatal(err)
	}
	h := raw.Hash()
	inner := tkafka.NewMemBus(h)
	bus, err := tkafka.NewValidatingBus(inner, nil)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	sink := &eventSink{}
	if _, err := bus.Subscribe(tkafka.TopicName(h, tkafka.TopicProcessEvents), sink.hook); err != nil {
		t.Fatal(err)
	}
	e := &env{
		t:      t,
		bus:    bus,
		hash:   h,
		store:  st,
		sink:   sink,
		disp:   &captureDispatcher{},
		ledger: &fakeLedger{remaining: 1.0},
	}
	e.cfg = Config{
		Hash:             h,
		Bus:              bus,
		Orchestrator:     e.disp,
		Store:            st,
		Ledger:           e.ledger,
		Logger:           log.New(os.Stderr, "[autoreflect-test] ", 0),
		WindowN:          20,
		HeartbeatMin:     60,
		RateLimitPerHour: 10,
		SkipPlaceholder:  true,
		Patterns:         []string{`^⏳`},
		HardTokenCap:     DefaultHardTokenCap,
	}
	return e
}

// start builds the consumer with cfg and subscribes.
func (e *env) start() {
	e.t.Helper()
	c, err := New(e.cfg)
	if err != nil {
		e.t.Fatal(err)
	}
	if err := c.Start(context.Background()); err != nil {
		e.t.Fatal(err)
	}
	e.consumer = c
	e.t.Cleanup(func() {
		c.Stop()
		_ = e.store.Close()
	})
}

// publish sends a Thought onto the thoughts.raw topic.
func (e *env) publish(th schema.Thought) {
	e.t.Helper()
	topic := tkafka.TopicName(e.hash, tkafka.TopicThoughtsRaw)
	if err := e.bus.Produce(context.Background(), topic, th.ThoughtID, th); err != nil {
		e.t.Fatal(err)
	}
}

// observation returns a valid non-question T with text content.
func observation(id, text string) schema.Thought {
	return schema.Thought{
		SchemaVer: schema.CurrentSchemaVer,
		ThoughtID: id,
		Type:      schema.ThoughtObservation,
		Content:   schema.Content{Text: text},
		Source:    schema.Source{Kind: schema.SourceTyped, Ref: "unit-test"},
		Timestamp: time.Now().UTC(),
	}
}

// forceHeartbeat bypasses the wall-clock ticker by calling tryFire
// directly. Used in tests so we don't have to sleep for real minutes.
func (e *env) forceHeartbeat() {
	e.consumer.tryFire(context.Background(), "heartbeat")
}

// ----- individual tests -----

func TestWindowTriggerAfterNThoughts(t *testing.T) {
	e := newEnv(t)
	e.cfg.WindowN = 5
	e.start()

	for i := 0; i < 5; i++ {
		e.publish(observation(fmt.Sprintf("t-%d", i), "observation"))
	}

	if !e.sink.waitFor(EventAutoReflectTriggered, 500*time.Millisecond) {
		t.Fatalf("expected AutoReflectTriggered after %d Ts; events=%+v",
			e.cfg.WindowN, e.sink.events)
	}
	evs := e.sink.byName(EventAutoReflectTriggered)
	if reason, _ := evs[0].Detail["reason"].(string); reason != "window" {
		t.Fatalf("reason = %q, want %q", reason, "window")
	}
	if e.disp.count() != 1 {
		t.Fatalf("dispatch count = %d, want 1", e.disp.count())
	}
	spec, _ := e.disp.last()
	if spec.CreatedBy != CreatedByAutoReflect {
		t.Fatalf("created_by = %q, want %q", spec.CreatedBy, CreatedByAutoReflect)
	}
	if spec.Budget == nil || spec.Budget.MaxTokens != DefaultHardTokenCap {
		t.Fatalf("MaxTokens = %+v, want %d", spec.Budget, DefaultHardTokenCap)
	}
	if spec.Mode != schema.ModeSemiLinear {
		t.Fatalf("mode = %q, want semi_linear", spec.Mode)
	}
	if len(spec.Steps) != 3 {
		t.Fatalf("steps = %d, want 3", len(spec.Steps))
	}
}

func TestHeartbeatNoNewThoughtsNoFire(t *testing.T) {
	e := newEnv(t)
	e.cfg.HeartbeatMin = 60 // irrelevant — we call forceHeartbeat
	e.start()

	// no publishes — window is empty
	e.forceHeartbeat()

	// tryFire with empty window emits Skipped(no_eligible_ts) rather
	// than AutoReflectTriggered. Assert both shapes.
	if !e.sink.waitFor(EventAutoReflectSkipped, 300*time.Millisecond) {
		t.Fatalf("expected Skipped(no_eligible_ts); got events=%+v", e.sink.events)
	}
	if len(e.sink.byName(EventAutoReflectTriggered)) != 0 {
		t.Fatalf("no T arrived — must not fire; events=%+v", e.sink.events)
	}
	skipped := e.sink.byName(EventAutoReflectSkipped)
	if len(skipped) != 1 {
		t.Fatalf("expected exactly one AutoReflectSkipped; got %d (%+v)",
			len(skipped), e.sink.events)
	}
	if reason, _ := skipped[0].Detail["reason"].(string); reason != "no_eligible_ts" {
		t.Fatalf("reason = %q, want no_eligible_ts", reason)
	}
	if e.disp.count() != 0 {
		t.Fatalf("must not dispatch; got %d", e.disp.count())
	}
}

func TestHeartbeatWithThoughtFires(t *testing.T) {
	e := newEnv(t)
	e.cfg.WindowN = 999 // make the window trigger effectively unreachable
	e.start()

	e.publish(observation("t-heart-1", "heartbeat source"))

	// Give the handler a chance to enqueue.
	time.Sleep(20 * time.Millisecond)

	e.forceHeartbeat()

	if !e.sink.waitFor(EventAutoReflectTriggered, 300*time.Millisecond) {
		t.Fatalf("heartbeat with ≥1 T must fire; events=%+v", e.sink.events)
	}
	evs := e.sink.byName(EventAutoReflectTriggered)
	if reason, _ := evs[0].Detail["reason"].(string); reason != "heartbeat" {
		t.Fatalf("reason = %q, want heartbeat", reason)
	}
}

func TestRateLimitSkipsOverCap(t *testing.T) {
	e := newEnv(t)
	e.cfg.WindowN = 1            // every T fires
	e.cfg.RateLimitPerHour = 10  // per brief: 11th call should be skipped
	e.start()

	// Fire 11 distinct windows. Use unique ids so dedup does not
	// intervene — the limiter is the subject under test here.
	for i := 0; i < 11; i++ {
		e.publish(observation(fmt.Sprintf("t-rl-%d", i), "x"))
		// Wait for each fire to land before publishing the next.
		// 50ms is generous on the in-memory bus.
		time.Sleep(20 * time.Millisecond)
	}

	triggered := e.sink.byName(EventAutoReflectTriggered)
	if len(triggered) != 10 {
		t.Fatalf("expected 10 triggered, got %d (events=%d)",
			len(triggered), len(e.sink.events))
	}
	skipped := e.sink.byName(EventAutoReflectSkipped)
	rateSkips := 0
	for _, ev := range skipped {
		if reason, _ := ev.Detail["reason"].(string); reason == "rate_limit" {
			rateSkips++
		}
	}
	if rateSkips < 1 {
		t.Fatalf("expected ≥1 rate_limit skip, got %d (events=%+v)",
			rateSkips, e.sink.events)
	}
}

func TestDedupSuppressesRepeatWindow(t *testing.T) {
	e := newEnv(t)
	e.cfg.WindowN = 2
	e.start()

	// First window: two Ts with canonical ids a,b.
	e.publish(observation("t-dedup-a", "x"))
	e.publish(observation("t-dedup-b", "y"))

	if !e.sink.waitFor(EventAutoReflectTriggered, 300*time.Millisecond) {
		t.Fatal("first window must trigger")
	}
	initial := len(e.sink.byName(EventAutoReflectTriggered))
	if initial != 1 {
		t.Fatalf("initial triggered = %d, want 1", initial)
	}

	// Force the exact same id-set by poking the window state and
	// calling tryFire manually. This simulates a true duplicate window
	// (same sorted id list) — the brief's definition of dedup.
	e.consumer.mu.Lock()
	e.consumer.eligibleIDs = []string{"t-dedup-a", "t-dedup-b"}
	e.consumer.mu.Unlock()
	e.consumer.tryFire(context.Background(), "window")

	if !e.sink.waitFor(EventAutoReflectSkipped, 300*time.Millisecond) {
		t.Fatalf("expected Skipped event after duplicate tryFire; events=%+v", e.sink.events)
	}
	skipped := e.sink.byName(EventAutoReflectSkipped)
	dedupSkips := 0
	for _, ev := range skipped {
		if reason, _ := ev.Detail["reason"].(string); reason == "dedup" {
			dedupSkips++
		}
	}
	if dedupSkips != 1 {
		t.Fatalf("expected exactly 1 dedup skip, got %d (events=%+v)",
			dedupSkips, e.sink.events)
	}
	// Dispatch count must stay at 1.
	if e.disp.count() != 1 {
		t.Fatalf("dedup must not dispatch; got %d dispatches", e.disp.count())
	}
}

func TestBudgetPauseSkipsBelowThreshold(t *testing.T) {
	e := newEnv(t)
	e.cfg.WindowN = 1
	// Remaining fraction is only 0.15 — well under the 0.20 floor
	// (1 - BudgetPauseFraction), so the next fire must skip.
	e.ledger.remaining = 0.15
	e.start()

	e.publish(observation("t-budget-1", "x"))

	if !e.sink.waitFor(EventAutoReflectSkipped, 300*time.Millisecond) {
		t.Fatalf("expected Skipped event; got %+v", e.sink.events)
	}
	skipped := e.sink.byName(EventAutoReflectSkipped)
	found := false
	for _, ev := range skipped {
		if reason, _ := ev.Detail["reason"].(string); reason == "budget" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected Skipped(reason=budget); got %+v", skipped)
	}
	paused := e.sink.byName(EventAutoReflectBudgetPaused)
	if len(paused) < 1 {
		t.Fatalf("expected AutoReflectBudgetPaused companion event; got %+v", e.sink.events)
	}
	if e.disp.count() != 0 {
		t.Fatalf("budget cap must prevent dispatch; got %d", e.disp.count())
	}
}

func TestPlaceholderFilterExcludesMatchingTs(t *testing.T) {
	e := newEnv(t)
	e.cfg.WindowN = 3
	e.start()

	// Ts 0, 2 match the placeholder pattern (hourglass prefix) and
	// must be dropped; T 1 is eligible. With WindowN=3 and only 1
	// eligible T, no fire should happen automatically.
	e.publish(observation("t-ph-0", "⏳ transcribing..."))
	e.publish(observation("t-ph-1", "real observation"))
	e.publish(observation("t-ph-2", "⏳ still transcribing"))

	time.Sleep(60 * time.Millisecond)

	if len(e.sink.byName(EventAutoReflectTriggered)) != 0 {
		t.Fatalf("placeholder-only Ts must not reach window count; events=%+v", e.sink.events)
	}
	// Verify the one eligible T did make it in.
	e.consumer.mu.Lock()
	n := len(e.consumer.eligibleIDs)
	e.consumer.mu.Unlock()
	if n != 1 {
		t.Fatalf("eligible count = %d, want 1 (only non-placeholder T)", n)
	}
}

func TestAllPlaceholderHeartbeatEmitsNoEligibleTs(t *testing.T) {
	e := newEnv(t)
	e.cfg.WindowN = 100
	e.start()

	// Every T is a placeholder. None reach the window.
	for i := 0; i < 5; i++ {
		e.publish(observation(fmt.Sprintf("t-only-ph-%d", i), "⏳ still transcribing"))
	}
	time.Sleep(30 * time.Millisecond)

	e.forceHeartbeat()

	if !e.sink.waitFor(EventAutoReflectSkipped, 300*time.Millisecond) {
		t.Fatalf("expected Skipped event; got %+v", e.sink.events)
	}
	skipped := e.sink.byName(EventAutoReflectSkipped)
	sawNoEligible := false
	for _, ev := range skipped {
		if reason, _ := ev.Detail["reason"].(string); reason == "no_eligible_ts" {
			sawNoEligible = true
			break
		}
	}
	if !sawNoEligible {
		t.Fatalf("expected Skipped(reason=no_eligible_ts); got %+v", e.sink.events)
	}
	if e.disp.count() != 0 {
		t.Fatalf("no dispatch when no eligible Ts; got %d", e.disp.count())
	}
}

func TestQuestionThoughtsExcluded(t *testing.T) {
	// Feedback-loop follow-ups (type=question) must never count
	// toward the auto-reflect window — otherwise the engine ping-pongs
	// on its own output.
	e := newEnv(t)
	e.cfg.WindowN = 1
	e.start()

	q := observation("t-q-1", "why?")
	q.Type = schema.ThoughtQuestion
	pa := "proc://p-1"
	q.Provenance = &schema.Provenance{CapturedBy: "i-proc", ParentArtifactID: &pa}
	e.publish(q)

	time.Sleep(30 * time.Millisecond)

	if len(e.sink.byName(EventAutoReflectTriggered)) != 0 {
		t.Fatalf("question Ts must be excluded; events=%+v", e.sink.events)
	}
}

func TestInvalidPatternFallsBackToDefault(t *testing.T) {
	e := newEnv(t)
	e.cfg.WindowN = 10
	e.cfg.Patterns = []string{`(`, ``, `[unclosed`}
	e.start()

	// With every configured pattern invalid, the consumer falls back
	// to DefaultPlaceholderPattern ("^⏳"). Verify both that invalid
	// patterns didn't crash startup AND that the fallback still works
	// on an hourglass-prefixed T.
	e.publish(observation("t-bad-pat-0", "⏳ drop me"))
	e.publish(observation("t-bad-pat-1", "keep me"))

	time.Sleep(30 * time.Millisecond)

	e.consumer.mu.Lock()
	ids := append([]string(nil), e.consumer.eligibleIDs...)
	e.consumer.mu.Unlock()
	if len(ids) != 1 || ids[0] != "t-bad-pat-1" {
		t.Fatalf("fallback pattern not applied; eligible=%v", ids)
	}
}

func TestDefaultSpecShape(t *testing.T) {
	ids := []string{"t-1", "t-2", "t-3"}
	spec := DefaultAutoReflectSpec(ids, 12345)
	if spec.Mode != schema.ModeSemiLinear {
		t.Errorf("mode = %q, want semi_linear", spec.Mode)
	}
	if len(spec.Steps) != 3 {
		t.Fatalf("len(steps) = %d, want 3", len(spec.Steps))
	}
	want := []struct {
		layer    schema.Layer
		strategy string
		prompt   string
	}{
		{schema.LayerR, "compare", "tmpl.reflect.compare.v1"},
		{schema.LayerI, "pattern", "tmpl.insight.pattern.v1"},
		{schema.LayerA, "summary", "tmpl.artifact.summary.v1"},
	}
	for i, w := range want {
		got := spec.Steps[i]
		if got.Layer != w.layer || got.Strategy != w.strategy {
			t.Errorf("step %d: %s/%s, want %s/%s", i, got.Layer, got.Strategy, w.layer, w.strategy)
		}
		if got.PromptID == nil || *got.PromptID != w.prompt {
			t.Errorf("step %d: prompt_id = %v, want %q", i, got.PromptID, w.prompt)
		}
		if got.Context == nil || got.Context.Scope == nil || len(got.Context.Scope.Entities) != len(ids) {
			t.Errorf("step %d: scope.entities = %+v, want %+v", i, got.Context, ids)
		}
	}
	if spec.Budget == nil || spec.Budget.MaxTokens != 12345 {
		t.Errorf("budget = %+v, want MaxTokens=12345", spec.Budget)
	}
	if spec.CreatedBy != CreatedByAutoReflect {
		t.Errorf("created_by = %q, want %q", spec.CreatedBy, CreatedByAutoReflect)
	}
}

func TestDedupHashIsOrderIndependent(t *testing.T) {
	a := dedupHash([]string{"t-1", "t-2", "t-3"})
	b := dedupHash([]string{"t-3", "t-1", "t-2"})
	if a != b {
		t.Errorf("dedup hash must be order-independent; %s != %s", a, b)
	}
	c := dedupHash([]string{"t-1", "t-2"})
	if a == c {
		t.Errorf("dedup hash must change when set changes")
	}
}
