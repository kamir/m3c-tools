// orchestrator_test.go — unit tests for the Week-3 step-barrier.
//
// Covers:
//   - semi_linear: step N+1 is NOT dispatched until StepCompleted for
//     step N arrives; and if step 2 emits ProcessFailed, step 3 is
//     never dispatched.
//   - loop: after the last step completes, the orchestrator re-enters
//     step 0 until max_iterations is reached.
//
// Tests use the in-memory bus directly and drive step completion by
// calling EmitStepCompleted / EmitProcessFailed from the test — no
// real processors are started.
package orchestrator

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
	tkafka "github.com/kamir/m3c-tools/internal/thinking/kafka"
	"github.com/kamir/m3c-tools/internal/thinking/schema"
	"github.com/kamir/m3c-tools/internal/thinking/store"
)

// cmdCollector subscribes to the command topic and records which step
// indices have been dispatched.
type cmdCollector struct {
	mu    sync.Mutex
	steps []int
}

func (c *cmdCollector) add(idx int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.steps = append(c.steps, idx)
}

func (c *cmdCollector) snapshot() []int {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]int, len(c.steps))
	copy(out, c.steps)
	return out
}

// newTestOrc builds an orchestrator against an in-memory validating
// bus and collects command dispatches.
func newTestOrc(t *testing.T) (*Orchestrator, *cmdCollector, mctx.Hash, tkafka.Bus, *store.Store, func()) {
	t.Helper()
	raw, err := mctx.NewRaw("orc-test")
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
	orc := New(h, bus, st)
	if err := orc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	col := &cmdCollector{}
	_, _ = bus.Subscribe(tkafka.TopicName(h, tkafka.TopicProcessCommands), func(ctx context.Context, m tkafka.Message) error {
		var cmd schema.ProcessCommand
		if err := json.Unmarshal(m.Value, &cmd); err == nil {
			col.add(cmd.StepIndex)
		}
		return nil
	})
	cleanup := func() {
		orc.Stop()
		_ = st.Close()
	}
	return orc, col, h, bus, st, cleanup
}

func TestSemiLinearDispatchesOnlyFirstStepImmediately(t *testing.T) {
	orc, col, _, _, _, cleanup := newTestOrc(t)
	defer cleanup()

	spec := schema.ProcessSpec{
		SchemaVer: schema.CurrentSchemaVer,
		ProcessID: uuid.NewString(),
		Intent:    "semi",
		Mode:      schema.ModeSemiLinear,
		Depth:     1,
		Steps: []schema.Step{
			{Layer: schema.LayerR, Strategy: "compare"},
			{Layer: schema.LayerI, Strategy: "pattern"},
			{Layer: schema.LayerA, Strategy: "report"},
		},
	}
	if err := orc.Submit(context.Background(), spec); err != nil {
		t.Fatal(err)
	}

	// Give the in-memory bus a moment to dispatch.
	time.Sleep(50 * time.Millisecond)

	got := col.snapshot()
	if len(got) != 1 || got[0] != 0 {
		t.Fatalf("semi_linear should dispatch only step 0 first, got %v", got)
	}
}

func TestSemiLinearAdvancesOnStepCompleted(t *testing.T) {
	orc, col, _, _, _, cleanup := newTestOrc(t)
	defer cleanup()

	spec := schema.ProcessSpec{
		SchemaVer: schema.CurrentSchemaVer,
		ProcessID: uuid.NewString(),
		Intent:    "semi",
		Mode:      schema.ModeSemiLinear,
		Depth:     1,
		Steps: []schema.Step{
			{Layer: schema.LayerR, Strategy: "compare"},
			{Layer: schema.LayerI, Strategy: "pattern"},
			{Layer: schema.LayerA, Strategy: "report"},
		},
	}
	if err := orc.Submit(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)

	// Simulate step 0 completing.
	_ = orc.EmitStepCompleted(context.Background(), spec.ProcessID, 0, schema.LayerR, map[string]interface{}{})
	// Wait for the orchestrator to observe + dispatch step 1.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if len(col.snapshot()) >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	got := col.snapshot()
	if len(got) < 2 {
		t.Fatalf("expected step 1 to be dispatched after step 0 completed, got %v", got)
	}
	if got[1] != 1 {
		t.Errorf("second dispatch = %d, want 1", got[1])
	}

	// Complete step 1 — expect step 2 to dispatch.
	_ = orc.EmitStepCompleted(context.Background(), spec.ProcessID, 1, schema.LayerI, map[string]interface{}{})
	deadline = time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if len(col.snapshot()) >= 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	got = col.snapshot()
	if len(got) != 3 {
		t.Fatalf("expected 3 total dispatches, got %v", got)
	}
	if got[2] != 2 {
		t.Errorf("third dispatch = %d, want 2", got[2])
	}
}

func TestSemiLinearStopsOnStepFailure(t *testing.T) {
	orc, col, _, _, _, cleanup := newTestOrc(t)
	defer cleanup()

	spec := schema.ProcessSpec{
		SchemaVer: schema.CurrentSchemaVer,
		ProcessID: uuid.NewString(),
		Intent:    "semi-fail",
		Mode:      schema.ModeSemiLinear,
		Depth:     1,
		Steps: []schema.Step{
			{Layer: schema.LayerR, Strategy: "compare"},
			{Layer: schema.LayerI, Strategy: "pattern"},
			{Layer: schema.LayerA, Strategy: "report"},
		},
	}
	if err := orc.Submit(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)

	// Step 0 completes fine, step 1 fails.
	_ = orc.EmitStepCompleted(context.Background(), spec.ProcessID, 0, schema.LayerR, map[string]interface{}{})
	time.Sleep(100 * time.Millisecond)
	_ = orc.EmitProcessFailed(context.Background(), spec.ProcessID, "boom")
	// Wait for anything else to NOT be dispatched.
	time.Sleep(150 * time.Millisecond)

	got := col.snapshot()
	if len(got) != 2 {
		t.Fatalf("expected 2 dispatches (0 and 1), got %v", got)
	}
	for _, idx := range got {
		if idx == 2 {
			t.Fatalf("step 2 must not be dispatched after failure; got %v", got)
		}
	}
}

func TestLoopModeIteratesUpToCap(t *testing.T) {
	orc, col, _, _, st, cleanup := newTestOrc(t)
	defer cleanup()

	spec := schema.ProcessSpec{
		SchemaVer: schema.CurrentSchemaVer,
		ProcessID: uuid.NewString(),
		Intent:    "loop",
		Mode:      schema.ModeLoop,
		Depth:     1,
		Steps: []schema.Step{
			{Layer: schema.LayerR, Strategy: "compare"},
			{Layer: schema.LayerI, Strategy: "pattern"},
		},
		Triggers: []schema.Trigger{
			{Type: schema.TriggerEvent, Event: strPtr("max_iterations=2")},
		},
	}
	if err := orc.Submit(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)

	// Drive two full iterations.
	for iter := 0; iter < 2; iter++ {
		_ = orc.EmitStepCompleted(context.Background(), spec.ProcessID, 0, schema.LayerR, nil)
		time.Sleep(50 * time.Millisecond)
		_ = orc.EmitStepCompleted(context.Background(), spec.ProcessID, 1, schema.LayerI, nil)
		time.Sleep(50 * time.Millisecond)
	}

	// After iteration 2 completes the cap is reached — NO further
	// step-0 dispatch should happen even if we try to complete again.
	_ = orc.EmitStepCompleted(context.Background(), spec.ProcessID, 1, schema.LayerI, nil)
	time.Sleep(50 * time.Millisecond)

	got := col.snapshot()
	// Expected dispatches: iter1 [0,1], iter2 [0,1] → 4 total. No iter3.
	if len(got) != 4 {
		t.Fatalf("loop: expected 4 total dispatches across 2 iterations, got %v", got)
	}
	expectedSeq := []int{0, 1, 0, 1}
	for i, v := range expectedSeq {
		if got[i] != v {
			t.Errorf("loop dispatch seq[%d] = %d, want %d (got %v)", i, got[i], v, got)
		}
	}

	// State should be completed with iteration_idx == 2.
	row, err := st.GetProcess(spec.ProcessID)
	if err != nil {
		t.Fatal(err)
	}
	if row.State != store.StateCompleted {
		t.Errorf("process state = %s, want completed", row.State)
	}
	if row.IterationIdx != 2 {
		t.Errorf("iteration_idx = %d, want 2", row.IterationIdx)
	}
}

func TestLoopModeUsesDefaultCapWhenNoTrigger(t *testing.T) {
	orc, col, _, _, _, cleanup := newTestOrc(t)
	defer cleanup()

	spec := schema.ProcessSpec{
		SchemaVer: schema.CurrentSchemaVer,
		ProcessID: uuid.NewString(),
		Intent:    "loop-default",
		Mode:      schema.ModeLoop,
		Depth:     1,
		Steps: []schema.Step{
			{Layer: schema.LayerR, Strategy: "compare"},
		},
	}
	if err := orc.Submit(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)

	// Drive DefaultLoopMaxIterations iterations of the single step.
	for i := 0; i < DefaultLoopMaxIterations; i++ {
		_ = orc.EmitStepCompleted(context.Background(), spec.ProcessID, 0, schema.LayerR, nil)
		time.Sleep(40 * time.Millisecond)
	}
	// Extra completion — should NOT advance past the cap.
	_ = orc.EmitStepCompleted(context.Background(), spec.ProcessID, 0, schema.LayerR, nil)
	time.Sleep(40 * time.Millisecond)

	got := col.snapshot()
	if len(got) != DefaultLoopMaxIterations {
		t.Errorf("loop default: expected %d dispatches, got %v (len=%d)", DefaultLoopMaxIterations, got, len(got))
	}
}

func TestLinearModeDispatchesAllStepsImmediately(t *testing.T) {
	orc, col, _, _, _, cleanup := newTestOrc(t)
	defer cleanup()

	spec := schema.ProcessSpec{
		SchemaVer: schema.CurrentSchemaVer,
		ProcessID: uuid.NewString(),
		Intent:    "lin",
		Mode:      schema.ModeLinear,
		Depth:     1,
		Steps: []schema.Step{
			{Layer: schema.LayerR, Strategy: "compare"},
			{Layer: schema.LayerI, Strategy: "pattern"},
			{Layer: schema.LayerA, Strategy: "report"},
		},
	}
	if err := orc.Submit(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	// Wait for async fan-out.
	time.Sleep(80 * time.Millisecond)
	got := col.snapshot()
	if len(got) != 3 {
		t.Errorf("linear: expected all 3 steps dispatched eagerly, got %v", got)
	}
}

func TestLoopMaxIterationsParsesEventOverride(t *testing.T) {
	spec := schema.ProcessSpec{
		Mode: schema.ModeLoop,
		Triggers: []schema.Trigger{
			{Type: schema.TriggerEvent, Event: strPtr("max_iterations=5")},
		},
	}
	if n := loopMaxIterations(spec); n != 5 {
		t.Errorf("max_iterations = %d, want 5", n)
	}

	// Invalid values fall back to default.
	spec.Triggers[0].Event = strPtr("max_iterations=-4")
	if n := loopMaxIterations(spec); n != DefaultLoopMaxIterations {
		t.Errorf("bad value: got %d, want default %d", n, DefaultLoopMaxIterations)
	}

	spec.Triggers = nil
	if n := loopMaxIterations(spec); n != DefaultLoopMaxIterations {
		t.Errorf("no triggers: got %d, want default %d", n, DefaultLoopMaxIterations)
	}
}

func strPtr(s string) *string { return &s }
