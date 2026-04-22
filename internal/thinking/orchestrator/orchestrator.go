// Package orchestrator accepts a ProcessSpec, publishes lifecycle
// events, and dispatches one ProcessCommand per step to the
// command topic. Processors (R/I/A/C) consume that topic and do the
// per-layer work.
//
// Week 3 (SPEC-0167 §Stream 3a) adds two execution modes on top of
// the Week-1 eager-dispatch behaviour:
//
//   - semi_linear: step N waits for StepCompleted of N-1. The
//     orchestrator subscribes to its own process.events topic and
//     only dispatches the next command once the previous step has
//     reported completion. If any step emits ProcessFailed the
//     barrier stops — subsequent steps are never dispatched.
//
//   - loop: same barrier semantics as semi_linear, but after the
//     final step completes we re-enter step 0 with a fresh iteration
//     counter until max_iterations (default 3) is reached. Prevents
//     runaway cost.
//
// SPEC-0167 §Service Components §orchestrator.
package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
	tkafka "github.com/kamir/m3c-tools/internal/thinking/kafka"
	"github.com/kamir/m3c-tools/internal/thinking/schema"
	"github.com/kamir/m3c-tools/internal/thinking/store"
)

// DefaultLoopMaxIterations is the SPEC-0167 §Stream 3a cap. Applied
// when ProcessSpec.Triggers does not carry an explicit override.
const DefaultLoopMaxIterations = 3

// Orchestrator drives a ProcessSpec to completion via Kafka.
type Orchestrator struct {
	hash     mctx.Hash
	bus      tkafka.Bus
	store    *store.Store
	cmdTopic string
	evtTopic string

	// barriers tracks semi_linear / loop processes so StepCompleted
	// events can advance them. Keyed by process_id.
	mu       sync.Mutex
	barriers map[string]*barrier
	stopEvt  func()
}

// barrier carries the runtime state for one semi_linear or loop process.
type barrier struct {
	spec         schema.ProcessSpec
	nextStep     int // the index the orchestrator will dispatch next
	iteration    int // loop-mode counter
	maxIters     int // loop cap (1 for semi_linear/linear, N for loop)
	done         bool
}

// New builds an orchestrator bound to the engine's own hash.
func New(h mctx.Hash, bus tkafka.Bus, s *store.Store) *Orchestrator {
	return &Orchestrator{
		hash:     h,
		bus:      bus,
		store:    s,
		cmdTopic: tkafka.TopicName(h, tkafka.TopicProcessCommands),
		evtTopic: tkafka.TopicName(h, tkafka.TopicProcessEvents),
		barriers: map[string]*barrier{},
	}
}

// Start subscribes the orchestrator to its own process.events topic
// so it can implement semi_linear / loop step barriers. Called once
// at engine boot. Safe to call multiple times — idempotent.
func (o *Orchestrator) Start(ctx context.Context) error {
	o.mu.Lock()
	if o.stopEvt != nil {
		o.mu.Unlock()
		return nil
	}
	o.mu.Unlock()

	stop, err := o.bus.Subscribe(o.evtTopic, func(hctx context.Context, m tkafka.Message) error {
		var ev schema.ProcessEvent
		if err := json.Unmarshal(m.Value, &ev); err != nil {
			return nil
		}
		o.onProcessEvent(ctx, ev)
		return nil
	})
	if err != nil {
		return fmt.Errorf("orchestrator: subscribe events: %w", err)
	}
	o.mu.Lock()
	o.stopEvt = stop
	o.mu.Unlock()
	return nil
}

// Stop releases the events subscription. Safe to call multiple times.
func (o *Orchestrator) Stop() {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.stopEvt != nil {
		o.stopEvt()
		o.stopEvt = nil
	}
}

// Submit registers the spec in the store, publishes ProcessStarted,
// and dispatches step 0. Subsequent steps depend on mode:
//
//   - linear: every remaining step is dispatched eagerly (Week 1 behaviour).
//   - semi_linear, loop: only step 0 is dispatched now; step N+1 is
//     dispatched when StepCompleted for step N arrives.
//   - guided: step 0 only; further steps wait for manual input
//     (UI will POST more commands; no auto-dispatch here).
func (o *Orchestrator) Submit(ctx context.Context, spec schema.ProcessSpec) error {
	if spec.ProcessID == "" {
		spec.ProcessID = uuid.NewString()
	}
	if spec.SchemaVer == 0 {
		spec.SchemaVer = schema.CurrentSchemaVer
	}
	if err := o.store.InsertProcess(spec); err != nil {
		return fmt.Errorf("orchestrator: store insert: %w", err)
	}
	if err := o.emit(ctx, spec.ProcessID, schema.EventProcessStarted, nil, nil); err != nil {
		return err
	}
	if err := o.store.UpdateState(spec.ProcessID, store.StateRunning, ""); err != nil {
		return err
	}

	switch spec.Mode {
	case schema.ModeSemiLinear, schema.ModeLoop:
		maxIters := 1
		if spec.Mode == schema.ModeLoop {
			maxIters = loopMaxIterations(spec)
		}
		o.mu.Lock()
		o.barriers[spec.ProcessID] = &barrier{
			spec:      spec,
			nextStep:  0,
			iteration: 0,
			maxIters:  maxIters,
		}
		o.mu.Unlock()
		// Dispatch step 0 only; subsequent steps gate on StepCompleted.
		if len(spec.Steps) == 0 {
			return nil
		}
		return o.dispatchStep(ctx, spec, 0)
	case schema.ModeGuided:
		// Guided mode: dispatch step 0 only, wait for manual
		// advancement. Week-3 scope does not change guided behaviour
		// beyond that.
		if len(spec.Steps) == 0 {
			return nil
		}
		return o.dispatchStep(ctx, spec, 0)
	default:
		// linear — dispatch every step eagerly (Week 1 behaviour).
		for i := range spec.Steps {
			if err := o.dispatchStep(ctx, spec, i); err != nil {
				return err
			}
		}
	}
	return nil
}

// dispatchStep emits one ProcessCommand for spec.Steps[i].
func (o *Orchestrator) dispatchStep(ctx context.Context, spec schema.ProcessSpec, i int) error {
	if i < 0 || i >= len(spec.Steps) {
		return fmt.Errorf("orchestrator: step index %d out of range [0,%d)", i, len(spec.Steps))
	}
	cmd := schema.ProcessCommand{
		SchemaVer: schema.CurrentSchemaVer,
		ProcessID: spec.ProcessID,
		StepIndex: i,
		Step:      spec.Steps[i],
		Spec:      spec,
		Timestamp: time.Now().UTC(),
	}
	if err := o.bus.Produce(ctx, o.cmdTopic, spec.ProcessID, cmd); err != nil {
		return fmt.Errorf("orchestrator: produce cmd step %d: %w", i, err)
	}
	return nil
}

// onProcessEvent handles StepCompleted / ProcessFailed to advance
// semi_linear / loop barriers.
func (o *Orchestrator) onProcessEvent(ctx context.Context, ev schema.ProcessEvent) {
	o.mu.Lock()
	b, ok := o.barriers[ev.ProcessID]
	o.mu.Unlock()
	if !ok {
		return
	}
	switch ev.Event {
	case schema.EventStepCompleted:
		// Extract step_index from detail (orchestrator populates this).
		idx, ok := stepIndexFromDetail(ev.Detail)
		if !ok {
			return
		}
		if _, err := o.store.AdvanceStepIndex(ev.ProcessID, idx); err != nil {
			return
		}
		o.mu.Lock()
		// Only advance if this completion is for the current step.
		if b.done || idx != b.nextStep {
			o.mu.Unlock()
			return
		}
		next := b.nextStep + 1
		spec := b.spec
		if next < len(spec.Steps) {
			b.nextStep = next
			o.mu.Unlock()
			_ = o.dispatchStep(ctx, spec, next)
			return
		}
		// End of iteration. In loop mode, re-enter step 0 if the cap
		// has not been reached.
		if spec.Mode == schema.ModeLoop {
			// Bump iteration counter first so cap check is accurate.
			iter, err := o.store.IncrementIteration(ev.ProcessID)
			if err != nil {
				o.mu.Unlock()
				return
			}
			b.iteration = iter
			if iter < b.maxIters {
				b.nextStep = 0
				o.mu.Unlock()
				_ = o.dispatchStep(ctx, spec, 0)
				return
			}
			// Cap reached — mark done and close out. Completion is
			// normally emitted by the last-step processor (A-proc);
			// if the spec has no A-step or that emitter doesn't run,
			// the caller can still call Complete() separately.
			b.done = true
			o.mu.Unlock()
			_ = o.emit(ctx, ev.ProcessID, schema.EventProcessCompleted, nil, map[string]interface{}{
				"loop_iterations": iter,
				"reason":          "max_iterations_reached",
			})
			_ = o.store.UpdateState(ev.ProcessID, store.StateCompleted, "")
			return
		}
		// semi_linear — end of chain.
		b.done = true
		o.mu.Unlock()

	case schema.EventProcessFailed, schema.EventProcessCancelled:
		// Stop the barrier — no more steps will be dispatched.
		o.mu.Lock()
		b.done = true
		o.mu.Unlock()
	}
}

func stepIndexFromDetail(detail map[string]interface{}) (int, bool) {
	if detail == nil {
		return 0, false
	}
	v, ok := detail["step_index"]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	case json.Number:
		i, err := n.Int64()
		if err == nil {
			return int(i), true
		}
	}
	return 0, false
}

// loopMaxIterations resolves the per-process iteration cap. Triggers
// of type=schedule with Cron unset are treated as opaque; the only
// way to override the default today is an explicit integer-valued
// Trigger.Event of form "max_iterations=N". Keeps the schema stable
// without growing ProcessSpec — revisit in Phase 2 if power users
// need a richer knob.
func loopMaxIterations(spec schema.ProcessSpec) int {
	for _, t := range spec.Triggers {
		if t.Event == nil {
			continue
		}
		s := *t.Event
		const pref = "max_iterations="
		if len(s) > len(pref) && s[:len(pref)] == pref {
			var n int
			_, err := fmt.Sscanf(s[len(pref):], "%d", &n)
			if err == nil && n > 0 && n <= 100 {
				return n
			}
		}
	}
	return DefaultLoopMaxIterations
}

// Cancel publishes ProcessCancelled and marks the store row.
func (o *Orchestrator) Cancel(ctx context.Context, processID string) error {
	if err := o.emit(ctx, processID, schema.EventProcessCancelled, nil, nil); err != nil {
		return err
	}
	return o.store.UpdateState(processID, store.StateCancelled, "")
}

// Complete marks the process completed and publishes
// ProcessCompleted. Called by whichever processor closes out the
// last step (in Week 1 this is the A-processor).
func (o *Orchestrator) Complete(ctx context.Context, processID string, artifactIDs []string) error {
	for _, id := range artifactIDs {
		_ = o.store.AppendArtifact(processID, id)
	}
	if err := o.store.UpdateState(processID, store.StateCompleted, ""); err != nil {
		return err
	}
	return o.emit(ctx, processID, schema.EventProcessCompleted, nil, map[string]interface{}{
		"artifact_ids": artifactIDs,
	})
}

// EmitStepStarted is called by processors when they begin work.
func (o *Orchestrator) EmitStepStarted(ctx context.Context, processID string, idx int, layer schema.Layer) error {
	return o.emit(ctx, processID, schema.EventStepStarted, &layer, map[string]interface{}{
		"step_index": idx,
	})
}

// EmitStepCompleted is called by processors when they finish work.
func (o *Orchestrator) EmitStepCompleted(ctx context.Context, processID string, idx int, layer schema.Layer, detail map[string]interface{}) error {
	if detail == nil {
		detail = map[string]interface{}{}
	}
	detail["step_index"] = idx
	return o.emit(ctx, processID, schema.EventStepCompleted, &layer, detail)
}

// EmitProcessFailed publishes ProcessFailed with an error message.
func (o *Orchestrator) EmitProcessFailed(ctx context.Context, processID string, reason string) error {
	_ = o.store.UpdateState(processID, store.StateFailed, "")
	return o.emit(ctx, processID, schema.EventProcessFailed, nil, map[string]interface{}{
		"reason": reason,
	})
}

func (o *Orchestrator) emit(ctx context.Context, processID string, name schema.ProcessEventName, layer *schema.Layer, detail map[string]interface{}) error {
	ev := schema.ProcessEvent{
		SchemaVer: schema.CurrentSchemaVer,
		ProcessID: processID,
		Event:     name,
		StepLayer: layer,
		Detail:    detail,
		Timestamp: time.Now().UTC(),
	}
	return o.bus.Produce(ctx, o.evtTopic, processID, ev)
}

// CmdTopic returns the command topic name so processors can subscribe.
func (o *Orchestrator) CmdTopic() string { return o.cmdTopic }

// EvtTopic returns the lifecycle-event topic name.
func (o *Orchestrator) EvtTopic() string { return o.evtTopic }
