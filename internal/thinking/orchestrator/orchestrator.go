// Package orchestrator accepts a ProcessSpec, publishes lifecycle
// events, and dispatches one ProcessCommand per step to the
// command topic. Processors (R/I/A/C) consume that topic and do the
// per-layer work.
//
// SPEC-0167 §Service Components §orchestrator.
package orchestrator

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
	tkafka "github.com/kamir/m3c-tools/internal/thinking/kafka"
	"github.com/kamir/m3c-tools/internal/thinking/schema"
	"github.com/kamir/m3c-tools/internal/thinking/store"
)

// Orchestrator drives a ProcessSpec to completion via Kafka.
type Orchestrator struct {
	hash     mctx.Hash
	bus      tkafka.Bus
	store    *store.Store
	cmdTopic string
	evtTopic string
}

// New builds an orchestrator bound to the engine's own hash.
func New(h mctx.Hash, bus tkafka.Bus, s *store.Store) *Orchestrator {
	return &Orchestrator{
		hash:     h,
		bus:      bus,
		store:    s,
		cmdTopic: tkafka.TopicName(h, tkafka.TopicProcessCommands),
		evtTopic: tkafka.TopicName(h, tkafka.TopicProcessEvents),
	}
}

// Submit registers the spec in the store, publishes ProcessStarted,
// and dispatches one StepStarted + command per step. For Week 1 the
// orchestrator fires commands eagerly; real sequencing (semi_linear
// barriers etc.) lands Week 2+.
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

	// Dispatch each step as a command. Consumers (processors) will
	// emit StepStarted/StepCompleted as they run.
	for i, step := range spec.Steps {
		cmd := schema.ProcessCommand{
			SchemaVer: schema.CurrentSchemaVer,
			ProcessID: spec.ProcessID,
			StepIndex: i,
			Step:      step,
			Spec:      spec,
			Timestamp: time.Now().UTC(),
		}
		if err := o.bus.Produce(ctx, o.cmdTopic, spec.ProcessID, cmd); err != nil {
			return fmt.Errorf("orchestrator: produce cmd: %w", err)
		}
	}
	return nil
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
