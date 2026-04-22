// Package processors provides the R/I/A/C cognitive-layer
// processors. Each sub-package is a Kafka consumer+producer with a
// strategy-dispatch map and stub handlers.
//
// Week 1 invariant: handlers log the step, sleep 100ms, emit a
// placeholder result. No LLM calls. No hardcoded prompts (all
// handlers fetch their prompt body via internal/thinking/prompts).
package processors

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
	tkafka "github.com/kamir/m3c-tools/internal/thinking/kafka"
	"github.com/kamir/m3c-tools/internal/thinking/orchestrator"
	"github.com/kamir/m3c-tools/internal/thinking/prompts"
	"github.com/kamir/m3c-tools/internal/thinking/schema"
)

// Deps is the shared wiring every layer processor needs.
type Deps struct {
	Hash     mctx.Hash
	Bus      tkafka.Bus
	Orc      *orchestrator.Orchestrator
	Prompts  prompts.Registry
	Log      *log.Logger
}

// Processor is the common interface: subscribe to the command topic
// and dispatch matching steps to a layer-specific handler. Call Stop
// to unsubscribe.
type Processor interface {
	Start(ctx context.Context) error
	Stop()
}

// LayerMatcher decides whether a dispatched command belongs to this
// processor.
type LayerMatcher func(schema.Layer) bool

// Handler is a per-strategy stub that produces a side-effect (e.g.
// publishing a Reflection to the reflections topic) and returns an
// opaque result that gets included in the StepCompleted event.
type Handler func(ctx context.Context, deps Deps, cmd schema.ProcessCommand) (map[string]interface{}, error)

// DecodeCommand unmarshals a Kafka message value into a ProcessCommand.
func DecodeCommand(m tkafka.Message) (schema.ProcessCommand, error) {
	var cmd schema.ProcessCommand
	if err := json.Unmarshal(m.Value, &cmd); err != nil {
		return schema.ProcessCommand{}, fmt.Errorf("processors: decode cmd: %w", err)
	}
	return cmd, nil
}

// RunStep is the standard wrapper: emit StepStarted, sleep-stub,
// run handler, emit StepCompleted (or ProcessFailed). Week 1 all
// real handlers are stubs so this wrapper carries the lifecycle
// contract cleanly.
func RunStep(ctx context.Context, deps Deps, cmd schema.ProcessCommand, h Handler) {
	if err := deps.Orc.EmitStepStarted(ctx, cmd.ProcessID, cmd.StepIndex, cmd.Step.Layer); err != nil {
		deps.Log.Printf("processors: emit StepStarted: %v", err)
	}

	// Week 1 stub sleep — represents "the real thing would take time".
	select {
	case <-time.After(100 * time.Millisecond):
	case <-ctx.Done():
		return
	}

	detail, err := h(ctx, deps, cmd)
	if err != nil {
		deps.Log.Printf("processors: step %d (%s/%s) failed: %v",
			cmd.StepIndex, cmd.Step.Layer, cmd.Step.Strategy, err)
		_ = deps.Orc.EmitProcessFailed(ctx, cmd.ProcessID, err.Error())
		return
	}
	if err := deps.Orc.EmitStepCompleted(ctx, cmd.ProcessID, cmd.StepIndex, cmd.Step.Layer, detail); err != nil {
		deps.Log.Printf("processors: emit StepCompleted: %v", err)
	}
}

// UnknownStrategyError returns a uniform error when a processor
// receives a strategy it does not implement.
func UnknownStrategyError(layer schema.Layer, strategy string) error {
	return fmt.Errorf("processors/%s: unknown strategy %q", layer, strategy)
}
