// Package r is the Reflection-layer processor. Week 1 strategies:
// compare, classify. Real prompt bodies live in the prompt registry
// (AP-06). Handlers here are stubs — they log, sleep, emit a
// placeholder Reflection.
package r

import (
	"context"
	"time"

	"github.com/google/uuid"
	tkafka "github.com/kamir/m3c-tools/internal/thinking/kafka"
	"github.com/kamir/m3c-tools/internal/thinking/processors"
	"github.com/kamir/m3c-tools/internal/thinking/prompts"
	"github.com/kamir/m3c-tools/internal/thinking/schema"
)

// Processor is the R-layer consumer.
type Processor struct {
	deps   processors.Deps
	stop   func()
	outTop string
}

// New returns an R-processor bound to deps.
func New(deps processors.Deps) *Processor {
	return &Processor{
		deps:   deps,
		outTop: tkafka.TopicName(deps.Hash, tkafka.TopicReflectionsGenerated),
	}
}

// Strategies exposed by Week 1.
var strategies = map[string]processors.Handler{
	"compare":  handleCompare,
	"classify": handleClassify,
}

// Start subscribes to the orchestrator's command topic.
func (p *Processor) Start(ctx context.Context) error {
	stop, err := p.deps.Bus.Subscribe(p.deps.Orc.CmdTopic(), func(hctx context.Context, m tkafka.Message) error {
		cmd, err := processors.DecodeCommand(m)
		if err != nil {
			return err
		}
		if cmd.Step.Layer != schema.LayerR {
			return nil
		}
		h, ok := strategies[cmd.Step.Strategy]
		if !ok {
			_ = p.deps.Orc.EmitProcessFailed(ctx, cmd.ProcessID, processors.UnknownStrategyError(schema.LayerR, cmd.Step.Strategy).Error())
			return nil
		}
		processors.RunStep(ctx, p.deps, cmd, h)
		return nil
	})
	if err != nil {
		return err
	}
	p.stop = stop
	p.deps.Log.Printf("r-proc: subscribed (strategies: compare, classify)")
	return nil
}

// Stop unsubscribes.
func (p *Processor) Stop() {
	if p.stop != nil {
		p.stop()
	}
}

// ----- handlers -----

func handleCompare(ctx context.Context, deps processors.Deps, cmd schema.ProcessCommand) (map[string]interface{}, error) {
	return emitReflection(ctx, deps, cmd, schema.StrategyCompare, "compare")
}

func handleClassify(ctx context.Context, deps processors.Deps, cmd schema.ProcessCommand) (map[string]interface{}, error) {
	return emitReflection(ctx, deps, cmd, schema.StrategyClassify, "classify")
}

func emitReflection(ctx context.Context, deps processors.Deps, cmd schema.ProcessCommand, strat schema.ReflectionStrategy, strName string) (map[string]interface{}, error) {
	promptID := prompts.DefaultStrategyPromptID("r", strName)
	// Even in stub form, we MUST resolve the prompt via the registry
	// (AP-06 no-hardcoded-prompts rule).
	p, err := deps.Prompts.Get(ctx, promptID)
	if err != nil {
		return nil, err
	}
	ref := schema.Reflection{
		SchemaVer:    schema.CurrentSchemaVer,
		ReflectionID: uuid.NewString(),
		ThoughtIDs:   []string{"[stub]"},
		Strategy:     strat,
		Objective:    cmd.Spec.Intent,
		Content: map[string]interface{}{
			"note":     "[stub] " + strName + " reflection",
			"prompt":   p.Body,
			"ctx_hash": deps.Hash.Hex(),
		},
		Trace: schema.Trace{
			PromptID:      p.ID,
			PromptVersion: p.Version,
			Model:         p.Model,
			Tokens:        schema.Tokens{In: 0, Out: 0},
			DurationMS:    100,
		},
		Timestamp: time.Now().UTC(),
		ProcessID: cmd.ProcessID,
	}
	topic := tkafka.TopicName(deps.Hash, tkafka.TopicReflectionsGenerated)
	if err := deps.Bus.Produce(ctx, topic, ref.ReflectionID, ref); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"reflection_id": ref.ReflectionID,
		"strategy":      strName,
	}, nil
}
