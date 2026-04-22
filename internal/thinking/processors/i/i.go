// Package i is the Insight-layer processor. Week 1 strategies:
// pattern, contradiction.
package i

import (
	"context"
	"time"

	"github.com/google/uuid"
	tkafka "github.com/kamir/m3c-tools/internal/thinking/kafka"
	"github.com/kamir/m3c-tools/internal/thinking/processors"
	"github.com/kamir/m3c-tools/internal/thinking/prompts"
	"github.com/kamir/m3c-tools/internal/thinking/schema"
)

type Processor struct {
	deps processors.Deps
	stop func()
}

func New(deps processors.Deps) *Processor {
	return &Processor{deps: deps}
}

var strategies = map[string]processors.Handler{
	"pattern":       handlePattern,
	"contradiction": handleContradiction,
}

func (p *Processor) Start(ctx context.Context) error {
	stop, err := p.deps.Bus.Subscribe(p.deps.Orc.CmdTopic(), func(hctx context.Context, m tkafka.Message) error {
		cmd, err := processors.DecodeCommand(m)
		if err != nil {
			return err
		}
		if cmd.Step.Layer != schema.LayerI {
			return nil
		}
		h, ok := strategies[cmd.Step.Strategy]
		if !ok {
			_ = p.deps.Orc.EmitProcessFailed(ctx, cmd.ProcessID, processors.UnknownStrategyError(schema.LayerI, cmd.Step.Strategy).Error())
			return nil
		}
		processors.RunStep(ctx, p.deps, cmd, h)
		return nil
	})
	if err != nil {
		return err
	}
	p.stop = stop
	p.deps.Log.Printf("i-proc: subscribed (strategies: pattern, contradiction)")
	return nil
}

func (p *Processor) Stop() {
	if p.stop != nil {
		p.stop()
	}
}

func handlePattern(ctx context.Context, deps processors.Deps, cmd schema.ProcessCommand) (map[string]interface{}, error) {
	return emitInsight(ctx, deps, cmd, schema.SynthesisPattern, "pattern")
}
func handleContradiction(ctx context.Context, deps processors.Deps, cmd schema.ProcessCommand) (map[string]interface{}, error) {
	return emitInsight(ctx, deps, cmd, schema.SynthesisContradiction, "contradiction")
}

func emitInsight(ctx context.Context, deps processors.Deps, cmd schema.ProcessCommand, mode schema.SynthesisMode, strName string) (map[string]interface{}, error) {
	promptID := prompts.DefaultStrategyPromptID("i", strName)
	p, err := deps.Prompts.Get(ctx, promptID)
	if err != nil {
		return nil, err
	}
	ins := schema.Insight{
		SchemaVer:     schema.CurrentSchemaVer,
		InsightID:     uuid.NewString(),
		InputIDs:      []string{"[stub]"},
		SynthesisMode: mode,
		Content: map[string]interface{}{
			"note":   "[stub] " + strName + " insight",
			"prompt": p.Body,
		},
		Confidence: 0.5,
		Trace: schema.Trace{
			PromptID:      p.ID,
			PromptVersion: p.Version,
			Model:         p.Model,
			DurationMS:    100,
		},
		Timestamp: time.Now().UTC(),
		ProcessID: cmd.ProcessID,
	}
	topic := tkafka.TopicName(deps.Hash, tkafka.TopicInsightsGenerated)
	if err := deps.Bus.Produce(ctx, topic, ins.InsightID, ins); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"insight_id": ins.InsightID,
		"mode":       strName,
	}, nil
}
