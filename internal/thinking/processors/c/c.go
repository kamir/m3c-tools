// Package c is the Compilation-layer processor. Week 1 strategies:
// summarize. Runs off scheduled triggers or explicit /v1/compile
// calls. Handlers are stubs.
package c

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
	"summarize": handleSummarize,
}

func (p *Processor) Start(ctx context.Context) error {
	stop, err := p.deps.Bus.Subscribe(p.deps.Orc.CmdTopic(), func(hctx context.Context, m tkafka.Message) error {
		cmd, err := processors.DecodeCommand(m)
		if err != nil {
			return err
		}
		if cmd.Step.Layer != schema.LayerC {
			return nil
		}
		h, ok := strategies[cmd.Step.Strategy]
		if !ok {
			_ = p.deps.Orc.EmitProcessFailed(ctx, cmd.ProcessID, processors.UnknownStrategyError(schema.LayerC, cmd.Step.Strategy).Error())
			return nil
		}
		processors.RunStep(ctx, p.deps, cmd, h)
		return nil
	})
	if err != nil {
		return err
	}
	p.stop = stop
	p.deps.Log.Printf("c-proc: subscribed (strategies: summarize)")
	return nil
}

func (p *Processor) Stop() {
	if p.stop != nil {
		p.stop()
	}
}

func handleSummarize(ctx context.Context, deps processors.Deps, cmd schema.ProcessCommand) (map[string]interface{}, error) {
	promptID := prompts.DefaultStrategyPromptID("c", "summarize")
	pm, err := deps.Prompts.Get(ctx, promptID)
	if err != nil {
		return nil, err
	}
	// C writes a "compilation artifact" in Week 1 — modeled as an
	// Artifact with format=summary, audience=system. Real C-proc
	// will land a distinct compilation message type in Phase 2.
	art := schema.Artifact{
		SchemaVer:  schema.CurrentSchemaVer,
		ArtifactID: uuid.NewString(),
		InsightIDs: []string{"[stub]"},
		Format:     schema.FormatSummary,
		Audience:   schema.AudienceSystem,
		Content: map[string]interface{}{
			"note":   "[stub] compilation rollup",
			"prompt": pm.Body,
		},
		Version: 1,
		Provenance: schema.ArtifactProvenance{
			TIDs: []string{"[stub]"},
			RIDs: []string{"[stub]"},
			IIDs: []string{"[stub]"},
		},
		Timestamp: time.Now().UTC(),
		ProcessID: cmd.ProcessID,
	}
	topic := tkafka.TopicName(deps.Hash, tkafka.TopicArtifactsCreated)
	if err := deps.Bus.Produce(ctx, topic, art.ArtifactID, art); err != nil {
		return nil, err
	}
	return map[string]interface{}{"compilation_artifact_id": art.ArtifactID}, nil
}
