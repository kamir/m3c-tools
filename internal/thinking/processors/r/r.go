// Package r is the Reflection-layer processor. Week 2 strategies:
// compare, classify.
//
// Both strategies resolve a prompt_id from the registry (AP-06),
// call the LLM adapter with JSON-formatted output, and publish a
// Reflection carrying a strategy-specific structured content:
//
//   compare:  {"similarities": [...], "differences": [...]}
//   classify: {"classification": "...", "confidence": float, "rationale": "..."}
//
// No hardcoded prompts live here.
package r

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
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

// Strategies exposed by Week 2 (compare, classify) + Week 3 (clarify).
var strategies = map[string]processors.Handler{
	"compare":  handleCompare,
	"classify": handleClassify,
	"clarify":  handleClarify,
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
	p.deps.Log.Printf("r-proc: subscribed (strategies: compare, classify, clarify)")
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
	return runReflection(ctx, deps, cmd, schema.StrategyCompare, "compare", parseCompareContent)
}

func handleClassify(ctx context.Context, deps processors.Deps, cmd schema.ProcessCommand) (map[string]interface{}, error) {
	return runReflection(ctx, deps, cmd, schema.StrategyClassify, "classify", parseClassifyContent)
}

// handleClarify is the Week-3 feedback-loop strategy. It takes the
// triggering question thought and expands it into an explicit
// reformulation + list of sub-questions. Output shape:
//
//	{"question": "...", "sub_questions": [...], "context": "..."}
func handleClarify(ctx context.Context, deps processors.Deps, cmd schema.ProcessCommand) (map[string]interface{}, error) {
	return runReflection(ctx, deps, cmd, schema.StrategyClarify, "clarify", parseClarifyContent)
}

type contentParser func(raw string) (map[string]interface{}, error)

func runReflection(ctx context.Context, deps processors.Deps, cmd schema.ProcessCommand, strat schema.ReflectionStrategy, strName string, parse contentParser) (map[string]interface{}, error) {
	promptID := selectPromptID(cmd, "r", strName)

	thoughtIDs := inputIDsFromCtx(cmd.Step)
	userInput := renderUserInput(cmd, thoughtIDs, strName)

	vars := map[string]string{
		"intent":   cmd.Spec.Intent,
		"strategy": strName,
		"ctx":      deps.Hash.Hex(),
	}
	if cmd.Step.Context != nil && cmd.Step.Context.Filters != nil {
		vars["taxonomy"] = strings.Join(cmd.Step.Context.Filters.Tags, ", ")
	}

	completion, trace, err := processors.RunLLMStep(ctx, deps, cmd, processors.LLMCallOpts{
		PromptID:    promptID,
		Input:       userInput,
		Vars:        vars,
		Format:      "json",
		Temperature: 0,
	})
	if err != nil {
		return nil, err
	}

	content, err := parse(completion)
	if err != nil {
		return nil, fmt.Errorf("r-proc/%s: parse completion: %w", strName, err)
	}

	if len(thoughtIDs) == 0 {
		thoughtIDs = []string{"[engine:no-inputs]"}
	}
	ref := schema.Reflection{
		SchemaVer:    schema.CurrentSchemaVer,
		ReflectionID: uuid.NewString(),
		ThoughtIDs:   thoughtIDs,
		Strategy:     strat,
		Objective:    cmd.Spec.Intent,
		Content:      content,
		Trace:        trace,
		Timestamp:    time.Now().UTC(),
		ProcessID:    cmd.ProcessID,
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

// selectPromptID returns step-level override if set, else the
// production "tmpl.reflect.<strategy>.v1" id.
func selectPromptID(cmd schema.ProcessCommand, layer, strategy string) string {
	if cmd.Step.PromptID != nil && *cmd.Step.PromptID != "" {
		return *cmd.Step.PromptID
	}
	return prompts.StrategyPromptID(layer, strategy)
}

func inputIDsFromCtx(step schema.Step) []string {
	if step.Context == nil || step.Context.Scope == nil {
		return nil
	}
	return append([]string(nil), step.Context.Scope.Entities...)
}

func renderUserInput(cmd schema.ProcessCommand, ids []string, strName string) string {
	var b strings.Builder
	b.WriteString("Intent: ")
	b.WriteString(cmd.Spec.Intent)
	b.WriteString("\n\n")
	b.WriteString("Strategy: ")
	b.WriteString(strName)
	b.WriteString("\n\n")
	if len(ids) > 0 {
		b.WriteString("Input refs:\n")
		for _, id := range ids {
			b.WriteString("- ")
			b.WriteString(id)
			b.WriteString("\n")
		}
	}
	return b.String()
}

func parseCompareContent(raw string) (map[string]interface{}, error) {
	var obj struct {
		Similarities []string `json:"similarities"`
		Differences  []string `json:"differences"`
	}
	clean := stripCodeFence(raw)
	if err := json.Unmarshal([]byte(clean), &obj); err != nil {
		return nil, fmt.Errorf("compare: non-json output: %w", err)
	}
	if obj.Similarities == nil {
		obj.Similarities = []string{}
	}
	if obj.Differences == nil {
		obj.Differences = []string{}
	}
	return map[string]interface{}{
		"similarities": obj.Similarities,
		"differences":  obj.Differences,
	}, nil
}

func parseClarifyContent(raw string) (map[string]interface{}, error) {
	var obj struct {
		Question     string   `json:"question"`
		SubQuestions []string `json:"sub_questions"`
		Context      string   `json:"context"`
	}
	clean := stripCodeFence(raw)
	if err := json.Unmarshal([]byte(clean), &obj); err != nil {
		return nil, fmt.Errorf("clarify: non-json output: %w", err)
	}
	if strings.TrimSpace(obj.Question) == "" {
		return nil, fmt.Errorf("clarify: missing question field")
	}
	if obj.SubQuestions == nil {
		obj.SubQuestions = []string{}
	}
	return map[string]interface{}{
		"question":      obj.Question,
		"sub_questions": obj.SubQuestions,
		"context":       obj.Context,
	}, nil
}

func parseClassifyContent(raw string) (map[string]interface{}, error) {
	var obj struct {
		Classification string  `json:"classification"`
		Confidence     float64 `json:"confidence"`
		Rationale      string  `json:"rationale"`
	}
	clean := stripCodeFence(raw)
	if err := json.Unmarshal([]byte(clean), &obj); err != nil {
		return nil, fmt.Errorf("classify: non-json output: %w", err)
	}
	if obj.Classification == "" {
		return nil, fmt.Errorf("classify: missing classification field")
	}
	return map[string]interface{}{
		"classification": obj.Classification,
		"confidence":     obj.Confidence,
		"rationale":      obj.Rationale,
	}, nil
}

func stripCodeFence(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```") {
		s = strings.TrimPrefix(s, "```json")
		s = strings.TrimPrefix(s, "```JSON")
		s = strings.TrimPrefix(s, "```")
		s = strings.TrimSpace(s)
	}
	if strings.HasSuffix(s, "```") {
		s = strings.TrimSuffix(s, "```")
		s = strings.TrimSpace(s)
	}
	return s
}
