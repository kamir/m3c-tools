// Package i is the Insight-layer processor. Week 2 strategies:
// pattern, contradiction.
//
// Both strategies fetch a registry-hosted prompt, call the LLM
// with JSON-mode, and publish an Insight whose .content is
// strategy-specific:
//
//   pattern:       {"pattern": "...", "occurrences": [...], "confidence": float}
//   contradiction: {"claim_a": "...", "claim_b": "...",
//                   "evidence_refs": [...], "severity": "low|medium|high"}
//
// Extra behaviour: contradiction also emits a follow-up Thought of
// type=question onto m3c.<ctx>.thoughts.raw, wiring Phase 2's
// feedback loop. The consumer side of that loop lands Week 3.
package i

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

// ----- handlers -----

func handlePattern(ctx context.Context, deps processors.Deps, cmd schema.ProcessCommand) (map[string]interface{}, error) {
	content, trace, inputs, err := runInsight(ctx, deps, cmd, "pattern", parsePatternContent)
	if err != nil {
		return nil, err
	}
	return emitInsight(ctx, deps, cmd, schema.SynthesisPattern, inputs, content, trace, "pattern", contentConfidence(content))
}

func handleContradiction(ctx context.Context, deps processors.Deps, cmd schema.ProcessCommand) (map[string]interface{}, error) {
	content, trace, inputs, err := runInsight(ctx, deps, cmd, "contradiction", parseContradictionContent)
	if err != nil {
		return nil, err
	}
	detail, err := emitInsight(ctx, deps, cmd, schema.SynthesisContradiction, inputs, content, trace, "contradiction", severityToConfidence(content))
	if err != nil {
		return nil, err
	}

	// Feedback loop (SPEC-0167 Phase 2 scaffold): emit a follow-up T
	// of type=question. Consumer wiring lands Week 3.
	if err := emitFollowupQuestion(ctx, deps, cmd, content); err != nil {
		deps.Log.Printf("i-proc/contradiction: follow-up question failed: %v", err)
	}
	return detail, nil
}

type contentParser func(raw string) (map[string]interface{}, error)

func runInsight(ctx context.Context, deps processors.Deps, cmd schema.ProcessCommand, strName string, parse contentParser) (map[string]interface{}, schema.Trace, []string, error) {
	promptID := selectPromptID(cmd, "i", strName)

	inputs := inputIDsFromCtx(cmd.Step)
	userInput := renderUserInput(cmd, inputs, strName)

	vars := map[string]string{
		"intent":   cmd.Spec.Intent,
		"strategy": strName,
		"ctx":      deps.Hash.Hex(),
	}

	completion, trace, err := processors.RunLLMStep(ctx, deps, cmd, processors.LLMCallOpts{
		PromptID:    promptID,
		Input:       userInput,
		Vars:        vars,
		Format:      "json",
		Temperature: 0,
	})
	if err != nil {
		return nil, schema.Trace{}, nil, err
	}
	content, err := parse(completion)
	if err != nil {
		return nil, schema.Trace{}, nil, fmt.Errorf("i-proc/%s: parse completion: %w", strName, err)
	}
	return content, trace, inputs, nil
}

func emitInsight(ctx context.Context, deps processors.Deps, cmd schema.ProcessCommand, mode schema.SynthesisMode, inputs []string, content map[string]interface{}, trace schema.Trace, strName string, confidence float64) (map[string]interface{}, error) {
	if len(inputs) == 0 {
		inputs = []string{"[engine:no-inputs]"}
	}
	ins := schema.Insight{
		SchemaVer:     schema.CurrentSchemaVer,
		InsightID:     uuid.NewString(),
		InputIDs:      inputs,
		SynthesisMode: mode,
		Content:       content,
		Confidence:    confidence,
		Trace:         trace,
		Timestamp:     time.Now().UTC(),
		ProcessID:     cmd.ProcessID,
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

// emitFollowupQuestion publishes a new Thought onto thoughts.raw of
// type=question, carrying the two contradicting claims.
func emitFollowupQuestion(ctx context.Context, deps processors.Deps, cmd schema.ProcessCommand, insightContent map[string]interface{}) error {
	claimA, _ := insightContent["claim_a"].(string)
	claimB, _ := insightContent["claim_b"].(string)
	text := "Which of these is true? \n  A: " + claimA + "\n  B: " + claimB
	t := schema.Thought{
		SchemaVer: schema.CurrentSchemaVer,
		ThoughtID: uuid.NewString(),
		Type:      schema.ThoughtQuestion,
		Content:   schema.Content{Text: text},
		Source: schema.Source{
			Kind: schema.SourceAgent,
			Ref:  "thinking-engine/i-proc/contradiction",
		},
		Tags:      []string{"feedback", "contradiction"},
		Timestamp: time.Now().UTC(),
		Provenance: &schema.Provenance{
			CapturedBy: "thinking-engine/i-proc",
		},
	}
	topic := tkafka.TopicName(deps.Hash, tkafka.TopicThoughtsRaw)
	return deps.Bus.Produce(ctx, topic, t.ThoughtID, t)
}

// ----- shared helpers -----

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

// ----- content parsers -----

func parsePatternContent(raw string) (map[string]interface{}, error) {
	var obj struct {
		Pattern     string      `json:"pattern"`
		Occurrences interface{} `json:"occurrences"`
		Confidence  float64     `json:"confidence"`
	}
	clean := stripCodeFence(raw)
	if err := json.Unmarshal([]byte(clean), &obj); err != nil {
		return nil, fmt.Errorf("pattern: non-json output: %w", err)
	}
	if obj.Pattern == "" {
		return nil, fmt.Errorf("pattern: missing pattern field")
	}
	if obj.Occurrences == nil {
		obj.Occurrences = []interface{}{}
	}
	return map[string]interface{}{
		"pattern":     obj.Pattern,
		"occurrences": obj.Occurrences,
		"confidence":  obj.Confidence,
	}, nil
}

func parseContradictionContent(raw string) (map[string]interface{}, error) {
	var obj struct {
		ClaimA       string   `json:"claim_a"`
		ClaimB       string   `json:"claim_b"`
		EvidenceRefs []string `json:"evidence_refs"`
		Severity     string   `json:"severity"`
	}
	clean := stripCodeFence(raw)
	if err := json.Unmarshal([]byte(clean), &obj); err != nil {
		return nil, fmt.Errorf("contradiction: non-json output: %w", err)
	}
	if obj.ClaimA == "" || obj.ClaimB == "" {
		return nil, fmt.Errorf("contradiction: claim_a and claim_b required")
	}
	if obj.EvidenceRefs == nil {
		obj.EvidenceRefs = []string{}
	}
	if obj.Severity == "" {
		obj.Severity = "medium"
	}
	return map[string]interface{}{
		"claim_a":       obj.ClaimA,
		"claim_b":       obj.ClaimB,
		"evidence_refs": obj.EvidenceRefs,
		"severity":      obj.Severity,
	}, nil
}

func contentConfidence(content map[string]interface{}) float64 {
	if v, ok := content["confidence"].(float64); ok {
		if v < 0 {
			return 0
		}
		if v > 1 {
			return 1
		}
		return v
	}
	return 0.5
}

func severityToConfidence(content map[string]interface{}) float64 {
	sev, _ := content["severity"].(string)
	switch strings.ToLower(sev) {
	case "high":
		return 0.9
	case "medium", "med":
		return 0.7
	case "low":
		return 0.4
	}
	return 0.5
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
