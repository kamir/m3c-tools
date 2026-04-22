// Package a is the Artifact-layer processor.
//
// Week 3 (SPEC-0167 §Stream 3a) replaces the Week-1 stub with real
// LLM-backed handlers that resolve a prompt from the registry,
// run it through the budget-enforced RunLLMStep pipeline, and
// publish a structured Artifact onto m3c.<ctx>.artifacts.created.
//
// Two strategies:
//
//   report  — structured markdown per prompt tmpl.artifact.report.v1
//             content: {title, sections:[{heading, body}], key_points:[]}
//   summary — compact JSON per prompt tmpl.artifact.summary.v1
//             content: {tl_dr, bullets:[], sources:[]}
//
// Both gather I-layer inputs from the command's context.scope.entities
// (written there by the preceding I-step in a semi_linear chain) and
// pass them into the user message so the LLM can cite them.
//
// When the A-step is the last step in the process, the handler calls
// orchestrator.Complete so the store + UI see the artifact id.
//
// Invariant: no hardcoded prompts live here. Every call goes through
// processors.RunLLMStep which enforces AP-06 + D4.
package a

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

// Processor is the A-layer consumer.
type Processor struct {
	deps processors.Deps
	stop func()
}

// New returns an A-processor bound to deps.
func New(deps processors.Deps) *Processor {
	return &Processor{deps: deps}
}

// Strategies exposed by Week 3.
var strategies = map[string]processors.Handler{
	"report":  handleReport,
	"summary": handleSummary,
}

// Start subscribes to the orchestrator's command topic.
func (p *Processor) Start(ctx context.Context) error {
	stop, err := p.deps.Bus.Subscribe(p.deps.Orc.CmdTopic(), func(hctx context.Context, m tkafka.Message) error {
		cmd, err := processors.DecodeCommand(m)
		if err != nil {
			return err
		}
		if cmd.Step.Layer != schema.LayerA {
			return nil
		}
		h, ok := strategies[cmd.Step.Strategy]
		if !ok {
			_ = p.deps.Orc.EmitProcessFailed(ctx, cmd.ProcessID, processors.UnknownStrategyError(schema.LayerA, cmd.Step.Strategy).Error())
			return nil
		}

		// Emit StepStarted, run the handler, emit StepCompleted (or
		// ProcessFailed). We don't call processors.RunStep here because
		// we need the detail map to extract the artifact_id for Complete.
		_ = p.deps.Orc.EmitStepStarted(ctx, cmd.ProcessID, cmd.StepIndex, cmd.Step.Layer)

		detail, err := h(ctx, p.deps, cmd)
		if err != nil {
			_ = p.deps.Orc.EmitProcessFailed(ctx, cmd.ProcessID, err.Error())
			return nil
		}
		_ = p.deps.Orc.EmitStepCompleted(ctx, cmd.ProcessID, cmd.StepIndex, cmd.Step.Layer, detail)

		// Last step — close out the process.
		if cmd.StepIndex == len(cmd.Spec.Steps)-1 {
			var artifactIDs []string
			if id, ok := detail["artifact_id"].(string); ok && id != "" {
				artifactIDs = []string{id}
			}
			_ = p.deps.Orc.Complete(ctx, cmd.ProcessID, artifactIDs)
		}
		return nil
	})
	if err != nil {
		return err
	}
	p.stop = stop
	p.deps.Log.Printf("a-proc: subscribed (strategies: report, summary)")
	return nil
}

// Stop unsubscribes.
func (p *Processor) Stop() {
	if p.stop != nil {
		p.stop()
	}
}

// ----- handlers -----

func handleReport(ctx context.Context, deps processors.Deps, cmd schema.ProcessCommand) (map[string]interface{}, error) {
	return runArtifact(ctx, deps, cmd, schema.FormatReport, "report", parseReportContent)
}

func handleSummary(ctx context.Context, deps processors.Deps, cmd schema.ProcessCommand) (map[string]interface{}, error) {
	return runArtifact(ctx, deps, cmd, schema.FormatSummary, "summary", parseSummaryContent)
}

type contentParser func(raw string) (map[string]interface{}, error)

func runArtifact(ctx context.Context, deps processors.Deps, cmd schema.ProcessCommand, format schema.ArtifactFormat, strName string, parse contentParser) (map[string]interface{}, error) {
	promptID := selectPromptID(cmd, "a", strName)

	insightIDs := insightIDsFromCtx(cmd.Step)
	userInput := renderUserInput(cmd, insightIDs, strName)

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
		return nil, err
	}

	content, err := parse(completion)
	if err != nil {
		return nil, fmt.Errorf("a-proc/%s: parse completion: %w", strName, err)
	}

	if len(insightIDs) == 0 {
		insightIDs = []string{"[engine:no-inputs]"}
	}
	art := schema.Artifact{
		SchemaVer:  schema.CurrentSchemaVer,
		ArtifactID: uuid.NewString(),
		InsightIDs: insightIDs,
		Format:     format,
		Audience:   schema.AudienceHuman,
		Content:    content,
		Version:    1,
		Provenance: schema.ArtifactProvenance{
			// Week 3 scaffold: the engine doesn't yet have a cross-layer
			// closure walker; Stream 3b's trace walker will reconcile
			// these from Kafka. For now we pass the insight_ids through
			// as i_ids and leave t_ids / r_ids empty slices (schema
			// accepts empty arrays).
			TIDs: []string{},
			RIDs: []string{},
			IIDs: insightIDs,
		},
		Timestamp: time.Now().UTC(),
		ProcessID: cmd.ProcessID,
	}

	// Carry the trace fields out in the return detail (so StepCompleted
	// events can surface model/prompt/token accounting to the UI).
	topic := tkafka.TopicName(deps.Hash, tkafka.TopicArtifactsCreated)
	if err := deps.Bus.Produce(ctx, topic, art.ArtifactID, art); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"artifact_id": art.ArtifactID,
		"format":      string(format),
		"prompt_id":   trace.PromptID,
		"model":       trace.Model,
		"tokens_in":   trace.Tokens.In,
		"tokens_out":  trace.Tokens.Out,
	}, nil
}

// selectPromptID returns step-level override if set, else the
// production "tmpl.artifact.<strategy>.v1" id.
func selectPromptID(cmd schema.ProcessCommand, layer, strategy string) string {
	if cmd.Step.PromptID != nil && *cmd.Step.PromptID != "" {
		return *cmd.Step.PromptID
	}
	return prompts.StrategyPromptID(layer, strategy)
}

// insightIDsFromCtx pulls the I-layer input ids passed in from the
// preceding I-step. In Week 3 these come via context.scope.entities;
// a later stream will wire them through a cleaner channel.
func insightIDsFromCtx(step schema.Step) []string {
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
	b.WriteString("Format: ")
	b.WriteString(strName)
	b.WriteString("\n\n")
	if len(ids) > 0 {
		b.WriteString("Insight refs:\n")
		for _, id := range ids {
			b.WriteString("- ")
			b.WriteString(id)
			b.WriteString("\n")
		}
	}
	return b.String()
}

// parseReportContent shape: {title, sections:[{heading, body}], key_points:[]}.
// The first section's body must be non-empty — the engine's acceptance
// criterion asserts that.
func parseReportContent(raw string) (map[string]interface{}, error) {
	var obj struct {
		Title     string   `json:"title"`
		Sections  []struct {
			Heading string `json:"heading"`
			Body    string `json:"body"`
		} `json:"sections"`
		KeyPoints []string `json:"key_points"`
	}
	clean := stripCodeFence(raw)
	if err := json.Unmarshal([]byte(clean), &obj); err != nil {
		return nil, fmt.Errorf("report: non-json output: %w", err)
	}
	if obj.Title == "" {
		return nil, fmt.Errorf("report: missing title field")
	}
	if len(obj.Sections) == 0 {
		return nil, fmt.Errorf("report: sections array must be non-empty")
	}
	if strings.TrimSpace(obj.Sections[0].Body) == "" {
		return nil, fmt.Errorf("report: sections[0].body must be non-empty")
	}
	if obj.KeyPoints == nil {
		obj.KeyPoints = []string{}
	}
	sections := make([]map[string]interface{}, 0, len(obj.Sections))
	for _, s := range obj.Sections {
		sections = append(sections, map[string]interface{}{
			"heading": s.Heading,
			"body":    s.Body,
		})
	}
	return map[string]interface{}{
		"title":      obj.Title,
		"sections":   sections,
		"key_points": obj.KeyPoints,
	}, nil
}

// parseSummaryContent shape: {tl_dr, bullets:[], sources:[]}.
func parseSummaryContent(raw string) (map[string]interface{}, error) {
	var obj struct {
		TLDR    string   `json:"tl_dr"`
		Bullets []string `json:"bullets"`
		Sources []string `json:"sources"`
	}
	clean := stripCodeFence(raw)
	if err := json.Unmarshal([]byte(clean), &obj); err != nil {
		return nil, fmt.Errorf("summary: non-json output: %w", err)
	}
	if strings.TrimSpace(obj.TLDR) == "" {
		return nil, fmt.Errorf("summary: missing tl_dr field")
	}
	if obj.Bullets == nil {
		obj.Bullets = []string{}
	}
	if obj.Sources == nil {
		obj.Sources = []string{}
	}
	return map[string]interface{}{
		"tl_dr":   obj.TLDR,
		"bullets": obj.Bullets,
		"sources": obj.Sources,
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
