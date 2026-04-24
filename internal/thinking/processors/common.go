// Package processors provides the R/I/A/C cognitive-layer
// processors. Each sub-package is a Kafka consumer+producer with a
// strategy-dispatch map.
//
// Week 2: handlers are real — they resolve a prompt from the
// registry (AP-06), enforce D4 budget caps, call an LLM adapter,
// parse the structured completion, and publish a typed message.
package processors

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/kamir/m3c-tools/internal/thinking/budget"
	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
	tkafka "github.com/kamir/m3c-tools/internal/thinking/kafka"
	"github.com/kamir/m3c-tools/internal/thinking/llm"
	"github.com/kamir/m3c-tools/internal/thinking/observability"
	"github.com/kamir/m3c-tools/internal/thinking/orchestrator"
	"github.com/kamir/m3c-tools/internal/thinking/prompts"
	"github.com/kamir/m3c-tools/internal/thinking/schema"
)

// Deps is the shared wiring every layer processor needs.
//
// Week 2 additions (SPEC-0167 D1, D4):
//   - LLM: provider-agnostic completion adapter. Required for real R/I handlers.
//   - Budgets: factory that returns a per-process budget Controller.
type Deps struct {
	Hash    mctx.Hash
	Bus     tkafka.Bus
	Orc     *orchestrator.Orchestrator
	Prompts prompts.Registry
	Log     *log.Logger

	// Week 2 additions. Nil-safe: handlers that require LLM/budget
	// will fail cleanly if unset.
	LLM     llm.Adapter
	Budgets func(processID string, spec schema.ProcessSpec) *budget.Controller

	// Metrics is the optional observability surface. Nil is safe —
	// every call site guards on nil so processors remain usable in
	// tests without an active Prometheus registry.
	Metrics observability.Metrics
}

// Processor is the common interface: subscribe to the command topic
// and dispatch matching steps to a layer-specific handler.
type Processor interface {
	Start(ctx context.Context) error
	Stop()
}

// LayerMatcher decides whether a dispatched command belongs to this processor.
type LayerMatcher func(schema.Layer) bool

// Handler is a per-strategy handler that produces a side-effect (e.g.
// publishing a Reflection) and returns an opaque result that gets
// included in the StepCompleted event.
type Handler func(ctx context.Context, deps Deps, cmd schema.ProcessCommand) (map[string]interface{}, error)

// DecodeCommand unmarshals a Kafka message value into a ProcessCommand.
func DecodeCommand(m tkafka.Message) (schema.ProcessCommand, error) {
	var cmd schema.ProcessCommand
	if err := json.Unmarshal(m.Value, &cmd); err != nil {
		return schema.ProcessCommand{}, fmt.Errorf("processors: decode cmd: %w", err)
	}
	return cmd, nil
}

// RunStep is the standard wrapper: emit StepStarted, run handler,
// emit StepCompleted (or ProcessFailed).
func RunStep(ctx context.Context, deps Deps, cmd schema.ProcessCommand, h Handler) {
	if err := deps.Orc.EmitStepStarted(ctx, cmd.ProcessID, cmd.StepIndex, cmd.Step.Layer); err != nil {
		deps.Log.Printf("processors: emit StepStarted: %v", err)
	}

	select {
	case <-time.After(10 * time.Millisecond):
	case <-ctx.Done():
		return
	}

	detail, err := h(ctx, deps, cmd)
	if err != nil {
		deps.Log.Printf("processors: step %d (%s/%s) failed: %v",
			cmd.StepIndex, cmd.Step.Layer, cmd.Step.Strategy, err)
		if deps.Metrics != nil {
			deps.Metrics.RecordStepFailure(string(cmd.Step.Layer), cmd.Step.Strategy, classifyErrReason(err))
			deps.Metrics.RecordProcessFailure(string(cmd.Spec.Mode))
		}
		_ = deps.Orc.EmitProcessFailed(ctx, cmd.ProcessID, err.Error())
		return
	}
	if err := deps.Orc.EmitStepCompleted(ctx, cmd.ProcessID, cmd.StepIndex, cmd.Step.Layer, detail); err != nil {
		deps.Log.Printf("processors: emit StepCompleted: %v", err)
	}
}

// classifyErrReason maps a handler error to a short, low-cardinality
// reason tag for the step_failures_total counter. Arbitrary error
// messages carry unbounded cardinality and would blow up Prometheus
// storage; we collapse them to a handful of stable bucket labels.
func classifyErrReason(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	switch {
	case containsAny(msg, "budget"):
		return "budget"
	case containsAny(msg, "llm:", "llm/"):
		return "llm"
	case containsAny(msg, "unknown strategy"):
		return "unknown_strategy"
	case containsAny(msg, "prompt"):
		return "prompt"
	case containsAny(msg, "parse completion", "non-json output"):
		return "parse"
	case containsAny(msg, "schema"):
		return "schema"
	}
	return "other"
}

func containsAny(s string, needles ...string) bool {
	for _, n := range needles {
		if indexOfSub(s, n) >= 0 {
			return true
		}
	}
	return false
}

// UnknownStrategyError returns a uniform error when a processor
// receives a strategy it does not implement.
func UnknownStrategyError(layer schema.Layer, strategy string) error {
	return fmt.Errorf("processors/%s: unknown strategy %q", layer, strategy)
}

// LLMCallOpts carries the per-call overrides a handler needs.
type LLMCallOpts struct {
	PromptID    string
	Model       string
	Input       string
	Vars        map[string]string
	Temperature float32
	Format      string
	MaxTokens   int
}

// RunLLMStep resolves the prompt via the registry, enforces budget,
// calls the LLM adapter, and returns completion + populated Trace.
//
// Invariant: budget is enforced BEFORE dispatching to the LLM.
// Invariant: prompt body always comes from the registry (AP-06).
func RunLLMStep(ctx context.Context, deps Deps, cmd schema.ProcessCommand, opts LLMCallOpts) (string, schema.Trace, error) {
	if deps.LLM == nil {
		return "", schema.Trace{}, fmt.Errorf("processors: LLM adapter not configured")
	}
	if opts.PromptID == "" {
		return "", schema.Trace{}, fmt.Errorf("processors: LLMCallOpts.PromptID required")
	}

	p, err := deps.Prompts.Get(ctx, opts.PromptID)
	if err != nil {
		return "", schema.Trace{}, fmt.Errorf("processors: resolve prompt %q: %w", opts.PromptID, err)
	}

	systemBody := applyVars(p.Body, opts.Vars)
	messages := []llm.Message{{Role: "system", Content: systemBody}}
	if opts.Input != "" {
		messages = append(messages, llm.Message{Role: "user", Content: opts.Input})
	}

	model := opts.Model
	if model == "" {
		model = p.Model
	}
	req := llm.Request{
		Model:       model,
		Messages:    messages,
		MaxTokens:   opts.MaxTokens,
		Temperature: opts.Temperature,
		Format:      opts.Format,
	}

	// D4 budget enforcement — estimate before dispatch. Tag the spend
	// with (layer, strategy) so /v1/budget/today can surface top
	// consumers (PLAN-0168 P1).
	if deps.Budgets != nil {
		ctrl := deps.Budgets(cmd.ProcessID, cmd.Spec)
		if ctrl != nil {
			tokens, _ := deps.LLM.EstimateCost(req)
			if err := ctrl.ReserveTagged(
				p.ID, model,
				string(cmd.Step.Layer), cmd.Step.Strategy,
				tokens/2,
			); err != nil {
				return "", schema.Trace{}, fmt.Errorf("processors: budget: %w", err)
			}
		}
	}

	resp, err := deps.LLM.Complete(ctx, req)
	if err != nil {
		return "", schema.Trace{}, fmt.Errorf("processors: llm: %w", err)
	}

	if deps.Metrics != nil {
		deps.Metrics.RecordLLMCall(
			resp.Model,
			string(cmd.Step.Layer),
			cmd.Step.Strategy,
			resp.TokensIn,
			resp.TokensOut,
			time.Duration(resp.DurationMS)*time.Millisecond,
		)
	}

	trace := schema.Trace{
		PromptID:      p.ID,
		PromptVersion: p.Version,
		Model:         resp.Model,
		Tokens:        schema.Tokens{In: resp.TokensIn, Out: resp.TokensOut},
		DurationMS:    resp.DurationMS,
		CostUSD:       resp.CostUSD,
	}
	return resp.Content, trace, nil
}

func applyVars(body string, vars map[string]string) string {
	if len(vars) == 0 {
		return body
	}
	out := body
	for k, v := range vars {
		out = replaceAllLiteral(out, "{{"+k+"}}", v)
	}
	return out
}

func replaceAllLiteral(s, old, new string) string {
	for {
		i := indexOfSub(s, old)
		if i < 0 {
			return s
		}
		s = s[:i] + new + s[i+len(old):]
	}
}

func indexOfSub(s, sub string) int {
	n, m := len(s), len(sub)
	if m == 0 || m > n {
		return -1
	}
	for i := 0; i+m <= n; i++ {
		if s[i:i+m] == sub {
			return i
		}
	}
	return -1
}
