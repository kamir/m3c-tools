// Package llm provides the Thinking Engine's LLM adapter surface.
//
// SPEC-0167 §Service Components §processors lists "LLM adapter" as a
// per-processor concern. This package centralizes that: R/I/A
// handlers call llm.Adapter.Complete with a rendered prompt, the
// adapter talks to the provider, and returns tokens + USD cost so
// the budget package can account for the call.
//
// Week 2: one real implementation (openai) via
// github.com/sashabaranov/go-openai, plus a MockAdapter used by unit
// + e2e tests. Ollama adapter lands Week 3 via env OLLAMA_URL.
//
// Invariant: NO OTHER PACKAGE in internal/thinking/* imports an LLM
// SDK. All provider interaction goes through llm.Adapter.
package llm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	openai "github.com/sashabaranov/go-openai"
)

// Message is the chat-message unit. Roles mirror the OpenAI chat
// completion API for ease of translation.
type Message struct {
	Role    string // "system" | "user" | "assistant"
	Content string
}

// Request is a single completion request.
type Request struct {
	Model       string    // provider-native model name; empty → adapter default
	Messages    []Message // ordered system/user messages
	MaxTokens   int       // optional upper bound on completion tokens
	Temperature float32   // 0 → deterministic
	Format      string    // "" | "json" — hint to force JSON output where supported
}

// Response is one completion.
type Response struct {
	Content      string
	Model        string  // actual model reported by the provider
	TokensIn     int     // prompt tokens
	TokensOut    int     // completion tokens
	CostUSD      float64 // provider-derived USD cost for this call
	DurationMS   int
}

// Adapter is the common surface every provider implements.
type Adapter interface {
	// Complete issues one chat-style completion and returns the
	// model's reply plus accounting.
	Complete(ctx context.Context, req Request) (Response, error)

	// EstimateCost returns a pre-call estimate for budget gating.
	// Implementations MAY be approximate; the real spend comes back
	// from Complete().
	EstimateCost(req Request) (tokensEst int, costUSD float64)

	// Name returns a stable provider identifier (e.g. "openai",
	// "ollama", "mock") used in traces and logs.
	Name() string
}

// ----- OpenAI adapter -----

// openaiAdapter implements Adapter over the OpenAI chat-completion API.
type openaiAdapter struct {
	client       *openai.Client
	defaultModel string
}

// NewOpenAI builds an adapter using OPENAI_API_KEY + OPENAI_MODEL.
// Returns an error if OPENAI_API_KEY is unset, since the engine must
// refuse to run with a misconfigured LLM path rather than silently
// drop calls.
func NewOpenAI() (Adapter, error) {
	key := strings.TrimSpace(os.Getenv("OPENAI_API_KEY"))
	if key == "" {
		return nil, errors.New("llm: OPENAI_API_KEY is not set")
	}
	model := strings.TrimSpace(os.Getenv("OPENAI_MODEL"))
	if model == "" {
		model = "gpt-4o-mini"
	}
	return &openaiAdapter{
		client:       openai.NewClient(key),
		defaultModel: model,
	}, nil
}

func (a *openaiAdapter) Name() string { return "openai" }

func (a *openaiAdapter) Complete(ctx context.Context, req Request) (Response, error) {
	model := req.Model
	if model == "" {
		model = a.defaultModel
	}
	msgs := make([]openai.ChatCompletionMessage, 0, len(req.Messages))
	for _, m := range req.Messages {
		msgs = append(msgs, openai.ChatCompletionMessage{Role: m.Role, Content: m.Content})
	}
	in := openai.ChatCompletionRequest{
		Model:       model,
		Messages:    msgs,
		MaxTokens:   req.MaxTokens,
		Temperature: req.Temperature,
	}
	if strings.EqualFold(req.Format, "json") {
		in.ResponseFormat = &openai.ChatCompletionResponseFormat{
			Type: openai.ChatCompletionResponseFormatTypeJSONObject,
		}
	}
	start := time.Now()
	out, err := a.client.CreateChatCompletion(ctx, in)
	if err != nil {
		return Response{}, fmt.Errorf("llm/openai: %w", err)
	}
	dur := int(time.Since(start) / time.Millisecond)

	if len(out.Choices) == 0 {
		return Response{}, errors.New("llm/openai: no choices returned")
	}
	body := out.Choices[0].Message.Content
	tokensIn := out.Usage.PromptTokens
	tokensOut := out.Usage.CompletionTokens
	cost := EstimateOpenAICost(out.Model, tokensIn, tokensOut)
	return Response{
		Content:    body,
		Model:      out.Model,
		TokensIn:   tokensIn,
		TokensOut: tokensOut,
		CostUSD:    cost,
		DurationMS: dur,
	}, nil
}

func (a *openaiAdapter) EstimateCost(req Request) (int, float64) {
	// Simple heuristic: ~4 chars per token, assume output ≈ input (bounded by MaxTokens).
	inChars := 0
	for _, m := range req.Messages {
		inChars += len(m.Content)
	}
	inTok := inChars / 4
	if inTok < 50 {
		inTok = 50
	}
	outTok := inTok
	if req.MaxTokens > 0 && req.MaxTokens < outTok {
		outTok = req.MaxTokens
	}
	model := req.Model
	if model == "" {
		model = a.defaultModel
	}
	cost := EstimateOpenAICost(model, inTok, outTok)
	return inTok + outTok, cost
}

// ----- Factory -----

// NewAdapterFromEnv picks an Adapter based on process environment.
//
// Precedence (documented in PLAN-0167 §Stream 3c):
//
//  1. If OPENAI_API_KEY is set → OpenAI adapter.
//     - If OLLAMA_URL is also set AND M3C_LLM_FALLBACK=ollama, the
//       returned adapter wraps OpenAI as primary and Ollama as
//       fallback on 5xx responses. Lets a prod-configured engine
//       degrade to local inference during transient outages.
//  2. Else if OLLAMA_URL is set → Ollama adapter (local, zero cost).
//  3. Else → error. The engine refuses to start without a configured
//     LLM path rather than silently no-op. Matches the Week-1
//     invariant that NewOpenAI errors on missing OPENAI_API_KEY.
//
// This is the single entry point the engine's main() should use;
// tests continue to construct MockAdapter directly.
func NewAdapterFromEnv() (Adapter, error) {
	haveOpenAI := strings.TrimSpace(os.Getenv("OPENAI_API_KEY")) != ""
	haveOllama := strings.TrimSpace(os.Getenv("OLLAMA_URL")) != ""
	fallback := strings.EqualFold(strings.TrimSpace(os.Getenv("M3C_LLM_FALLBACK")), "ollama")

	switch {
	case haveOpenAI && haveOllama && fallback:
		primary, err := NewOpenAI()
		if err != nil {
			return nil, fmt.Errorf("llm: factory primary (openai): %w", err)
		}
		secondary, err := NewOllama()
		if err != nil {
			return nil, fmt.Errorf("llm: factory fallback (ollama): %w", err)
		}
		return &fallbackAdapter{primary: primary, secondary: secondary}, nil
	case haveOpenAI:
		return NewOpenAI()
	case haveOllama:
		return NewOllama()
	default:
		return nil, errors.New("llm: no LLM configured — set OPENAI_API_KEY or OLLAMA_URL")
	}
}

// fallbackAdapter tries primary.Complete first; on a 5xx-style error
// from the primary it retries once against the secondary. Used when
// OpenAI is configured as primary with Ollama as a local fallback for
// transient provider outages.
type fallbackAdapter struct {
	primary   Adapter
	secondary Adapter
}

func (f *fallbackAdapter) Name() string {
	return f.primary.Name() + "+fallback:" + f.secondary.Name()
}

func (f *fallbackAdapter) Complete(ctx context.Context, req Request) (Response, error) {
	resp, err := f.primary.Complete(ctx, req)
	if err == nil {
		return resp, nil
	}
	if !isTransientLLMError(err) {
		return Response{}, err
	}
	return f.secondary.Complete(ctx, req)
}

func (f *fallbackAdapter) EstimateCost(req Request) (int, float64) {
	return f.primary.EstimateCost(req)
}

// isTransientLLMError heuristically detects 5xx-class upstream errors
// from provider adapters. The go-openai client returns errors whose
// String form includes "status code: 5" on 5xx; our ollama adapter
// returns "status <code>:" on any >= 500. We keep this loose rather
// than typed because the OpenAI SDK's error type isn't stable across
// versions and this gate only decides whether to try the fallback.
func isTransientLLMError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	if strings.Contains(s, "status code: 5") {
		return true
	}
	if strings.Contains(s, "status 5") {
		return true
	}
	return false
}

// EstimateOpenAICost returns USD cost for (model, promptTokens, completionTokens)
// using a conservative fixed-rate card. Real production numbers are
// whatever the API bills; this is an internal estimator for budget
// gating and trace records.
//
// Rates are per-1M-tokens, approximate as of 2026-Q1:
//   gpt-4o-mini: $0.15 / $0.60
//   gpt-4o:      $2.50 / $10.00
//   default:     $1.00 / $3.00
func EstimateOpenAICost(model string, inTok, outTok int) float64 {
	var inRate, outRate float64 // per 1M tokens
	m := strings.ToLower(model)
	switch {
	case strings.Contains(m, "gpt-4o-mini"):
		inRate, outRate = 0.15, 0.60
	case strings.Contains(m, "gpt-4o"):
		inRate, outRate = 2.50, 10.00
	case strings.Contains(m, "o1-mini"):
		inRate, outRate = 1.10, 4.40
	default:
		inRate, outRate = 1.00, 3.00
	}
	return float64(inTok)/1_000_000*inRate + float64(outTok)/1_000_000*outRate
}

// ----- Mock adapter -----

// MockAdapter is a deterministic in-process Adapter for tests and
// e2e runs. It returns either a fixed response or one determined by
// a caller-supplied Responder function, and reports token counts
// derived from the message size.
type MockAdapter struct {
	// Responder, if set, is called for each Complete() and its
	// return value becomes the response body. If nil, FixedResponse
	// is used verbatim.
	Responder func(req Request) string

	// FixedResponse is the body returned when Responder is nil.
	FixedResponse string

	// ModelName reported in Response.Model (default "mock-llm").
	ModelName string

	// Err, if non-nil, is returned from Complete() regardless of
	// Responder. Used to test error paths.
	Err error

	// Calls records every Complete() invocation (most recent last)
	// for assertions in tests.
	Calls []Request
}

// NewMock returns a MockAdapter with a fixed response body.
func NewMock(fixed string) *MockAdapter {
	return &MockAdapter{FixedResponse: fixed, ModelName: "mock-llm"}
}

// Name reports "mock".
func (m *MockAdapter) Name() string { return "mock" }

// Complete returns the configured response.
func (m *MockAdapter) Complete(ctx context.Context, req Request) (Response, error) {
	m.Calls = append(m.Calls, req)
	if m.Err != nil {
		return Response{}, m.Err
	}
	body := m.FixedResponse
	if m.Responder != nil {
		body = m.Responder(req)
	}
	model := m.ModelName
	if req.Model != "" {
		model = req.Model
	}
	if model == "" {
		model = "mock-llm"
	}
	inChars := 0
	for _, msg := range req.Messages {
		inChars += len(msg.Content)
	}
	tokensIn := inChars / 4
	if tokensIn < 1 {
		tokensIn = 1
	}
	tokensOut := len(body) / 4
	if tokensOut < 1 {
		tokensOut = 1
	}
	return Response{
		Content:    body,
		Model:      model,
		TokensIn:   tokensIn,
		TokensOut: tokensOut,
		CostUSD:    0, // mock calls are free
		DurationMS: 1,
	}, nil
}

// EstimateCost returns a fixed, tiny estimate so budget gating
// exercises the plumbing without biasing tests.
func (m *MockAdapter) EstimateCost(req Request) (int, float64) {
	inChars := 0
	for _, msg := range req.Messages {
		inChars += len(msg.Content)
	}
	tokens := inChars/4 + 200 // assume ~200 completion tokens
	if tokens < 100 {
		tokens = 100
	}
	return tokens, 0.0001
}
