// Ollama adapter — local, zero-cost LLM provider for Thinking Engine
// dev cycles. Talks to the Ollama HTTP server at $OLLAMA_URL (default
// http://localhost:11434) via its /api/chat endpoint.
//
// SPEC-0167 Week 3 Stream 3c (PLAN-0167-week3-kickoff.md §Stream 3c):
// we need a zero-cost local path so dev iteration doesn't burn OpenAI
// credits. Ollama is good enough for the R/I/A processor loops at
// llama3.1:8b quality, and keeping Cost=0 means the budget accounting
// code stays identical between local and cloud runs.
//
// Token accounting limitation: Ollama's /api/chat response includes
// prompt_eval_count and eval_count, but those are tokenizer-dependent
// and not reliable across all model families — especially for custom
// or quantized builds. Rather than mix two accounting modes, we always
// estimate both TokensIn and TokensOut from character length (chars/4),
// matching the heuristic used by openaiAdapter.EstimateCost. CostUSD
// is always 0.0 for local inference. The per-process token cap still
// fires correctly because it reads tokens.in/out, not CostUSD.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	defaultOllamaURL   = "http://localhost:11434"
	defaultOllamaModel = "llama3.1:8b"
	ollamaChatPath     = "/api/chat"
	// ollamaDefaultTimeout bounds a single /api/chat call. Local
	// inference on llama3.1:8b on consumer hardware can take 10-30s
	// for a long response; 120s gives ample headroom without wedging
	// the orchestrator forever on a stuck model.
	ollamaDefaultTimeout = 120 * time.Second
)

// ollamaAdapter implements Adapter against a local Ollama server.
type ollamaAdapter struct {
	baseURL      string
	defaultModel string
	http         *http.Client
}

// NewOllama builds an adapter pointed at $OLLAMA_URL (default
// http://localhost:11434) using $OLLAMA_MODEL as the default model
// (default llama3.1:8b). Unlike NewOpenAI this does not fail if the
// env var is missing — the URL has a sensible default — but it does
// trim whitespace so an empty-string env var is treated as unset.
func NewOllama() (Adapter, error) {
	base := strings.TrimSpace(os.Getenv("OLLAMA_URL"))
	if base == "" {
		base = defaultOllamaURL
	}
	base = strings.TrimRight(base, "/")
	model := strings.TrimSpace(os.Getenv("OLLAMA_MODEL"))
	if model == "" {
		model = defaultOllamaModel
	}
	return &ollamaAdapter{
		baseURL:      base,
		defaultModel: model,
		http:         &http.Client{Timeout: ollamaDefaultTimeout},
	}, nil
}

func (a *ollamaAdapter) Name() string { return "ollama" }

// ollamaChatRequest is the payload shape for /api/chat.
type ollamaChatRequest struct {
	Model    string              `json:"model"`
	Messages []ollamaChatMessage `json:"messages"`
	Stream   bool                `json:"stream"`
	Format   string              `json:"format,omitempty"`
	Options  *ollamaOptions      `json:"options,omitempty"`
}

type ollamaChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ollamaOptions struct {
	Temperature *float32 `json:"temperature,omitempty"`
	NumPredict  *int     `json:"num_predict,omitempty"`
}

// ollamaChatResponse is the non-streaming response shape.
type ollamaChatResponse struct {
	Model   string            `json:"model"`
	Message ollamaChatMessage `json:"message"`
	Done    bool              `json:"done"`
}

func (a *ollamaAdapter) Complete(ctx context.Context, req Request) (Response, error) {
	model := req.Model
	if model == "" {
		model = a.defaultModel
	}
	msgs := make([]ollamaChatMessage, 0, len(req.Messages))
	for _, m := range req.Messages {
		msgs = append(msgs, ollamaChatMessage{Role: m.Role, Content: m.Content})
	}
	payload := ollamaChatRequest{
		Model:    model,
		Messages: msgs,
		Stream:   false,
	}
	if strings.EqualFold(req.Format, "json") {
		payload.Format = "json"
	}
	if req.Temperature != 0 || req.MaxTokens > 0 {
		opts := &ollamaOptions{}
		if req.Temperature != 0 {
			t := req.Temperature
			opts.Temperature = &t
		}
		if req.MaxTokens > 0 {
			n := req.MaxTokens
			opts.NumPredict = &n
		}
		payload.Options = opts
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return Response{}, fmt.Errorf("llm/ollama: marshal request: %w", err)
	}

	url := a.baseURL + ollamaChatPath
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return Response{}, fmt.Errorf("llm/ollama: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	start := time.Now()
	httpResp, err := a.http.Do(httpReq)
	if err != nil {
		return Response{}, fmt.Errorf("llm/ollama: http: %w", err)
	}
	defer httpResp.Body.Close()
	dur := int(time.Since(start) / time.Millisecond)

	if httpResp.StatusCode >= 500 {
		snippet, _ := io.ReadAll(io.LimitReader(httpResp.Body, 512))
		return Response{}, fmt.Errorf("llm/ollama: status %d: %s", httpResp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	if httpResp.StatusCode >= 400 {
		snippet, _ := io.ReadAll(io.LimitReader(httpResp.Body, 512))
		return Response{}, fmt.Errorf("llm/ollama: status %d: %s", httpResp.StatusCode, strings.TrimSpace(string(snippet)))
	}

	raw, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return Response{}, fmt.Errorf("llm/ollama: read body: %w", err)
	}
	var parsed ollamaChatResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return Response{}, fmt.Errorf("llm/ollama: decode: %w", err)
	}
	content := parsed.Message.Content
	if strings.TrimSpace(content) == "" {
		return Response{}, errors.New("llm/ollama: empty response")
	}

	returnedModel := parsed.Model
	if returnedModel == "" {
		returnedModel = model
	}
	tokensIn, tokensOut := estimateOllamaTokens(req.Messages, content)
	return Response{
		Content:    content,
		Model:      returnedModel,
		TokensIn:   tokensIn,
		TokensOut:  tokensOut,
		CostUSD:    0.0,
		DurationMS: dur,
	}, nil
}

// EstimateCost for the Ollama adapter always returns 0 USD (local
// inference is free). Token estimate uses the same chars/4 heuristic
// as the OpenAI adapter so pre-call budget gating still fires
// meaningfully on local runs.
func (a *ollamaAdapter) EstimateCost(req Request) (int, float64) {
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
	return inTok + outTok, 0.0
}

// estimateOllamaTokens computes (TokensIn, TokensOut) from character
// lengths of the request messages and response body. Documented on the
// package doc comment: Ollama's native counters aren't reliable across
// model families, so we use chars/4 end-to-end for consistency.
func estimateOllamaTokens(msgs []Message, out string) (int, int) {
	inChars := 0
	for _, m := range msgs {
		inChars += len(m.Content)
	}
	in := inChars / 4
	if in < 1 {
		in = 1
	}
	o := len(out) / 4
	if o < 1 {
		o = 1
	}
	return in, o
}
