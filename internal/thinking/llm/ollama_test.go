package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newOllamaTestServer spins up an httptest server that responds to
// /api/chat with the supplied body/status, and returns an Adapter
// pointed at it.
func newOllamaTestServer(t *testing.T, handler http.HandlerFunc) (Adapter, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	t.Setenv("OLLAMA_URL", srv.URL)
	t.Setenv("OLLAMA_MODEL", "test-model")
	a, err := NewOllama()
	if err != nil {
		t.Fatalf("NewOllama: %v", err)
	}
	return a, srv
}

func TestOllamaHappyPath(t *testing.T) {
	a, _ := newOllamaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		if r.URL.Path != "/api/chat" {
			t.Errorf("path = %s", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		var parsed ollamaChatRequest
		if err := json.Unmarshal(body, &parsed); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if parsed.Stream {
			t.Errorf("expected stream=false")
		}
		if parsed.Model != "test-model" {
			t.Errorf("model = %s", parsed.Model)
		}
		if len(parsed.Messages) != 1 || parsed.Messages[0].Content != "hello" {
			t.Errorf("messages = %+v", parsed.Messages)
		}
		fmt.Fprintln(w, `{"model":"test-model","message":{"role":"assistant","content":"hi back"},"done":true}`)
	})

	resp, err := a.Complete(context.Background(), Request{
		Messages: []Message{{Role: "user", Content: "hello"}},
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if resp.Content != "hi back" {
		t.Errorf("content = %q", resp.Content)
	}
	if resp.Model != "test-model" {
		t.Errorf("model = %s", resp.Model)
	}
	if resp.CostUSD != 0.0 {
		t.Errorf("ollama cost must be 0, got %f", resp.CostUSD)
	}
	if resp.TokensIn <= 0 || resp.TokensOut <= 0 {
		t.Errorf("tokens = (%d,%d)", resp.TokensIn, resp.TokensOut)
	}
	if a.Name() != "ollama" {
		t.Errorf("name = %s", a.Name())
	}
}

func TestOllamaEmptyResponseErrors(t *testing.T) {
	a, _ := newOllamaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `{"model":"test-model","message":{"role":"assistant","content":""},"done":true}`)
	})
	_, err := a.Complete(context.Background(), Request{
		Messages: []Message{{Role: "user", Content: "x"}},
	})
	if err == nil || !strings.Contains(err.Error(), "empty response") {
		t.Errorf("expected empty response error, got %v", err)
	}
}

func TestOllama500Errors(t *testing.T) {
	a, _ := newOllamaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, `{"error":"model crashed"}`)
	})
	_, err := a.Complete(context.Background(), Request{
		Messages: []Message{{Role: "user", Content: "x"}},
	})
	if err == nil {
		t.Fatalf("expected error on 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention status, got %v", err)
	}
	if !isTransientLLMError(err) {
		t.Errorf("ollama 5xx should be classified transient for fallback gate")
	}
}

func TestOllamaTokenEstimation(t *testing.T) {
	// 24 chars in, 12 chars out → 6 tokens in, 3 tokens out (chars/4).
	in := "0123456789012345678901234" // 25 chars
	out := "abcdefghijkl"              // 12 chars
	a, _ := newOllamaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"model":"test-model","message":{"role":"assistant","content":%q},"done":true}`, out)
	})
	resp, err := a.Complete(context.Background(), Request{
		Messages: []Message{{Role: "user", Content: in}},
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	wantIn := len(in) / 4
	wantOut := len(out) / 4
	if resp.TokensIn != wantIn {
		t.Errorf("TokensIn = %d, want %d", resp.TokensIn, wantIn)
	}
	if resp.TokensOut != wantOut {
		t.Errorf("TokensOut = %d, want %d", resp.TokensOut, wantOut)
	}
	if resp.CostUSD != 0.0 {
		t.Errorf("CostUSD = %f, want 0.0 for local", resp.CostUSD)
	}
}

func TestOllamaEstimateCostZero(t *testing.T) {
	t.Setenv("OLLAMA_URL", "http://localhost:11434")
	a, err := NewOllama()
	if err != nil {
		t.Fatalf("NewOllama: %v", err)
	}
	tokens, cost := a.EstimateCost(Request{
		Messages: []Message{{Role: "user", Content: "a fairly long prompt for estimation"}},
	})
	if tokens <= 0 {
		t.Errorf("tokens = %d", tokens)
	}
	if cost != 0.0 {
		t.Errorf("cost = %f, want 0 for local", cost)
	}
}

func TestOllamaJSONFormatPassthrough(t *testing.T) {
	got := make(chan string, 1)
	a, _ := newOllamaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var parsed ollamaChatRequest
		_ = json.Unmarshal(body, &parsed)
		got <- parsed.Format
		fmt.Fprintln(w, `{"model":"test-model","message":{"role":"assistant","content":"{}"},"done":true}`)
	})
	_, err := a.Complete(context.Background(), Request{
		Messages: []Message{{Role: "user", Content: "x"}},
		Format:   "json",
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if f := <-got; f != "json" {
		t.Errorf("format = %q, want json", f)
	}
}

// ----- Factory tests -----

func TestNewAdapterFromEnvOpenAIOnly(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "test-key")
	t.Setenv("OLLAMA_URL", "")
	t.Setenv("M3C_LLM_FALLBACK", "")
	a, err := NewAdapterFromEnv()
	if err != nil {
		t.Fatalf("NewAdapterFromEnv: %v", err)
	}
	if a.Name() != "openai" {
		t.Errorf("name = %s, want openai", a.Name())
	}
}

func TestNewAdapterFromEnvOllamaOnly(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("OLLAMA_URL", "http://localhost:11434")
	t.Setenv("M3C_LLM_FALLBACK", "")
	a, err := NewAdapterFromEnv()
	if err != nil {
		t.Fatalf("NewAdapterFromEnv: %v", err)
	}
	if a.Name() != "ollama" {
		t.Errorf("name = %s, want ollama", a.Name())
	}
}

func TestNewAdapterFromEnvBothWithoutFallbackPicksOpenAI(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "test-key")
	t.Setenv("OLLAMA_URL", "http://localhost:11434")
	t.Setenv("M3C_LLM_FALLBACK", "")
	a, err := NewAdapterFromEnv()
	if err != nil {
		t.Fatalf("NewAdapterFromEnv: %v", err)
	}
	if a.Name() != "openai" {
		t.Errorf("name = %s, want openai (fallback off)", a.Name())
	}
}

func TestNewAdapterFromEnvBothWithFallbackWrapsBoth(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "test-key")
	t.Setenv("OLLAMA_URL", "http://localhost:11434")
	t.Setenv("M3C_LLM_FALLBACK", "ollama")
	a, err := NewAdapterFromEnv()
	if err != nil {
		t.Fatalf("NewAdapterFromEnv: %v", err)
	}
	if !strings.Contains(a.Name(), "openai") || !strings.Contains(a.Name(), "ollama") {
		t.Errorf("name = %s, want composite openai+fallback:ollama", a.Name())
	}
}

func TestNewAdapterFromEnvNothingConfigured(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("OLLAMA_URL", "")
	t.Setenv("M3C_LLM_FALLBACK", "")
	_, err := NewAdapterFromEnv()
	if err == nil {
		t.Fatalf("expected error when no LLM configured")
	}
	if !strings.Contains(err.Error(), "no LLM configured") {
		t.Errorf("unexpected error text: %v", err)
	}
}

// ----- Fallback dispatch -----

type scriptedAdapter struct {
	name string
	err  error
	resp Response
	n    int
}

func (s *scriptedAdapter) Name() string { return s.name }
func (s *scriptedAdapter) Complete(ctx context.Context, req Request) (Response, error) {
	s.n++
	if s.err != nil {
		return Response{}, s.err
	}
	return s.resp, nil
}
func (s *scriptedAdapter) EstimateCost(req Request) (int, float64) { return 100, 0.001 }

func TestFallbackTriggersOnTransient(t *testing.T) {
	primary := &scriptedAdapter{name: "openai", err: errors.New("openai: status code: 503 service unavailable")}
	secondary := &scriptedAdapter{name: "ollama", resp: Response{Content: "local reply", Model: "llama3.1:8b", TokensIn: 10, TokensOut: 5}}
	f := &fallbackAdapter{primary: primary, secondary: secondary}

	resp, err := f.Complete(context.Background(), Request{
		Messages: []Message{{Role: "user", Content: "hi"}},
	})
	if err != nil {
		t.Fatalf("fallback Complete: %v", err)
	}
	if resp.Content != "local reply" {
		t.Errorf("content = %q, want local fallback", resp.Content)
	}
	if primary.n != 1 || secondary.n != 1 {
		t.Errorf("call counts: primary=%d secondary=%d, want 1/1", primary.n, secondary.n)
	}
}

func TestFallbackDoesNotTriggerOnClientError(t *testing.T) {
	primary := &scriptedAdapter{name: "openai", err: errors.New("openai: status code: 401 unauthorized")}
	secondary := &scriptedAdapter{name: "ollama", resp: Response{Content: "local reply"}}
	f := &fallbackAdapter{primary: primary, secondary: secondary}

	_, err := f.Complete(context.Background(), Request{})
	if err == nil {
		t.Fatalf("expected primary 4xx to surface, not fall back")
	}
	if secondary.n != 0 {
		t.Errorf("secondary.n = %d, want 0 on 4xx", secondary.n)
	}
}

func TestFallbackHappyPathSkipsSecondary(t *testing.T) {
	primary := &scriptedAdapter{name: "openai", resp: Response{Content: "cloud reply"}}
	secondary := &scriptedAdapter{name: "ollama", resp: Response{Content: "local reply"}}
	f := &fallbackAdapter{primary: primary, secondary: secondary}

	resp, err := f.Complete(context.Background(), Request{})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if resp.Content != "cloud reply" {
		t.Errorf("content = %q, want cloud reply", resp.Content)
	}
	if secondary.n != 0 {
		t.Errorf("secondary.n = %d, want 0 on happy path", secondary.n)
	}
}
