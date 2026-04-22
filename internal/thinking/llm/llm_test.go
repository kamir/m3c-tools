package llm

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestMockReturnsFixedResponse(t *testing.T) {
	m := NewMock("hello from mock")
	resp, err := m.Complete(context.Background(), Request{
		Messages: []Message{{Role: "user", Content: "ping"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Content != "hello from mock" {
		t.Errorf("content = %q", resp.Content)
	}
	if resp.Model == "" {
		t.Errorf("model empty")
	}
	if resp.TokensIn == 0 || resp.TokensOut == 0 {
		t.Errorf("tokens unset: %+v", resp)
	}
}

func TestMockResponderFunction(t *testing.T) {
	m := &MockAdapter{
		Responder: func(req Request) string {
			return "echo:" + req.Messages[len(req.Messages)-1].Content
		},
	}
	resp, err := m.Complete(context.Background(), Request{
		Messages: []Message{{Role: "user", Content: "hi"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(resp.Content, "echo:") {
		t.Errorf("unexpected: %s", resp.Content)
	}
	if len(m.Calls) != 1 {
		t.Errorf("calls = %d", len(m.Calls))
	}
}

func TestMockErrorPath(t *testing.T) {
	boom := errors.New("boom")
	m := &MockAdapter{Err: boom}
	_, err := m.Complete(context.Background(), Request{})
	if err == nil || err != boom {
		t.Errorf("expected boom, got %v", err)
	}
}

func TestMockEstimateCost(t *testing.T) {
	m := NewMock("x")
	tokens, cost := m.EstimateCost(Request{
		Messages: []Message{{Role: "user", Content: "a longer prompt that should estimate something"}},
	})
	if tokens <= 0 {
		t.Errorf("tokens = %d", tokens)
	}
	if cost <= 0 {
		t.Errorf("cost = %f", cost)
	}
}

func TestEstimateOpenAICostShape(t *testing.T) {
	// gpt-4o-mini is cheapest in the table
	cheap := EstimateOpenAICost("gpt-4o-mini", 1_000_000, 1_000_000)
	pricey := EstimateOpenAICost("gpt-4o", 1_000_000, 1_000_000)
	if !(cheap < pricey) {
		t.Errorf("expected gpt-4o-mini cheaper than gpt-4o: %f vs %f", cheap, pricey)
	}
	// Unknown model uses default rates — still positive.
	other := EstimateOpenAICost("some-new-model", 1000, 1000)
	if other <= 0 {
		t.Errorf("default cost should be positive")
	}
}

func TestNewOpenAIRequiresAPIKey(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "")
	if _, err := NewOpenAI(); err == nil {
		t.Errorf("expected error when OPENAI_API_KEY unset")
	}
}
