package kafka

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
)

func TestDefaultValidatorCompiles(t *testing.T) {
	v, err := DefaultValidator()
	if err != nil {
		t.Fatalf("DefaultValidator: %v", err)
	}
	for _, s := range AllSchemas() {
		if _, ok := v.schemas[s]; !ok {
			t.Errorf("missing compiled schema: %s", s)
		}
	}
}

// Minimal fixtures per schema. Each pair: one valid, one invalid.
func TestValidatorAcceptsValidFixtures(t *testing.T) {
	v, err := DefaultValidator()
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Format(time.RFC3339)

	valid := map[SchemaName]any{
		SchemaT: map[string]any{
			"schema_ver": 1,
			"thought_id": "t-1",
			"type":       "observation",
			"content":    "hi",
			"source":     map[string]any{"kind": "typed", "ref": "manual"},
			"timestamp":  now,
			"provenance": map[string]any{"captured_by": "test"},
		},
		SchemaR: map[string]any{
			"schema_ver":    1,
			"reflection_id": "r-1",
			"thought_ids":   []string{"t-1"},
			"strategy":      "compare",
			"content":       map[string]any{"x": "y"},
			"trace":         map[string]any{"prompt_id": "p", "model": "m"},
			"timestamp":     now,
		},
		SchemaI: map[string]any{
			"schema_ver":     1,
			"insight_id":     "i-1",
			"input_ids":      []string{"r-1"},
			"synthesis_mode": "pattern",
			"content":        map[string]any{"pattern": "x"},
			"confidence":     0.5,
			"trace":          map[string]any{"prompt_id": "p", "model": "m"},
			"timestamp":      now,
		},
		SchemaA: map[string]any{
			"schema_ver":  1,
			"artifact_id": "a-1",
			"insight_ids": []string{"i-1"},
			"format":      "report",
			"audience":    "human",
			"content":     map[string]any{"title": "x"},
			"version":     1,
			"provenance":  map[string]any{"t_ids": []string{}, "r_ids": []string{}, "i_ids": []string{"i-1"}},
			"timestamp":   now,
		},
		SchemaProcessSpec: map[string]any{
			"schema_ver": 1,
			"process_id": "p-1",
			"intent":     "x",
			"mode":       "linear",
			"depth":      1,
			"steps":      []any{map[string]any{"layer": "R", "strategy": "compare"}},
		},
	}
	for s, val := range valid {
		body, _ := json.Marshal(val)
		if err := v.Validate(s, body); err != nil {
			t.Errorf("valid %s should pass: %v", s, err)
		}
	}
}

func TestValidatorRejectsInvalidFixtures(t *testing.T) {
	v, _ := DefaultValidator()

	// Each case: schema, body, substring expected in error.
	cases := []struct {
		name string
		s    SchemaName
		body any
	}{
		{"T missing schema_ver", SchemaT, map[string]any{"thought_id": "t"}},
		{"T bad type enum", SchemaT, map[string]any{
			"schema_ver": 1, "thought_id": "t-1", "type": "invalid-type",
			"content": "x", "source": map[string]any{"kind": "typed", "ref": "r"},
			"timestamp": "2026-04-22T00:00:00Z",
		}},
		{"R missing strategy", SchemaR, map[string]any{
			"schema_ver": 1, "reflection_id": "r", "thought_ids": []string{"t"},
			"content": map[string]any{}, "trace": map[string]any{"prompt_id": "p", "model": "m"},
			"timestamp": "2026-04-22T00:00:00Z",
		}},
		{"I confidence out of range", SchemaI, map[string]any{
			"schema_ver": 1, "insight_id": "i", "input_ids": []string{"r"},
			"synthesis_mode": "pattern", "content": map[string]any{}, "confidence": 5.0,
			"trace": map[string]any{"prompt_id": "p", "model": "m"}, "timestamp": "2026-04-22T00:00:00Z",
		}},
		{"A wrong format enum", SchemaA, map[string]any{
			"schema_ver": 1, "artifact_id": "a", "insight_ids": []string{"i"},
			"format": "not-a-format", "audience": "human", "content": map[string]any{},
			"version": 1, "provenance": map[string]any{"t_ids": []string{}, "r_ids": []string{}, "i_ids": []string{}},
			"timestamp": "2026-04-22T00:00:00Z",
		}},
		{"ProcessSpec invalid mode", SchemaProcessSpec, map[string]any{
			"schema_ver": 1, "process_id": "p", "intent": "x", "mode": "nope",
			"depth": 1, "steps": []any{map[string]any{"layer": "R", "strategy": "c"}},
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body, _ := json.Marshal(c.body)
			err := v.Validate(c.s, body)
			if err == nil {
				t.Fatalf("expected validation error for %s", c.name)
			}
			if !IsSchemaValidationError(err) {
				t.Errorf("expected *SchemaValidationError, got %T", err)
			}
		})
	}
}

func TestSchemaValidationErrorMessage(t *testing.T) {
	v, _ := DefaultValidator()
	err := v.Validate(SchemaT, []byte(`{"thought_id":"x"}`))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "schema validation failed") {
		t.Errorf("error message missing prefix: %v", err)
	}
	var sv *SchemaValidationError
	if !errors.As(err, &sv) {
		t.Errorf("expected *SchemaValidationError")
	}
}

func TestSchemaForTopicResolution(t *testing.T) {
	raw, _ := mctx.NewRaw("u")
	h := raw.Hash()
	cases := map[string]SchemaName{
		TopicName(h, TopicThoughtsRaw):          SchemaT,
		TopicName(h, TopicReflectionsGenerated): SchemaR,
		TopicName(h, TopicInsightsGenerated):    SchemaI,
		TopicName(h, TopicArtifactsCreated):     SchemaA,
		TopicName(h, TopicProcessEvents):        "",
		TopicName(h, TopicProcessCommands):      "",
	}
	for topic, want := range cases {
		got := SchemaForTopic(topic)
		if got != want {
			t.Errorf("SchemaForTopic(%s) = %q, want %q", topic, got, want)
		}
	}
}

func TestValidatingBusProduceRejectsInvalid(t *testing.T) {
	raw, _ := mctx.NewRaw("u")
	h := raw.Hash()
	inner := NewMemBus(h)
	vb, err := NewValidatingBus(inner, nil)
	if err != nil {
		t.Fatal(err)
	}
	topic := TopicName(h, TopicThoughtsRaw)
	bad := map[string]any{"thought_id": "t", "type": "wrong-enum"}
	err = vb.Produce(context.Background(), topic, "k", bad)
	if err == nil {
		t.Fatal("expected produce validation error")
	}
	if !IsSchemaValidationError(err) {
		t.Errorf("expected *SchemaValidationError, got %T", err)
	}
	if vb.Metrics().Rejected(SchemaT) == 0 {
		t.Errorf("rejected counter not incremented")
	}
}

func TestValidatingBusProduceAcceptsValid(t *testing.T) {
	raw, _ := mctx.NewRaw("u")
	h := raw.Hash()
	inner := NewMemBus(h)
	vb, _ := NewValidatingBus(inner, nil)
	topic := TopicName(h, TopicThoughtsRaw)

	good := map[string]any{
		"schema_ver": 1, "thought_id": "t-1", "type": "observation",
		"content":   "x",
		"source":    map[string]any{"kind": "typed", "ref": "m"},
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	if err := vb.Produce(context.Background(), topic, "k", good); err != nil {
		t.Fatalf("valid produce failed: %v", err)
	}
	if vb.Metrics().Produced(SchemaT) == 0 {
		t.Errorf("produced counter not incremented")
	}
}

func TestValidatingBusSubscribeRejectsInvalid(t *testing.T) {
	raw, _ := mctx.NewRaw("u")
	h := raw.Hash()
	inner := NewMemBus(h)
	vb, _ := NewValidatingBus(inner, nil)
	topic := TopicName(h, TopicThoughtsRaw)

	var wg sync.WaitGroup
	wg.Add(1)
	var handlerCalled bool

	_, err := vb.Subscribe(topic, func(ctx context.Context, m Message) error {
		handlerCalled = true
		wg.Done()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Bypass validation by producing via the raw inner bus with an
	// invalid payload — simulates a malformed message hitting the
	// wire from elsewhere.
	badBody := []byte(`{"thought_id":"t","type":"not-an-enum"}`)
	if err := inner.Produce(context.Background(), topic, "k", json.RawMessage(badBody)); err != nil {
		t.Fatal(err)
	}

	// Wait briefly for dispatch; handler MUST NOT fire.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		t.Errorf("handler should not fire for invalid payload")
	case <-time.After(150 * time.Millisecond):
		// expected: handler not called
	}
	if handlerCalled {
		t.Errorf("handler was called with invalid payload")
	}
	if vb.Metrics().Rejected(SchemaT) == 0 {
		t.Errorf("rejected counter not incremented on consume")
	}
}

func TestValidatingBusPassThroughNonSchemaTopic(t *testing.T) {
	raw, _ := mctx.NewRaw("u")
	h := raw.Hash()
	inner := NewMemBus(h)
	vb, _ := NewValidatingBus(inner, nil)
	// process.events has no schema gate — any shape allowed.
	topic := TopicName(h, TopicProcessEvents)
	if err := vb.Produce(context.Background(), topic, "k", map[string]string{"anything": "goes"}); err != nil {
		t.Fatalf("pass-through produce failed: %v", err)
	}
}
