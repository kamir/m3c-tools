package r

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
	tkafka "github.com/kamir/m3c-tools/internal/thinking/kafka"
	"github.com/kamir/m3c-tools/internal/thinking/llm"
	"github.com/kamir/m3c-tools/internal/thinking/orchestrator"
	"github.com/kamir/m3c-tools/internal/thinking/processors"
	"github.com/kamir/m3c-tools/internal/thinking/prompts"
	"github.com/kamir/m3c-tools/internal/thinking/schema"
	"github.com/kamir/m3c-tools/internal/thinking/store"
)

// seedTestRegistry returns a Registry seeded with production Week 2
// prompt ids so the handlers can resolve them.
func seedTestRegistry(t *testing.T) prompts.Registry {
	t.Helper()
	return &fakeRegistry{prompts: map[string]prompts.Prompt{
		prompts.StrategyPromptID("r", "compare"):  {ID: prompts.StrategyPromptID("r", "compare"), Version: 1, Body: "compare-prompt-body", Model: "mock-llm"},
		prompts.StrategyPromptID("r", "classify"): {ID: prompts.StrategyPromptID("r", "classify"), Version: 1, Body: "classify-prompt-body taxonomy={{taxonomy}}", Model: "mock-llm"},
	}}
}

type fakeRegistry struct{ prompts map[string]prompts.Prompt }

func (r *fakeRegistry) Get(ctx context.Context, id string) (prompts.Prompt, error) {
	p, ok := r.prompts[id]
	if !ok {
		return prompts.Prompt{}, &missErr{id: id}
	}
	return p, nil
}

type missErr struct{ id string }

func (e *missErr) Error() string { return "unknown prompt: " + e.id }

func newDeps(t *testing.T, mock *llm.MockAdapter) (processors.Deps, func()) {
	t.Helper()
	raw, _ := mctx.NewRaw("r-test")
	h := raw.Hash()
	innerBus := tkafka.NewMemBus(h)
	bus, err := tkafka.NewValidatingBus(innerBus, nil)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	orc := orchestrator.New(h, bus, st)

	deps := processors.Deps{
		Hash:    h,
		Bus:     bus,
		Orc:     orc,
		Prompts: seedTestRegistry(t),
		Log:     log.New(os.Stderr, "[r-test] ", 0),
		LLM:     mock,
	}
	return deps, func() { _ = st.Close() }
}

func TestCompareProducesStructuredContent(t *testing.T) {
	mock := llm.NewMock(`{"similarities":["A","B"],"differences":["x","y"]}`)
	deps, cleanup := newDeps(t, mock)
	defer cleanup()

	// Subscribe to reflections topic to capture output.
	reflTopic := tkafka.TopicName(deps.Hash, tkafka.TopicReflectionsGenerated)
	captured := make(chan []byte, 1)
	_, err := deps.Bus.Subscribe(reflTopic, func(ctx context.Context, m tkafka.Message) error {
		captured <- append([]byte(nil), m.Value...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	cmd := schema.ProcessCommand{
		SchemaVer: schema.CurrentSchemaVer,
		ProcessID: uuid.NewString(),
		StepIndex: 0,
		Step:      schema.Step{Layer: schema.LayerR, Strategy: "compare"},
		Spec: schema.ProcessSpec{
			SchemaVer: schema.CurrentSchemaVer, ProcessID: "p-1",
			Intent: "compare things", Mode: schema.ModeLinear, Depth: 1,
			Steps: []schema.Step{{Layer: schema.LayerR, Strategy: "compare"}},
		},
		Timestamp: time.Now().UTC(),
	}

	// Call the public handler directly (instead of the Kafka dispatch
	// loop) for a clean unit test.
	detail, err := callHandler(t, "compare", deps, cmd)
	if err != nil {
		t.Fatalf("handleCompare error: %v", err)
	}
	if detail["strategy"] != "compare" {
		t.Errorf("strategy = %v", detail["strategy"])
	}

	// Read the produced reflection.
	select {
	case raw := <-captured:
		var r schema.Reflection
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatal(err)
		}
		if r.Strategy != schema.StrategyCompare {
			t.Errorf("strategy %s", r.Strategy)
		}
		sims, _ := r.Content["similarities"].([]interface{})
		diffs, _ := r.Content["differences"].([]interface{})
		if len(sims) != 2 || len(diffs) != 2 {
			t.Errorf("content shape wrong: %+v", r.Content)
		}
		if r.Trace.PromptID == "" || r.Trace.Model == "" {
			t.Errorf("trace not populated: %+v", r.Trace)
		}
	case <-time.After(time.Second):
		t.Fatal("no reflection produced")
	}
}

func TestClassifyRejectsMalformedCompletion(t *testing.T) {
	mock := llm.NewMock(`not json at all`)
	deps, cleanup := newDeps(t, mock)
	defer cleanup()

	cmd := schema.ProcessCommand{
		SchemaVer: schema.CurrentSchemaVer,
		ProcessID: uuid.NewString(),
		Step:      schema.Step{Layer: schema.LayerR, Strategy: "classify"},
		Spec: schema.ProcessSpec{
			SchemaVer: schema.CurrentSchemaVer, ProcessID: "p-2",
			Intent: "x", Mode: schema.ModeLinear, Depth: 1,
			Steps: []schema.Step{{Layer: schema.LayerR, Strategy: "classify"}},
		},
	}
	_, err := callHandler(t, "classify", deps, cmd)
	if err == nil {
		t.Fatal("expected parse error")
	}
	if !strings.Contains(err.Error(), "non-json") && !strings.Contains(err.Error(), "parse") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCompareStripsCodeFence(t *testing.T) {
	mock := llm.NewMock("```json\n{\"similarities\":[],\"differences\":[\"d\"]}\n```")
	deps, cleanup := newDeps(t, mock)
	defer cleanup()

	cmd := schema.ProcessCommand{
		SchemaVer: schema.CurrentSchemaVer,
		ProcessID: uuid.NewString(),
		Step:      schema.Step{Layer: schema.LayerR, Strategy: "compare"},
		Spec: schema.ProcessSpec{
			SchemaVer: schema.CurrentSchemaVer, ProcessID: "p-3",
			Intent: "x", Mode: schema.ModeLinear, Depth: 1,
			Steps: []schema.Step{{Layer: schema.LayerR, Strategy: "compare"}},
		},
	}
	if _, err := callHandler(t, "compare", deps, cmd); err != nil {
		t.Fatal(err)
	}
}

// callHandler dispatches through the strategies map directly,
// bypassing Kafka Subscribe and the RunStep wrapper so the unit test
// is deterministic.
func callHandler(t *testing.T, strategy string, deps processors.Deps, cmd schema.ProcessCommand) (map[string]interface{}, error) {
	t.Helper()
	h, ok := strategies[strategy]
	if !ok {
		t.Fatalf("unknown strategy %q in test", strategy)
	}
	return h(context.Background(), deps, cmd)
}
