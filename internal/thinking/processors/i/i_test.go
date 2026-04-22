package i

import (
	"context"
	"encoding/json"
	"log"
	"os"
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
	raw, _ := mctx.NewRaw("i-test")
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

	reg := &fakeRegistry{prompts: map[string]prompts.Prompt{
		prompts.StrategyPromptID("i", "pattern"):       {ID: prompts.StrategyPromptID("i", "pattern"), Version: 1, Body: "pattern-prompt", Model: "mock-llm"},
		prompts.StrategyPromptID("i", "contradiction"): {ID: prompts.StrategyPromptID("i", "contradiction"), Version: 1, Body: "contradiction-prompt", Model: "mock-llm"},
	}}

	deps := processors.Deps{
		Hash:    h,
		Bus:     bus,
		Orc:     orc,
		Prompts: reg,
		Log:     log.New(os.Stderr, "[i-test] ", 0),
		LLM:     mock,
	}
	return deps, func() { _ = st.Close() }
}

func TestPatternEmitsStructuredInsight(t *testing.T) {
	mock := llm.NewMock(`{"pattern":"recurring latency","occurrences":[1,2,3],"confidence":0.72}`)
	deps, cleanup := newDeps(t, mock)
	defer cleanup()

	topic := tkafka.TopicName(deps.Hash, tkafka.TopicInsightsGenerated)
	captured := make(chan []byte, 1)
	_, _ = deps.Bus.Subscribe(topic, func(ctx context.Context, m tkafka.Message) error {
		captured <- append([]byte(nil), m.Value...)
		return nil
	})

	cmd := schema.ProcessCommand{
		SchemaVer: schema.CurrentSchemaVer,
		ProcessID: uuid.NewString(),
		Step:      schema.Step{Layer: schema.LayerI, Strategy: "pattern"},
		Spec: schema.ProcessSpec{
			SchemaVer: schema.CurrentSchemaVer, ProcessID: "p-1",
			Intent: "find patterns", Mode: schema.ModeLinear, Depth: 1,
			Steps: []schema.Step{{Layer: schema.LayerI, Strategy: "pattern"}},
		},
	}
	if _, err := handlePattern(context.Background(), deps, cmd); err != nil {
		t.Fatal(err)
	}

	select {
	case raw := <-captured:
		var ins schema.Insight
		if err := json.Unmarshal(raw, &ins); err != nil {
			t.Fatal(err)
		}
		if ins.SynthesisMode != schema.SynthesisPattern {
			t.Errorf("mode = %s", ins.SynthesisMode)
		}
		if ins.Content["pattern"] != "recurring latency" {
			t.Errorf("bad pattern content: %v", ins.Content)
		}
		if ins.Confidence < 0.71 || ins.Confidence > 0.73 {
			t.Errorf("confidence = %f", ins.Confidence)
		}
	case <-time.After(time.Second):
		t.Fatal("no insight emitted")
	}
}

func TestContradictionEmitsInsightAndFollowupQuestion(t *testing.T) {
	mock := llm.NewMock(`{"claim_a":"Timeline is tight","claim_b":"Staffing is light","evidence_refs":["t-1","t-2"],"severity":"high"}`)
	deps, cleanup := newDeps(t, mock)
	defer cleanup()

	iTopic := tkafka.TopicName(deps.Hash, tkafka.TopicInsightsGenerated)
	tTopic := tkafka.TopicName(deps.Hash, tkafka.TopicThoughtsRaw)

	iCh := make(chan []byte, 1)
	tCh := make(chan []byte, 1)
	_, _ = deps.Bus.Subscribe(iTopic, func(ctx context.Context, m tkafka.Message) error {
		iCh <- append([]byte(nil), m.Value...)
		return nil
	})
	_, _ = deps.Bus.Subscribe(tTopic, func(ctx context.Context, m tkafka.Message) error {
		tCh <- append([]byte(nil), m.Value...)
		return nil
	})

	cmd := schema.ProcessCommand{
		SchemaVer: schema.CurrentSchemaVer,
		ProcessID: uuid.NewString(),
		Step:      schema.Step{Layer: schema.LayerI, Strategy: "contradiction"},
		Spec: schema.ProcessSpec{
			SchemaVer: schema.CurrentSchemaVer, ProcessID: "p-2",
			Intent: "find contradictions", Mode: schema.ModeLinear, Depth: 1,
			Steps: []schema.Step{{Layer: schema.LayerI, Strategy: "contradiction"}},
		},
	}
	if _, err := handleContradiction(context.Background(), deps, cmd); err != nil {
		t.Fatal(err)
	}

	select {
	case raw := <-iCh:
		var ins schema.Insight
		_ = json.Unmarshal(raw, &ins)
		if ins.SynthesisMode != schema.SynthesisContradiction {
			t.Errorf("mode: %s", ins.SynthesisMode)
		}
		if ins.Confidence < 0.85 {
			t.Errorf("high severity should map to high confidence: %f", ins.Confidence)
		}
	case <-time.After(time.Second):
		t.Fatal("no insight")
	}

	select {
	case raw := <-tCh:
		var th schema.Thought
		_ = json.Unmarshal(raw, &th)
		if th.Type != schema.ThoughtQuestion {
			t.Errorf("follow-up thought type = %s, want question", th.Type)
		}
		if th.Source.Kind != schema.SourceAgent {
			t.Errorf("source kind = %s", th.Source.Kind)
		}
	case <-time.After(time.Second):
		t.Fatal("no follow-up question thought emitted")
	}
}

func TestPatternRejectsBadCompletion(t *testing.T) {
	mock := llm.NewMock(`{"no_pattern":"here"}`)
	deps, cleanup := newDeps(t, mock)
	defer cleanup()

	cmd := schema.ProcessCommand{
		SchemaVer: schema.CurrentSchemaVer,
		ProcessID: uuid.NewString(),
		Step:      schema.Step{Layer: schema.LayerI, Strategy: "pattern"},
		Spec: schema.ProcessSpec{
			SchemaVer: schema.CurrentSchemaVer, ProcessID: "p-3",
			Intent: "x", Mode: schema.ModeLinear, Depth: 1,
			Steps: []schema.Step{{Layer: schema.LayerI, Strategy: "pattern"}},
		},
	}
	if _, err := handlePattern(context.Background(), deps, cmd); err == nil {
		t.Error("expected error on missing pattern field")
	}
}
