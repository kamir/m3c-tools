// a_test.go — unit tests for the Week-3 Artifact processor.
//
// Covers:
//   - report: LLM output of {title, sections[{heading,body}], key_points}
//     becomes a structured Artifact on artifacts.created with non-empty
//     sections[0].body (Week 3 acceptance criterion).
//   - summary: LLM output of {tl_dr, bullets, sources} becomes a
//     structured Artifact.
//   - Missing required fields (no title; empty body) cause the
//     handler to fail cleanly so the process reports StepFailed.
package a

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

func newDeps(t *testing.T, mock *llm.MockAdapter) (processors.Deps, tkafka.Bus, mctx.Hash, func()) {
	t.Helper()
	raw, _ := mctx.NewRaw("a-test")
	h := raw.Hash()
	inner := tkafka.NewMemBus(h)
	bus, err := tkafka.NewValidatingBus(inner, nil)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	orc := orchestrator.New(h, bus, st)
	reg := &fakeRegistry{prompts: map[string]prompts.Prompt{
		prompts.StrategyPromptID("a", "report"):  {ID: prompts.StrategyPromptID("a", "report"), Version: 1, Body: "report-prompt", Model: "mock-llm"},
		prompts.StrategyPromptID("a", "summary"): {ID: prompts.StrategyPromptID("a", "summary"), Version: 1, Body: "summary-prompt", Model: "mock-llm"},
	}}
	deps := processors.Deps{
		Hash:    h,
		Bus:     bus,
		Orc:     orc,
		Prompts: reg,
		Log:     log.New(os.Stderr, "[a-test] ", 0),
		LLM:     mock,
	}
	return deps, bus, h, func() { _ = st.Close() }
}

func TestReportEmitsStructuredArtifactWithNonEmptyBody(t *testing.T) {
	mock := llm.NewMock(`{"title":"Q1 risks","sections":[{"heading":"Timeline","body":"Schedule slip likely"},{"heading":"Staffing","body":"Two open seats"}],"key_points":["slip","hire"]}`)
	deps, bus, h, cleanup := newDeps(t, mock)
	defer cleanup()

	topic := tkafka.TopicName(h, tkafka.TopicArtifactsCreated)
	captured := make(chan []byte, 1)
	_, _ = bus.Subscribe(topic, func(ctx context.Context, m tkafka.Message) error {
		captured <- append([]byte(nil), m.Value...)
		return nil
	})

	cmd := schema.ProcessCommand{
		SchemaVer: schema.CurrentSchemaVer,
		ProcessID: uuid.NewString(),
		Step: schema.Step{
			Layer:    schema.LayerA,
			Strategy: "report",
			Context: &schema.StepContext{
				Scope: &schema.StepContextScope{Entities: []string{"i-01", "i-02"}},
			},
		},
		Spec: schema.ProcessSpec{
			SchemaVer: schema.CurrentSchemaVer, ProcessID: "p-1",
			Intent: "report risks", Mode: schema.ModeLinear, Depth: 1,
			Steps: []schema.Step{{Layer: schema.LayerA, Strategy: "report"}},
		},
		Timestamp: time.Now().UTC(),
	}
	detail, err := handleReport(context.Background(), deps, cmd)
	if err != nil {
		t.Fatalf("handleReport error: %v", err)
	}
	if id, _ := detail["artifact_id"].(string); id == "" {
		t.Errorf("detail.artifact_id empty: %+v", detail)
	}
	if detail["format"] != "report" {
		t.Errorf("detail.format = %v", detail["format"])
	}

	select {
	case raw := <-captured:
		var art schema.Artifact
		if err := json.Unmarshal(raw, &art); err != nil {
			t.Fatal(err)
		}
		if art.Format != schema.FormatReport {
			t.Errorf("format = %s", art.Format)
		}
		sections, ok := art.Content["sections"].([]interface{})
		if !ok || len(sections) < 2 {
			t.Fatalf("sections not propagated: %+v", art.Content)
		}
		s0, _ := sections[0].(map[string]interface{})
		body, _ := s0["body"].(string)
		if strings.TrimSpace(body) == "" {
			t.Errorf("sections[0].body empty — Week 3 acceptance criterion")
		}
		if len(art.InsightIDs) != 2 {
			t.Errorf("insight_ids = %v (want 2 from context.scope.entities)", art.InsightIDs)
		}
	case <-time.After(time.Second):
		t.Fatal("no artifact emitted")
	}
}

func TestReportRejectsEmptyBody(t *testing.T) {
	// sections[0].body is whitespace only — must be rejected.
	mock := llm.NewMock(`{"title":"x","sections":[{"heading":"h","body":"   "}],"key_points":[]}`)
	deps, _, _, cleanup := newDeps(t, mock)
	defer cleanup()

	cmd := schema.ProcessCommand{
		SchemaVer: schema.CurrentSchemaVer,
		ProcessID: uuid.NewString(),
		Step:      schema.Step{Layer: schema.LayerA, Strategy: "report"},
		Spec: schema.ProcessSpec{
			SchemaVer: schema.CurrentSchemaVer, ProcessID: "p-2", Intent: "x",
			Mode: schema.ModeLinear, Depth: 1,
			Steps: []schema.Step{{Layer: schema.LayerA, Strategy: "report"}},
		},
	}
	if _, err := handleReport(context.Background(), deps, cmd); err == nil {
		t.Fatal("expected error for empty sections[0].body")
	}
}

func TestSummaryEmitsStructuredArtifact(t *testing.T) {
	mock := llm.NewMock(`{"tl_dr":"everything is fine","bullets":["a","b"],"sources":["i-01"]}`)
	deps, bus, h, cleanup := newDeps(t, mock)
	defer cleanup()

	topic := tkafka.TopicName(h, tkafka.TopicArtifactsCreated)
	captured := make(chan []byte, 1)
	_, _ = bus.Subscribe(topic, func(ctx context.Context, m tkafka.Message) error {
		captured <- append([]byte(nil), m.Value...)
		return nil
	})

	cmd := schema.ProcessCommand{
		SchemaVer: schema.CurrentSchemaVer,
		ProcessID: uuid.NewString(),
		Step:      schema.Step{Layer: schema.LayerA, Strategy: "summary"},
		Spec: schema.ProcessSpec{
			SchemaVer: schema.CurrentSchemaVer, ProcessID: "p-3", Intent: "summarise",
			Mode: schema.ModeLinear, Depth: 1,
			Steps: []schema.Step{{Layer: schema.LayerA, Strategy: "summary"}},
		},
	}
	if _, err := handleSummary(context.Background(), deps, cmd); err != nil {
		t.Fatal(err)
	}

	select {
	case raw := <-captured:
		var art schema.Artifact
		if err := json.Unmarshal(raw, &art); err != nil {
			t.Fatal(err)
		}
		if art.Format != schema.FormatSummary {
			t.Errorf("format = %s", art.Format)
		}
		if art.Content["tl_dr"] != "everything is fine" {
			t.Errorf("tl_dr = %v", art.Content["tl_dr"])
		}
	case <-time.After(time.Second):
		t.Fatal("no artifact emitted")
	}
}

func TestSummaryRejectsMissingTLDR(t *testing.T) {
	mock := llm.NewMock(`{"bullets":["a"],"sources":[]}`)
	deps, _, _, cleanup := newDeps(t, mock)
	defer cleanup()

	cmd := schema.ProcessCommand{
		SchemaVer: schema.CurrentSchemaVer,
		ProcessID: uuid.NewString(),
		Step:      schema.Step{Layer: schema.LayerA, Strategy: "summary"},
		Spec: schema.ProcessSpec{
			SchemaVer: schema.CurrentSchemaVer, ProcessID: "p-4", Intent: "x",
			Mode: schema.ModeLinear, Depth: 1,
			Steps: []schema.Step{{Layer: schema.LayerA, Strategy: "summary"}},
		},
	}
	if _, err := handleSummary(context.Background(), deps, cmd); err == nil {
		t.Fatal("expected error when tl_dr is missing")
	}
}
