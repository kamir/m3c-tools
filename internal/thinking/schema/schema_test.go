package schema

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestThoughtMarshalRoundtrip(t *testing.T) {
	ts := time.Date(2026, 4, 22, 12, 0, 0, 0, time.UTC)
	in := Thought{
		SchemaVer: CurrentSchemaVer,
		ThoughtID: "t-1",
		Type:      ThoughtObservation,
		Content:   Content{Text: "hello"},
		Source:    Source{Kind: SourceTyped, Ref: "manual"},
		Tags:      []string{"demo"},
		Timestamp: ts,
		Provenance: &Provenance{CapturedBy: "test"},
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"schema_ver":1`) {
		t.Errorf("missing schema_ver=1: %s", b)
	}
	if !strings.Contains(string(b), `"content":"hello"`) {
		t.Errorf("inline text content not emitted as string: %s", b)
	}
	var out Thought
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.Content.Text != "hello" {
		t.Errorf("content.text = %q, want hello", out.Content.Text)
	}
	if out.Type != ThoughtObservation {
		t.Errorf("type roundtrip failed")
	}
}

func TestThoughtContentRef(t *testing.T) {
	in := Thought{
		SchemaVer: CurrentSchemaVer,
		ThoughtID: "t-2",
		Type:      ThoughtFact,
		Content:   Content{Ref: "er1://ctx/items/doc-1"},
		Source:    Source{Kind: SourceImport, Ref: "bulk"},
		Timestamp: time.Now().UTC(),
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"ref":"er1://ctx/items/doc-1"`) {
		t.Errorf("ref not marshaled as object: %s", b)
	}
	var out Thought
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.Content.Ref != "er1://ctx/items/doc-1" {
		t.Errorf("ref roundtrip failed")
	}
}

func TestContentRejectsBoth(t *testing.T) {
	c := Content{Text: "x", Ref: "er1://y"}
	if _, err := json.Marshal(c); err == nil {
		t.Errorf("expected error when both Text and Ref set")
	}
}

func TestReflectionInsightArtifact(t *testing.T) {
	r := Reflection{
		SchemaVer:    CurrentSchemaVer,
		ReflectionID: "r-1",
		ThoughtIDs:   []string{"t-1"},
		Strategy:     StrategyCompare,
		Content:      map[string]interface{}{"note": "stub"},
		Trace:        Trace{PromptID: "p1", Model: "stub"},
		Timestamp:    time.Now().UTC(),
	}
	b, _ := json.Marshal(r)
	if !strings.Contains(string(b), `"schema_ver":1`) {
		t.Errorf("reflection missing schema_ver")
	}

	i := Insight{
		SchemaVer:     CurrentSchemaVer,
		InsightID:     "i-1",
		InputIDs:      []string{"r-1"},
		SynthesisMode: SynthesisPattern,
		Content:       map[string]interface{}{"pattern": "x"},
		Confidence:    0.5,
		Trace:         Trace{PromptID: "p1", Model: "stub"},
		Timestamp:     time.Now().UTC(),
	}
	b, _ = json.Marshal(i)
	if !strings.Contains(string(b), `"synthesis_mode":"pattern"`) {
		t.Errorf("insight enum missing: %s", b)
	}

	a := Artifact{
		SchemaVer:  CurrentSchemaVer,
		ArtifactID: "a-1",
		InsightIDs: []string{"i-1"},
		Format:     FormatReport,
		Audience:   AudienceHuman,
		Content:    map[string]interface{}{"title": "x"},
		Version:    1,
		Provenance: ArtifactProvenance{
			TIDs: []string{"t-1"}, RIDs: []string{"r-1"}, IIDs: []string{"i-1"},
		},
		Timestamp: time.Now().UTC(),
	}
	b, _ = json.Marshal(a)
	var out Artifact
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.Version != 1 || out.Format != FormatReport {
		t.Errorf("artifact roundtrip failed: %+v", out)
	}
}

func TestProcessSpecDefaultsAndRoundtrip(t *testing.T) {
	spec := ProcessSpec{
		SchemaVer: CurrentSchemaVer,
		ProcessID: "p-1",
		Intent:    "summarize today",
		Mode:      ModeLinear,
		Depth:     1,
		Steps: []Step{
			{Layer: LayerR, Strategy: "compare"},
			{Layer: LayerA, Strategy: "report"},
		},
	}
	if spec.EffectiveMaxTokens() != DefaultMaxTokens {
		t.Errorf("default tokens = %d, want %d", spec.EffectiveMaxTokens(), DefaultMaxTokens)
	}
	spec.Budget = &Budget{MaxTokens: 1234}
	if spec.EffectiveMaxTokens() != 1234 {
		t.Errorf("override not respected")
	}
	b, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	var out ProcessSpec
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Steps) != 2 || out.Steps[1].Strategy != "report" {
		t.Errorf("step roundtrip failed: %+v", out.Steps)
	}
}

func TestProcessEventSchemaVer(t *testing.T) {
	ev := ProcessEvent{
		SchemaVer: CurrentSchemaVer,
		ProcessID: "p-1",
		Event:     EventProcessStarted,
		Timestamp: time.Now().UTC(),
	}
	b, _ := json.Marshal(ev)
	if !strings.Contains(string(b), `"schema_ver":1`) {
		t.Errorf("process event missing schema_ver: %s", b)
	}
}
