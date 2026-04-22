// engine_flow_test.go — end-to-end test for the Thinking Engine.
//
// Week 2 (Stream 2a): runs a linear ProcessSpec with real prompts
// (resolved from a test-local in-memory registry) and a mock LLM
// adapter. Asserts:
//
//   1. process state reaches "completed"
//   2. the artifact appears on the artifacts.created topic with the
//      expected format/audience and a structured content shape
//   3. every message published during the run passes schema validation
//   4. the listing endpoints (/v1/thoughts, /v1/reflections, …) serve
//      the live data from the consumer-side cache
//   5. contradictory insights emit a follow-up T of type=question
//      onto thoughts.raw
//
// Skipped in -short mode so the smoke subset of `go test` stays fast.

package thinking_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kamir/m3c-tools/internal/thinking/api"
	"github.com/kamir/m3c-tools/internal/thinking/budget"
	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
	"github.com/kamir/m3c-tools/internal/thinking/feedback"
	tkafka "github.com/kamir/m3c-tools/internal/thinking/kafka"
	"github.com/kamir/m3c-tools/internal/thinking/llm"
	"github.com/kamir/m3c-tools/internal/thinking/orchestrator"
	procA "github.com/kamir/m3c-tools/internal/thinking/processors/a"
	procI "github.com/kamir/m3c-tools/internal/thinking/processors/i"
	procR "github.com/kamir/m3c-tools/internal/thinking/processors/r"
	"github.com/kamir/m3c-tools/internal/thinking/processors"
	"github.com/kamir/m3c-tools/internal/thinking/prompts"
	"github.com/kamir/m3c-tools/internal/thinking/schema"
	"github.com/kamir/m3c-tools/internal/thinking/store"
)

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}

func newLogger(t *testing.T) *log.Logger {
	return log.New(testWriter{t: t}, "[test] ", log.LstdFlags)
}

// testRegistry satisfies prompts.Registry with Week-2 prompt ids
// seeded in-process so the test doesn't need a Flask bridge.
type testRegistry struct{ byID map[string]prompts.Prompt }

func (r *testRegistry) Get(ctx context.Context, id string) (prompts.Prompt, error) {
	p, ok := r.byID[id]
	if !ok {
		return prompts.Prompt{}, &missErr{id: id}
	}
	return p, nil
}

type missErr struct{ id string }

func (e *missErr) Error() string { return "unknown prompt: " + e.id }

func seedRegistry() prompts.Registry {
	return &testRegistry{byID: map[string]prompts.Prompt{
		prompts.StrategyPromptID("r", "compare"):       {ID: prompts.StrategyPromptID("r", "compare"), Version: 1, Body: "compare-template", Model: "mock-llm"},
		prompts.StrategyPromptID("r", "classify"):      {ID: prompts.StrategyPromptID("r", "classify"), Version: 1, Body: "classify-template", Model: "mock-llm"},
		prompts.StrategyPromptID("r", "clarify"):       {ID: prompts.StrategyPromptID("r", "clarify"), Version: 1, Body: "clarify-template", Model: "mock-llm"},
		prompts.StrategyPromptID("i", "pattern"):       {ID: prompts.StrategyPromptID("i", "pattern"), Version: 1, Body: "pattern-template", Model: "mock-llm"},
		prompts.StrategyPromptID("i", "contradiction"): {ID: prompts.StrategyPromptID("i", "contradiction"), Version: 1, Body: "contradiction-template", Model: "mock-llm"},
		prompts.StrategyPromptID("i", "decision"):      {ID: prompts.StrategyPromptID("i", "decision"), Version: 1, Body: "decision-template", Model: "mock-llm"},
		prompts.StrategyPromptID("a", "report"):        {ID: prompts.StrategyPromptID("a", "report"), Version: 1, Body: "report-template", Model: "mock-llm"},
		prompts.StrategyPromptID("a", "summary"):       {ID: prompts.StrategyPromptID("a", "summary"), Version: 1, Body: "summary-template", Model: "mock-llm"},
	}}
}

// mockRouter returns a fixed JSON body for each layer's LLM call.
// Looks at the system prompt template to decide which shape to emit.
func mockRouter(req llm.Request) string {
	sys := ""
	for _, m := range req.Messages {
		if m.Role == "system" {
			sys = m.Content
			break
		}
	}
	switch {
	case strings.Contains(sys, "compare-template"):
		return `{"similarities":["alpha","beta"],"differences":["gamma"]}`
	case strings.Contains(sys, "classify-template"):
		return `{"classification":"risk","confidence":0.83,"rationale":"evidence points to risk"}`
	case strings.Contains(sys, "clarify-template"):
		return `{"question":"Which claim is true?","sub_questions":["a","b"],"context":"x"}`
	case strings.Contains(sys, "pattern-template"):
		return `{"pattern":"deadlines slip on low-staffing sprints","occurrences":[{"week":1},{"week":3}],"confidence":0.74}`
	case strings.Contains(sys, "contradiction-template"):
		return `{"claim_a":"Timeline is tight","claim_b":"Staffing is light","evidence_refs":["t-1"],"severity":"high"}`
	case strings.Contains(sys, "decision-template"):
		return `{"decision":"Ship","rationale":"Evidence favors shipping","confidence":0.7}`
	case strings.Contains(sys, "report-template"):
		return `{"title":"Project risks","sections":[{"heading":"Timeline","body":"Timeline is tight; staffing is light. See I-01 and I-02."}],"key_points":["Timeline tight","Staffing light"]}`
	case strings.Contains(sys, "summary-template"):
		return `{"tl_dr":"Tight timeline, light staffing.","bullets":["Tight schedule","Few engineers"],"sources":["i-01","i-02"]}`
	}
	return "unexpected-prompt"
}

func TestLinearProcessEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("thinking e2e: skipped in -short mode")
	}

	raw, _ := mctx.NewRaw("e2e-user")
	hash := raw.Hash()

	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	innerBus := tkafka.NewMemBus(hash)
	bus, err := tkafka.NewValidatingBus(innerBus, nil)
	if err != nil {
		t.Fatal(err)
	}
	orc := orchestrator.New(hash, bus, st)

	// Subscribe early so we capture every produced message for
	// post-run assertions.
	artifactCh := make(chan []byte, 4)
	reflectionCh := make(chan []byte, 4)
	_, _ = bus.Subscribe(tkafka.TopicName(hash, tkafka.TopicArtifactsCreated), func(ctx context.Context, m tkafka.Message) error {
		artifactCh <- append([]byte(nil), m.Value...)
		return nil
	})
	_, _ = bus.Subscribe(tkafka.TopicName(hash, tkafka.TopicReflectionsGenerated), func(ctx context.Context, m tkafka.Message) error {
		reflectionCh <- append([]byte(nil), m.Value...)
		return nil
	})

	reg := seedRegistry()
	mockLLM := &llm.MockAdapter{Responder: mockRouter, ModelName: "mock-llm"}

	budgetFactory := func(processID string, spec schema.ProcessSpec) *budget.Controller {
		return budget.New(processID, spec.EffectiveMaxTokens(), 100.0, st, budget.StubEstimator{})
	}

	deps := processors.Deps{
		Hash: hash, Bus: bus, Orc: orc, Prompts: reg,
		Log: newLogger(t), LLM: mockLLM, Budgets: budgetFactory,
	}

	// Start the consumer-side cache so /v1/* listings return data.
	cache, err := store.NewCache(store.CacheConfig{
		Store: st, Bus: bus, Hash: hash, Logger: newLogger(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.Start(); err != nil {
		t.Fatal(err)
	}
	defer cache.Stop()

	ctx := t.Context()
	for _, p := range []processors.Processor{procR.New(deps), procI.New(deps), procA.New(deps)} {
		if err := p.Start(ctx); err != nil {
			t.Fatal(err)
		}
	}

	srv := api.New(api.Config{
		OwnerRaw:  raw,
		Hash:      hash,
		Secret:    []byte("t-secret"),
		Bus:       bus,
		Orc:       orc,
		Store:     st,
		BuildInfo: "test",
		Cache:     cache,
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	tok := api.SignToken([]byte("t-secret"), api.Claims{
		CtxID: "e2e-user", Expiry: time.Now().Add(time.Minute), Nonce: "t",
	})

	spec := schema.ProcessSpec{
		SchemaVer: schema.CurrentSchemaVer,
		ProcessID: uuid.NewString(),
		Intent:    "e2e linear",
		Mode:      schema.ModeLinear,
		Depth:     1,
		Steps: []schema.Step{
			{Layer: schema.LayerR, Strategy: "compare"},
			{Layer: schema.LayerI, Strategy: "pattern"},
			{Layer: schema.LayerA, Strategy: "report"},
		},
	}
	body, _ := json.Marshal(spec)

	req, _ := http.NewRequest("POST", ts.URL+"/v1/process", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusAccepted {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /v1/process status=%d body=%s", resp.StatusCode, b)
	}
	resp.Body.Close()

	// 1. Wait for completion.
	deadline := time.Now().Add(3 * time.Second)
	var last map[string]interface{}
	for time.Now().Before(deadline) {
		statusReq, _ := http.NewRequest("GET", ts.URL+"/v1/process/"+spec.ProcessID, nil)
		statusReq.Header.Set("Authorization", "Bearer "+tok)
		sr, err := http.DefaultClient.Do(statusReq)
		if err != nil {
			t.Fatal(err)
		}
		_ = json.NewDecoder(sr.Body).Decode(&last)
		sr.Body.Close()
		if last["state"] == "completed" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if last["state"] != "completed" {
		t.Fatalf("process did not complete: %+v", last)
	}

	// 2. Capture and assert Artifact shape.
	select {
	case raw := <-artifactCh:
		var a schema.Artifact
		if err := json.Unmarshal(raw, &a); err != nil {
			t.Fatal(err)
		}
		if a.Format == "" {
			t.Errorf("artifact.format empty: %+v", a)
		}
		if a.Audience == "" {
			t.Errorf("artifact.audience empty: %+v", a)
		}
		if a.Version < 1 {
			t.Errorf("artifact.version < 1")
		}
		if a.Provenance.IIDs == nil {
			t.Errorf("artifact.provenance.i_ids missing")
		}
		if a.Content == nil || len(a.Content) == 0 {
			t.Errorf("artifact.content empty")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no artifact emitted")
	}

	// 3. Capture Reflection — the LLM mock's structured output should
	// have propagated into the published R payload.
	select {
	case raw := <-reflectionCh:
		var r schema.Reflection
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatal(err)
		}
		if r.Strategy != schema.StrategyCompare {
			t.Errorf("reflection strategy = %s", r.Strategy)
		}
		sims, _ := r.Content["similarities"].([]interface{})
		diffs, _ := r.Content["differences"].([]interface{})
		if len(sims) != 2 || len(diffs) != 1 {
			t.Errorf("compare content shape unexpected: %+v", r.Content)
		}
		if r.Trace.PromptID == "" || r.Trace.Model == "" {
			t.Errorf("trace fields empty: %+v", r.Trace)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no reflection emitted")
	}

	// 4. Listing endpoints served from cache — should include our data.
	listURL := ts.URL + "/v1/artifacts"
	lr, _ := http.NewRequest("GET", listURL, nil)
	lr.Header.Set("Authorization", "Bearer "+tok)
	lresp, err := http.DefaultClient.Do(lr)
	if err != nil {
		t.Fatal(err)
	}
	defer lresp.Body.Close()
	var listed []json.RawMessage
	if err := json.NewDecoder(lresp.Body).Decode(&listed); err != nil {
		t.Fatalf("decode /v1/artifacts: %v", err)
	}
	if len(listed) == 0 {
		t.Errorf("GET /v1/artifacts returned empty — cache not populated")
	}

	// Snapshot LLM mock: every R/I step must have called it.
	if len(mockLLM.Calls) < 2 {
		t.Errorf("expected at least 2 LLM calls (R + I), got %d", len(mockLLM.Calls))
	}
}

func TestMalformedThoughtRejectedByValidator(t *testing.T) {
	if testing.Short() {
		t.Skip("thinking e2e: skipped in -short mode")
	}
	raw, _ := mctx.NewRaw("validator-user")
	hash := raw.Hash()

	innerBus := tkafka.NewMemBus(hash)
	bus, err := tkafka.NewValidatingBus(innerBus, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Producer-side: malformed Thought must be rejected before dispatch.
	bad := map[string]interface{}{
		"thought_id": "t-bad",
		"type":       "not-a-valid-enum",
		"content":    "x",
	}
	err = bus.Produce(context.Background(), tkafka.TopicName(hash, tkafka.TopicThoughtsRaw), "k", bad)
	if err == nil {
		t.Fatalf("expected producer to reject invalid T")
	}
	if !tkafka.IsSchemaValidationError(err) {
		t.Errorf("expected *SchemaValidationError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "schema validation failed") {
		t.Errorf("error message missing expected prefix: %v", err)
	}
}

func TestContradictionEmitsFollowupQuestion(t *testing.T) {
	if testing.Short() {
		t.Skip("thinking e2e: skipped in -short mode")
	}
	raw, _ := mctx.NewRaw("fb-user")
	hash := raw.Hash()

	st, _ := store.Open(":memory:")
	defer st.Close()

	innerBus := tkafka.NewMemBus(hash)
	bus, err := tkafka.NewValidatingBus(innerBus, nil)
	if err != nil {
		t.Fatal(err)
	}
	orc := orchestrator.New(hash, bus, st)

	thoughtCh := make(chan []byte, 4)
	_, _ = bus.Subscribe(tkafka.TopicName(hash, tkafka.TopicThoughtsRaw), func(ctx context.Context, m tkafka.Message) error {
		thoughtCh <- append([]byte(nil), m.Value...)
		return nil
	})

	mockLLM := &llm.MockAdapter{
		Responder: func(req llm.Request) string {
			return `{"claim_a":"A","claim_b":"B","evidence_refs":["t-1"],"severity":"high"}`
		},
		ModelName: "mock-llm",
	}
	reg := &testRegistry{byID: map[string]prompts.Prompt{
		prompts.StrategyPromptID("i", "contradiction"): {ID: prompts.StrategyPromptID("i", "contradiction"), Version: 1, Body: "contradiction-template", Model: "mock-llm"},
	}}
	deps := processors.Deps{
		Hash: hash, Bus: bus, Orc: orc, Prompts: reg, Log: newLogger(t),
		LLM: mockLLM,
	}
	iProc := procI.New(deps)
	if err := iProc.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer iProc.Stop()

	// Fire a command through the command topic.
	spec := schema.ProcessSpec{
		SchemaVer: schema.CurrentSchemaVer, ProcessID: "p-fb",
		Intent: "find contradictions", Mode: schema.ModeLinear, Depth: 1,
		Steps: []schema.Step{{Layer: schema.LayerI, Strategy: "contradiction"}},
	}
	if err := orc.Submit(t.Context(), spec); err != nil {
		t.Fatal(err)
	}

	// Expect one follow-up T of type=question on thoughts.raw.
	select {
	case raw := <-thoughtCh:
		var th schema.Thought
		_ = json.Unmarshal(raw, &th)
		if th.Type != schema.ThoughtQuestion {
			t.Errorf("follow-up type = %s, want question", th.Type)
		}
		if !strings.Contains(th.Source.Ref, "i-proc/contradiction") {
			t.Errorf("follow-up source.ref = %s", th.Source.Ref)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no follow-up question thought")
	}
}

func TestHealthNoAuth(t *testing.T) {
	if testing.Short() {
		t.Skip("thinking e2e: skipped in -short mode")
	}
	raw, _ := mctx.NewRaw("e2e-user")
	hash := raw.Hash()
	st, _ := store.Open(":memory:")
	defer st.Close()
	innerBus := tkafka.NewMemBus(hash)
	bus, _ := tkafka.NewValidatingBus(innerBus, nil)
	orc := orchestrator.New(hash, bus, st)
	srv := api.New(api.Config{
		OwnerRaw: raw, Hash: hash, Secret: []byte("x"),
		Bus: bus, Orc: orc, Store: st, BuildInfo: "test",
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d", resp.StatusCode)
	}
	var h map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&h)
	if h["ctx"] != hash.Hex() {
		t.Errorf("health ctx = %v, want %s", h["ctx"], hash.Hex())
	}
}

// TestSemiLinearHaltsOnStepFailure exercises the Week-3 step barrier.
// A 3-step semi_linear spec deliberately fails in step 2 (the I-proc
// receives a malformed JSON completion). Step 3 (A-proc) must NEVER
// fire — if it did, the orchestrator's barrier is broken.
func TestSemiLinearHaltsOnStepFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("thinking e2e: skipped in -short mode")
	}
	raw, _ := mctx.NewRaw("e2e-semi")
	hash := raw.Hash()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	innerBus := tkafka.NewMemBus(hash)
	bus, err := tkafka.NewValidatingBus(innerBus, nil)
	if err != nil {
		t.Fatal(err)
	}
	orc := orchestrator.New(hash, bus, st)
	if err := orc.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer orc.Stop()

	// Mock LLM: R gets valid JSON, I gets garbage so it fails, A should
	// never be called because the barrier halts.
	var aCalls atomic.Int32
	mockLLM := &llm.MockAdapter{
		Responder: func(req llm.Request) string {
			sys := ""
			for _, m := range req.Messages {
				if m.Role == "system" {
					sys = m.Content
					break
				}
			}
			switch {
			case strings.Contains(sys, "compare-template"):
				return `{"similarities":["x"],"differences":["y"]}`
			case strings.Contains(sys, "pattern-template"):
				// Deliberately malformed — I-proc parses this and fails.
				return `garbage not json`
			case strings.Contains(sys, "report-template"):
				aCalls.Add(1)
				return `{"title":"x","sections":[{"heading":"h","body":"b"}],"key_points":[]}`
			}
			return ""
		},
		ModelName: "mock-llm",
	}

	reg := seedRegistry()
	deps := processors.Deps{
		Hash: hash, Bus: bus, Orc: orc, Prompts: reg, Log: newLogger(t),
		LLM: mockLLM,
		Budgets: func(pid string, s schema.ProcessSpec) *budget.Controller {
			return budget.New(pid, s.EffectiveMaxTokens(), 100.0, st, budget.StubEstimator{})
		},
	}
	for _, p := range []processors.Processor{procR.New(deps), procI.New(deps), procA.New(deps)} {
		if err := p.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
	}

	// Track events so we can assert state transitions.
	evtCh := make(chan schema.ProcessEvent, 32)
	_, _ = bus.Subscribe(tkafka.TopicName(hash, tkafka.TopicProcessEvents), func(ctx context.Context, m tkafka.Message) error {
		var ev schema.ProcessEvent
		if err := json.Unmarshal(m.Value, &ev); err == nil {
			evtCh <- ev
		}
		return nil
	})

	spec := schema.ProcessSpec{
		SchemaVer: schema.CurrentSchemaVer,
		ProcessID: uuid.NewString(),
		Intent:    "semi-linear halt test",
		Mode:      schema.ModeSemiLinear,
		Depth:     1,
		Steps: []schema.Step{
			{Layer: schema.LayerR, Strategy: "compare"},
			{Layer: schema.LayerI, Strategy: "pattern"},
			{Layer: schema.LayerA, Strategy: "report"},
		},
	}
	if err := orc.Submit(t.Context(), spec); err != nil {
		t.Fatal(err)
	}

	// Wait for ProcessFailed.
	deadline := time.Now().Add(3 * time.Second)
	failed := false
	for time.Now().Before(deadline) && !failed {
		select {
		case ev := <-evtCh:
			if ev.Event == schema.EventProcessFailed {
				failed = true
			}
		case <-time.After(50 * time.Millisecond):
		}
	}
	if !failed {
		t.Fatal("process did not fail; step-barrier halt was not triggered")
	}

	// Give the bus a moment to ensure no stray A dispatch happens.
	time.Sleep(250 * time.Millisecond)
	if n := aCalls.Load(); n != 0 {
		t.Errorf("A-proc fired %d times despite step-2 failure; barrier broken", n)
	}

	// Process state should be failed.
	row, err := st.GetProcess(spec.ProcessID)
	if err != nil {
		t.Fatal(err)
	}
	if row.State != store.StateFailed {
		t.Errorf("process state = %s, want failed", row.State)
	}
}

// TestContradictionFeedbackLoopProducesFollowupArtifact exercises the
// Week-3 feedback loop end-to-end:
//
//   1. An initial I/contradiction step emits a follow-up Thought
//      with provenance.parent_artifact_id set.
//   2. The feedback consumer picks that T off thoughts.raw, filters,
//      rate-limits, and posts a default linear spec
//      (R.clarify → I.decision → A.summary) back to the orchestrator.
//   3. The downstream process produces a second Artifact —
//      closing the cognitive loop.
func TestContradictionFeedbackLoopProducesFollowupArtifact(t *testing.T) {
	if testing.Short() {
		t.Skip("thinking e2e: skipped in -short mode")
	}
	raw, _ := mctx.NewRaw("e2e-feedback")
	hash := raw.Hash()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	innerBus := tkafka.NewMemBus(hash)
	bus, err := tkafka.NewValidatingBus(innerBus, nil)
	if err != nil {
		t.Fatal(err)
	}
	orc := orchestrator.New(hash, bus, st)
	if err := orc.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer orc.Stop()

	mockLLM := &llm.MockAdapter{Responder: mockRouter, ModelName: "mock-llm"}
	reg := seedRegistry()

	deps := processors.Deps{
		Hash: hash, Bus: bus, Orc: orc, Prompts: reg, Log: newLogger(t),
		LLM: mockLLM,
		Budgets: func(pid string, s schema.ProcessSpec) *budget.Controller {
			return budget.New(pid, s.EffectiveMaxTokens(), 100.0, st, budget.StubEstimator{})
		},
	}
	for _, p := range []processors.Processor{procR.New(deps), procI.New(deps), procA.New(deps)} {
		if err := p.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
	}

	// Capture artifacts so we can see the follow-up one.
	artifactCh := make(chan []byte, 8)
	_, _ = bus.Subscribe(tkafka.TopicName(hash, tkafka.TopicArtifactsCreated), func(ctx context.Context, m tkafka.Message) error {
		artifactCh <- append([]byte(nil), m.Value...)
		return nil
	})

	// Capture follow-up thoughts so we can assert the loop input shape.
	thoughtCh := make(chan []byte, 8)
	_, _ = bus.Subscribe(tkafka.TopicName(hash, tkafka.TopicThoughtsRaw), func(ctx context.Context, m tkafka.Message) error {
		thoughtCh <- append([]byte(nil), m.Value...)
		return nil
	})

	// Start the feedback consumer.
	fb, err := feedback.New(feedback.Config{
		Hash: hash, Bus: bus, Orchestrator: orc, Store: st,
		Logger: log.New(testWriter{t: t}, "[fb] ", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := fb.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer fb.Stop()

	// Kick off the initial contradiction step.
	spec := schema.ProcessSpec{
		SchemaVer: schema.CurrentSchemaVer,
		ProcessID: uuid.NewString(),
		Intent:    "find contradictions, let feedback loop close",
		Mode:      schema.ModeLinear,
		Depth:     1,
		Steps: []schema.Step{
			{Layer: schema.LayerI, Strategy: "contradiction"},
		},
	}
	if err := orc.Submit(t.Context(), spec); err != nil {
		t.Fatal(err)
	}

	// Expect a follow-up question thought with parent_artifact_id set.
	foundFollowup := false
	deadline := time.Now().Add(2 * time.Second)
	for !foundFollowup && time.Now().Before(deadline) {
		select {
		case body := <-thoughtCh:
			var th schema.Thought
			if err := json.Unmarshal(body, &th); err != nil {
				continue
			}
			if th.Type == schema.ThoughtQuestion && th.Provenance != nil && th.Provenance.ParentArtifactID != nil {
				foundFollowup = true
			}
		case <-time.After(50 * time.Millisecond):
		}
	}
	if !foundFollowup {
		t.Fatal("no follow-up question with parent_artifact_id seen — i-proc wiring regression")
	}

	// Expect an Artifact emitted by the feedback-driven process
	// (A.summary at the end of the default feedback spec).
	var gotSummary bool
	deadline = time.Now().Add(3 * time.Second)
	for !gotSummary && time.Now().Before(deadline) {
		select {
		case body := <-artifactCh:
			var art schema.Artifact
			if err := json.Unmarshal(body, &art); err != nil {
				continue
			}
			if art.Format == schema.FormatSummary {
				gotSummary = true
			}
		case <-time.After(50 * time.Millisecond):
		}
	}
	if !gotSummary {
		t.Fatal("feedback loop did not produce a summary artifact — loop is broken")
	}
}
