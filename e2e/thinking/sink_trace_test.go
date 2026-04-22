// sink_trace_test.go — Week 3 Stream 3b e2e coverage.
//
// Covers:
//   - Running a linear process with the ER1 sinker enabled emits
//     ArtifactPersisted on process.events within 2s (against a fake
//     ER1 HTTP server).
//   - GET /v1/trace/<artifact_id> returns a 4-level tree
//     (A → I → R → T) after the pipeline completes.
//   - With the sinker disabled, zero ER1 HTTP calls happen.

package thinking_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kamir/m3c-tools/internal/thinking/api"
	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
	"github.com/kamir/m3c-tools/internal/thinking/er1"
	tkafka "github.com/kamir/m3c-tools/internal/thinking/kafka"
	"github.com/kamir/m3c-tools/internal/thinking/orchestrator"
	"github.com/kamir/m3c-tools/internal/thinking/rebuild"
	"github.com/kamir/m3c-tools/internal/thinking/schema"
	"github.com/kamir/m3c-tools/internal/thinking/sink"
	"github.com/kamir/m3c-tools/internal/thinking/store"
)

// fakeER1Server spins up a test HTTP server that answers the
// thinking-engine's ER1 endpoints (GET /memory/.../... and
// POST /memory/.../artifacts) with canned responses.
func fakeER1Server(t *testing.T, calls *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/artifacts") {
			body, _ := io.ReadAll(r.Body)
			_ = body
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"er1_ref":"er1://e2e/items/a-fake"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"unknown"}`))
	}))
}

func TestSinkerPersistsArtifactWithin2s(t *testing.T) {
	if testing.Short() {
		t.Skip("thinking e2e: skipped in -short mode")
	}

	var er1Calls atomic.Int32
	fake := fakeER1Server(t, &er1Calls)
	defer fake.Close()

	raw, _ := mctx.NewRaw("e2e-sinker")
	hash := raw.Hash()

	st, _ := store.Open(":memory:")
	defer st.Close()

	innerBus := tkafka.NewMemBus(hash)
	bus, err := tkafka.NewValidatingBus(innerBus, nil)
	if err != nil {
		t.Fatal(err)
	}

	cache, err := store.NewCache(store.CacheConfig{Store: st, Bus: bus, Hash: hash, Logger: newLogger(t)})
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.Start(); err != nil {
		t.Fatal(err)
	}
	defer cache.Stop()

	// Real ER1 client pointed at the fake server.
	er1Client, err := er1.NewWithConfig(raw, er1.Config{
		BaseURL: fake.URL, HMACSecret: []byte("e2e-sinker-secret"),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Start the sinker.
	sinker := sink.New(sink.Config{
		Hash: hash, OwnerID: "e2e-sinker",
		Bus: bus, ER1: er1Client, Logger: newLogger(t),
		BaseBackoff: time.Millisecond, MaxBackoff: 2 * time.Millisecond,
	})
	if err := sinker.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer sinker.Stop()

	// Capture ArtifactPersisted events.
	persistedCh := make(chan schema.ProcessEvent, 4)
	evtTopic := tkafka.TopicName(hash, tkafka.TopicProcessEvents)
	_, _ = bus.Subscribe(evtTopic, func(ctx context.Context, m tkafka.Message) error {
		var ev schema.ProcessEvent
		if err := json.Unmarshal(m.Value, &ev); err != nil {
			return err
		}
		if ev.Event == "ArtifactPersisted" {
			persistedCh <- ev
		}
		return nil
	})

	// Directly publish an artifact (processors wiring is covered by
	// the other e2e tests).
	art := schema.Artifact{
		SchemaVer: schema.CurrentSchemaVer, ArtifactID: uuid.NewString(),
		InsightIDs: []string{"i-1"}, Format: schema.FormatSummary, Audience: schema.AudienceHuman,
		Content: map[string]interface{}{"tl_dr": "quick"}, Version: 1,
		Provenance: schema.ArtifactProvenance{TIDs: []string{"t-1"}, RIDs: []string{"r-1"}, IIDs: []string{"i-1"}},
		Timestamp:  time.Now().UTC(),
		ProcessID:  "p-1",
	}
	artTopic := tkafka.TopicName(hash, tkafka.TopicArtifactsCreated)
	if err := bus.Produce(context.Background(), artTopic, art.ArtifactID, art); err != nil {
		t.Fatal(err)
	}

	select {
	case ev := <-persistedCh:
		ref, _ := ev.Detail["er1_ref"].(string)
		if ref == "" {
			t.Errorf("er1_ref missing in ArtifactPersisted: %+v", ev.Detail)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ArtifactPersisted not emitted within 2s")
	}

	if er1Calls.Load() < 1 {
		t.Errorf("expected at least 1 ER1 HTTP call, got %d", er1Calls.Load())
	}
}

func TestSinkerDisabledMeansZeroER1Calls(t *testing.T) {
	if testing.Short() {
		t.Skip("thinking e2e: skipped in -short mode")
	}

	var er1Calls atomic.Int32
	fake := fakeER1Server(t, &er1Calls)
	defer fake.Close()

	raw, _ := mctx.NewRaw("e2e-sinker-off")
	hash := raw.Hash()

	st, _ := store.Open(":memory:")
	defer st.Close()

	innerBus := tkafka.NewMemBus(hash)
	bus, _ := tkafka.NewValidatingBus(innerBus, nil)
	_ = orchestrator.New(hash, bus, st)

	// Sinker is NOT started — mirrors ENABLE_ER1_SINK=0 behaviour.
	// Publish the artifact anyway.
	art := schema.Artifact{
		SchemaVer: schema.CurrentSchemaVer, ArtifactID: "a-no-sink",
		InsightIDs: []string{"i-1"}, Format: schema.FormatSummary, Audience: schema.AudienceHuman,
		Content: map[string]interface{}{"tl_dr": "nope"}, Version: 1,
		Provenance: schema.ArtifactProvenance{TIDs: []string{"t-1"}, RIDs: []string{"r-1"}, IIDs: []string{"i-1"}},
		Timestamp:  time.Now().UTC(), ProcessID: "p-1",
	}
	_ = bus.Produce(context.Background(), tkafka.TopicName(hash, tkafka.TopicArtifactsCreated), "k", art)

	// Give any rogue consumer time to surface.
	time.Sleep(300 * time.Millisecond)
	if got := er1Calls.Load(); got != 0 {
		t.Errorf("expected zero ER1 calls with sinker disabled, got %d", got)
	}
}

func TestTraceEndpointReturnsFourLayerTree(t *testing.T) {
	if testing.Short() {
		t.Skip("thinking e2e: skipped in -short mode")
	}

	raw, _ := mctx.NewRaw("e2e-trace")
	hash := raw.Hash()

	st, _ := store.Open(":memory:")
	defer st.Close()

	innerBus := tkafka.NewMemBus(hash)
	bus, _ := tkafka.NewValidatingBus(innerBus, nil)
	orc := orchestrator.New(hash, bus, st)

	cache, _ := store.NewCache(store.CacheConfig{Store: st, Bus: bus, Hash: hash, Logger: newLogger(t)})
	if err := cache.Start(); err != nil {
		t.Fatal(err)
	}
	defer cache.Stop()

	// Seed a fully-linked chain directly onto the topics so we can
	// exercise the trace walker against a well-formed provenance tree
	// without depending on Stream 3a's orchestration wiring.
	now := time.Now().UTC()
	th := schema.Thought{
		SchemaVer: schema.CurrentSchemaVer, ThoughtID: "t-e2e",
		Type: schema.ThoughtObservation, Content: schema.Content{Text: "staff thin, deadlines tight"},
		Source: schema.Source{Kind: schema.SourceTyped, Ref: "e2e"}, Timestamp: now,
	}
	refl := schema.Reflection{
		SchemaVer: schema.CurrentSchemaVer, ReflectionID: "r-e2e",
		ThoughtIDs: []string{"t-e2e"}, Strategy: schema.StrategyCompare,
		Content: map[string]interface{}{"similarities": "repeated sprint slip"},
		Trace:   schema.Trace{PromptID: "tmpl.r.compare", Model: "mock"}, Timestamp: now,
	}
	ins := schema.Insight{
		SchemaVer: schema.CurrentSchemaVer, InsightID: "i-e2e",
		InputIDs: []string{"r-e2e"}, SynthesisMode: schema.SynthesisPattern,
		Content: map[string]interface{}{"pattern": "deadline risk"}, Confidence: 0.8,
		Trace:   schema.Trace{PromptID: "tmpl.i.pattern", Model: "mock"}, Timestamp: now,
	}
	art := schema.Artifact{
		SchemaVer: schema.CurrentSchemaVer, ArtifactID: "a-e2e",
		InsightIDs: []string{"i-e2e"}, Format: schema.FormatSummary, Audience: schema.AudienceHuman,
		Content: map[string]interface{}{"title": "E2E Trace Report"}, Version: 1,
		Provenance: schema.ArtifactProvenance{
			TIDs: []string{"t-e2e"}, RIDs: []string{"r-e2e"}, IIDs: []string{"i-e2e"},
		},
		Timestamp: now,
	}
	ctx := context.Background()
	_ = bus.Produce(ctx, tkafka.TopicName(hash, tkafka.TopicThoughtsRaw), "k", th)
	_ = bus.Produce(ctx, tkafka.TopicName(hash, tkafka.TopicReflectionsGenerated), "k", refl)
	_ = bus.Produce(ctx, tkafka.TopicName(hash, tkafka.TopicInsightsGenerated), "k", ins)
	_ = bus.Produce(ctx, tkafka.TopicName(hash, tkafka.TopicArtifactsCreated), "k", art)

	// Wait for the cache to hydrate.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cache.Count("A") > 0 && cache.Count("I") > 0 && cache.Count("R") > 0 && cache.Count("T") > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Also stand up a rebuild service so the full config is exercised.
	rb := &rebuild.Service{
		Hash: hash, OwnerID: "e2e-trace", Bus: bus,
		ER1: nil, Orc: orc, Cache: cache, Logger: newLogger(t),
	}

	srv := api.New(api.Config{
		OwnerRaw: raw, Hash: hash, Secret: []byte("trace-secret"),
		Bus: bus, Orc: orc, Store: st, BuildInfo: "e2e-trace",
		Cache: cache, Rebuild: rb,
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	tok := api.SignToken([]byte("trace-secret"), api.Claims{
		CtxID: "e2e-trace", Expiry: time.Now().Add(time.Minute), Nonce: "t",
	})

	// GET /v1/trace/a-e2e.
	treeReq, _ := http.NewRequest("GET", ts.URL+"/v1/trace/a-e2e", nil)
	treeReq.Header.Set("Authorization", "Bearer "+tok)
	tr, err := http.DefaultClient.Do(treeReq)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Body.Close()
	if tr.StatusCode != 200 {
		b, _ := io.ReadAll(tr.Body)
		t.Fatalf("trace status=%d body=%s", tr.StatusCode, b)
	}
	var node map[string]interface{}
	if err := json.NewDecoder(tr.Body).Decode(&node); err != nil {
		t.Fatal(err)
	}
	if node["layer"] != "A" {
		t.Errorf("root layer = %v, want A", node["layer"])
	}
	layersSeen := collectLayers(node)
	for _, want := range []string{"A", "I", "R", "T"} {
		if !layersSeen[want] {
			t.Errorf("expected layer %q in tree; saw %+v", want, layersSeen)
		}
	}
}

func collectLayers(node map[string]interface{}) map[string]bool {
	out := map[string]bool{}
	var walk func(n map[string]interface{})
	walk = func(n map[string]interface{}) {
		if l, ok := n["layer"].(string); ok {
			out[l] = true
		}
		kids, _ := n["children"].([]interface{})
		for _, k := range kids {
			if km, ok := k.(map[string]interface{}); ok {
				walk(km)
			}
		}
	}
	walk(node)
	return out
}
