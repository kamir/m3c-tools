package api

import (
	"context"
	"io"
	"log"
	"testing"
	"time"

	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
	tkafka "github.com/kamir/m3c-tools/internal/thinking/kafka"
	"github.com/kamir/m3c-tools/internal/thinking/schema"
	"github.com/kamir/m3c-tools/internal/thinking/store"
)

func silentLogger() *log.Logger { return log.New(io.Discard, "", 0) }

// seedCacheWithChain publishes one T → R → I → A chain through the
// validating bus so the cache picks them up, returning the full
// topology for assertions.
func seedCacheWithChain(t *testing.T) (*store.Cache, string) {
	t.Helper()
	raw, _ := mctx.NewRaw("trace-user")
	hash := raw.Hash()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	innerBus := tkafka.NewMemBus(hash)
	bus, err := tkafka.NewValidatingBus(innerBus, nil)
	if err != nil {
		t.Fatal(err)
	}
	cache, err := store.NewCache(store.CacheConfig{Store: st, Bus: bus, Hash: hash, Logger: silentLogger()})
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cache.Stop)

	now := time.Now().UTC()

	// T node.
	th := schema.Thought{
		SchemaVer: schema.CurrentSchemaVer, ThoughtID: "t-1",
		Type: schema.ThoughtObservation, Content: schema.Content{Text: "staff is thin and deadlines are tight"},
		Source: schema.Source{Kind: schema.SourceTyped, Ref: "test"}, Timestamp: now,
	}
	if err := bus.Produce(context.Background(), tkafka.TopicName(hash, tkafka.TopicThoughtsRaw), "k", th); err != nil {
		t.Fatal(err)
	}
	// R node referencing T.
	refl := schema.Reflection{
		SchemaVer: schema.CurrentSchemaVer, ReflectionID: "r-1",
		ThoughtIDs: []string{"t-1"}, Strategy: schema.StrategyCompare,
		Content: map[string]interface{}{"similarities": "matching deadlines"},
		Trace:   schema.Trace{PromptID: "tmpl.r.compare", Model: "mock"}, Timestamp: now,
	}
	if err := bus.Produce(context.Background(), tkafka.TopicName(hash, tkafka.TopicReflectionsGenerated), "k", refl); err != nil {
		t.Fatal(err)
	}
	// I node referencing R.
	ins := schema.Insight{
		SchemaVer: schema.CurrentSchemaVer, InsightID: "i-1",
		InputIDs: []string{"r-1"}, SynthesisMode: schema.SynthesisPattern,
		Content: map[string]interface{}{"pattern": "deadline slip on thin weeks"}, Confidence: 0.8,
		Trace:   schema.Trace{PromptID: "tmpl.i.pattern", Model: "mock"}, Timestamp: now,
	}
	if err := bus.Produce(context.Background(), tkafka.TopicName(hash, tkafka.TopicInsightsGenerated), "k", ins); err != nil {
		t.Fatal(err)
	}
	// A node.
	art := schema.Artifact{
		SchemaVer: schema.CurrentSchemaVer, ArtifactID: "a-1",
		InsightIDs: []string{"i-1"}, Format: schema.FormatSummary, Audience: schema.AudienceHuman,
		Content: map[string]interface{}{"title": "Deadline Risk Report"},
		Version: 1,
		Provenance: schema.ArtifactProvenance{
			TIDs: []string{"t-1"}, RIDs: []string{"r-1"}, IIDs: []string{"i-1"},
		},
		Timestamp: now,
	}
	if err := bus.Produce(context.Background(), tkafka.TopicName(hash, tkafka.TopicArtifactsCreated), "k", art); err != nil {
		t.Fatal(err)
	}

	// Give the async mem bus a moment to drain.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if cache.Count("A") >= 1 && cache.Count("I") >= 1 && cache.Count("R") >= 1 && cache.Count("T") >= 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cache, "a-1"
}

func TestBuildTraceReturnsFullTree(t *testing.T) {
	cache, artifactID := seedCacheWithChain(t)

	tree, ok := buildTrace(cache, artifactID)
	if !ok {
		t.Fatal("expected tree; artifact not found")
	}
	if tree.Layer != "A" || tree.ID != "a-1" {
		t.Errorf("root wrong: %+v", tree)
	}
	if len(tree.Children) != 1 || tree.Children[0].Layer != "I" || tree.Children[0].ID != "i-1" {
		t.Errorf("I children wrong: %+v", tree.Children)
	}
	iNode := tree.Children[0]
	if len(iNode.Children) != 1 || iNode.Children[0].Layer != "R" || iNode.Children[0].ID != "r-1" {
		t.Errorf("R children wrong: %+v", iNode.Children)
	}
	rNode := iNode.Children[0]
	if len(rNode.Children) != 1 || rNode.Children[0].Layer != "T" || rNode.Children[0].ID != "t-1" {
		t.Errorf("T children wrong: %+v", rNode.Children)
	}
	// Summaries.
	if tree.Summary == "" {
		t.Errorf("A summary empty")
	}
	if rNode.Children[0].Summary == "" {
		t.Errorf("T summary empty")
	}
}

func TestBuildTraceMissingIntermediate(t *testing.T) {
	cache, _ := seedCacheWithChain(t)
	// Walker for a non-existent Insight reference — we simulate by
	// asking for an artifact that doesn't exist in the cache.
	_, ok := buildTrace(cache, "does-not-exist")
	if ok {
		t.Errorf("expected tree not found for unknown artifact")
	}
}

func TestBuildTraceGracefulMissingChild(t *testing.T) {
	// Seed an artifact whose i_ids reference an insight that was never
	// published — walker should return an I leaf with error=missing,
	// never crash.
	raw, _ := mctx.NewRaw("trace-user-2")
	hash := raw.Hash()
	st, _ := store.Open(":memory:")
	t.Cleanup(func() { st.Close() })
	innerBus := tkafka.NewMemBus(hash)
	bus, _ := tkafka.NewValidatingBus(innerBus, nil)
	cache, _ := store.NewCache(store.CacheConfig{Store: st, Bus: bus, Hash: hash, Logger: silentLogger()})
	_ = cache.Start()
	t.Cleanup(cache.Stop)

	art := schema.Artifact{
		SchemaVer: schema.CurrentSchemaVer, ArtifactID: "a-miss",
		InsightIDs: []string{"i-missing"}, Format: schema.FormatSummary, Audience: schema.AudienceHuman,
		Content: map[string]interface{}{"title": "X"}, Version: 1,
		Provenance: schema.ArtifactProvenance{
			TIDs: []string{}, RIDs: []string{}, IIDs: []string{"i-missing"},
		},
		Timestamp: time.Now().UTC(),
	}
	_ = bus.Produce(context.Background(), tkafka.TopicName(hash, tkafka.TopicArtifactsCreated), "k", art)

	// wait for cache
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) && cache.Count("A") == 0 {
		time.Sleep(5 * time.Millisecond)
	}

	tree, ok := buildTrace(cache, "a-miss")
	if !ok {
		t.Fatal("expected tree for a-miss")
	}
	if len(tree.Children) != 1 {
		t.Fatalf("expected 1 child, got %d", len(tree.Children))
	}
	child := tree.Children[0]
	if child.Layer != "I" || child.Error != "missing" {
		t.Errorf("expected missing I leaf, got %+v", child)
	}
}

func TestTruncate(t *testing.T) {
	cases := []struct{ in, want string }{
		{"short", "short"},
		{"0123456789012345678901234567890123456789012345678901234567890123456789012345678912345", "0123456789012345678901234567890123456789012345678901234567890123456789012345678912345"[:80] + "…"},
	}
	for _, c := range cases {
		if got := truncate(c.in, 80); got != c.want {
			t.Errorf("truncate(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
