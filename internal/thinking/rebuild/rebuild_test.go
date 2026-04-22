package rebuild

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"sync"
	"testing"
	"time"

	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
	"github.com/kamir/m3c-tools/internal/thinking/er1"
	tkafka "github.com/kamir/m3c-tools/internal/thinking/kafka"
	"github.com/kamir/m3c-tools/internal/thinking/orchestrator"
	"github.com/kamir/m3c-tools/internal/thinking/schema"
	"github.com/kamir/m3c-tools/internal/thinking/store"
)

type stubER1 struct {
	mu    sync.Mutex
	items []er1.Item
}

func (s *stubER1) GetItem(ctxID, docID string) (er1.Item, error) { return er1.Item{}, nil }
func (s *stubER1) CreateArtifact(ctxID string, a schema.Artifact) (string, error) {
	return "", nil
}
func (s *stubER1) ListItemsSince(ctxID string, since time.Time, limit int) ([]er1.Item, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]er1.Item, 0, len(s.items))
	for _, it := range s.items {
		if since.IsZero() || it.CreatedAt.After(since) {
			out = append(out, it)
		}
	}
	return out, nil
}

func silent() *log.Logger { return log.New(io.Discard, "", 0) }

func mustHash(s string) mctx.Hash {
	r, _ := mctx.NewRaw(s)
	return r.Hash()
}

func setup(t *testing.T) (*store.Store, tkafka.Bus, *store.Cache, *orchestrator.Orchestrator, mctx.Hash) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	hash := mustHash("rebuild-user")
	innerBus := tkafka.NewMemBus(hash)
	bus, err := tkafka.NewValidatingBus(innerBus, nil)
	if err != nil {
		t.Fatal(err)
	}
	cache, err := store.NewCache(store.CacheConfig{Store: st, Bus: bus, Hash: hash, Logger: silent()})
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cache.Stop)
	orc := orchestrator.New(hash, bus, st)
	return st, bus, cache, orc, hash
}

func TestRebuildEmitsThoughtsForNewItems(t *testing.T) {
	_, bus, cache, orc, hash := setup(t)

	now := time.Now().UTC()
	items := []er1.Item{
		{DocID: "t-a", CtxID: "rebuild-user", CreatedAt: now.Add(-time.Hour), Summary: "alpha"},
		{DocID: "t-b", CtxID: "rebuild-user", CreatedAt: now.Add(-30 * time.Minute), Summary: "beta"},
	}
	fakeER1 := &stubER1{items: items}

	thoughtCh := make(chan []byte, 4)
	_, _ = bus.Subscribe(tkafka.TopicName(hash, tkafka.TopicThoughtsRaw), func(ctx context.Context, m tkafka.Message) error {
		thoughtCh <- append([]byte(nil), m.Value...)
		return nil
	})

	s := &Service{
		Hash: hash, OwnerID: "rebuild-user",
		Bus: bus, ER1: fakeER1, Orc: orc, Cache: cache, Logger: silent(),
	}
	res, err := s.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.NewThoughts != 2 {
		t.Errorf("expected 2 new thoughts, got %d", res.NewThoughts)
	}
	if len(res.QueuedProcesses) != 2 {
		t.Errorf("expected 2 queued processes, got %d", len(res.QueuedProcesses))
	}
	if res.RebuildID == "" {
		t.Errorf("empty rebuild_id")
	}

	// Drain the bus.
	deadline := time.Now().Add(500 * time.Millisecond)
	seen := 0
	for time.Now().Before(deadline) && seen < 2 {
		select {
		case <-thoughtCh:
			seen++
		case <-time.After(20 * time.Millisecond):
		}
	}
	if seen < 2 {
		t.Errorf("expected 2 thoughts on wire, saw %d", seen)
	}
}

func TestRebuildDedupsExistingThoughts(t *testing.T) {
	_, bus, cache, orc, hash := setup(t)

	now := time.Now().UTC()
	// Pre-populate the cache with a T that already has id "t-a".
	pre := schema.Thought{
		SchemaVer: schema.CurrentSchemaVer, ThoughtID: "t-a",
		Type: schema.ThoughtObservation, Content: schema.Content{Text: "existing"},
		Source: schema.Source{Kind: schema.SourceTyped, Ref: "pre"},
		Timestamp: now.Add(-time.Hour),
	}
	if err := bus.Produce(context.Background(), tkafka.TopicName(hash, tkafka.TopicThoughtsRaw), "k", pre); err != nil {
		t.Fatal(err)
	}
	// Wait for cache.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) && cache.Count("T") == 0 {
		time.Sleep(5 * time.Millisecond)
	}

	items := []er1.Item{
		{DocID: "t-a", CtxID: "rebuild-user", CreatedAt: now.Add(-30 * time.Minute), Summary: "should-be-skipped"},
		{DocID: "t-b", CtxID: "rebuild-user", CreatedAt: now.Add(-10 * time.Minute), Summary: "new"},
	}
	fakeER1 := &stubER1{items: items}

	s := &Service{
		Hash: hash, OwnerID: "rebuild-user",
		Bus: bus, ER1: fakeER1, Orc: orc, Cache: cache, Logger: silent(),
	}
	res, err := s.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.NewThoughts != 1 {
		t.Errorf("expected 1 new thought after dedup, got %d", res.NewThoughts)
	}
}

func TestRebuildZeroItems(t *testing.T) {
	_, bus, cache, orc, hash := setup(t)
	fakeER1 := &stubER1{items: nil}
	s := &Service{
		Hash: hash, OwnerID: "rebuild-user",
		Bus: bus, ER1: fakeER1, Orc: orc, Cache: cache, Logger: silent(),
	}
	res, err := s.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.NewThoughts != 0 || len(res.QueuedProcesses) != 0 {
		t.Errorf("expected empty result, got %+v", res)
	}
	if res.RebuildID == "" {
		t.Errorf("empty rebuild_id")
	}
}

func TestDefaultProcessSpecShape(t *testing.T) {
	spec := DefaultProcessSpec("t-1")
	if spec.Mode != schema.ModeLinear {
		t.Errorf("mode = %s, want linear", spec.Mode)
	}
	if len(spec.Steps) != 3 {
		t.Fatalf("steps = %d, want 3", len(spec.Steps))
	}
	if spec.Steps[0].Layer != schema.LayerR || spec.Steps[1].Layer != schema.LayerI || spec.Steps[2].Layer != schema.LayerA {
		t.Errorf("unexpected layer sequence: %+v", spec.Steps)
	}
}

func TestThoughtFromItemInlineVsRef(t *testing.T) {
	small := er1.Item{DocID: "t-1", CtxID: "u", Summary: "hi", CreatedAt: time.Now()}
	th := thoughtFromItem(small)
	if th.Content.Text != "hi" {
		t.Errorf("expected inline content, got %+v", th.Content)
	}

	// Large summary → ref content.
	big := make([]byte, 600)
	for i := range big {
		big[i] = 'x'
	}
	large := er1.Item{DocID: "t-2", CtxID: "u", Summary: string(big), CreatedAt: time.Now()}
	th2 := thoughtFromItem(large)
	if th2.Content.Ref == "" {
		t.Errorf("expected ref content for large summary, got %+v", th2.Content)
	}
}

func TestTryBeginMutex(t *testing.T) {
	s := &Service{}
	if !TryBegin(s) {
		t.Fatal("first TryBegin should succeed")
	}
	if TryBegin(s) {
		t.Fatal("second TryBegin should fail while one is in flight")
	}
	End(s)
	if !TryBegin(s) {
		t.Fatal("post-End TryBegin should succeed")
	}
	End(s)
}

// TestRebuildLatestTimestamp asserts that pre-existing T timestamps
// are respected when computing the `since` cutoff for ER1.
func TestRebuildUsesLatestThoughtTimestamp(t *testing.T) {
	_, bus, cache, _, hash := setup(t)

	ts := time.Date(2026, 4, 15, 10, 0, 0, 0, time.UTC)
	pre := schema.Thought{
		SchemaVer: schema.CurrentSchemaVer, ThoughtID: "t-x",
		Type: schema.ThoughtObservation, Content: schema.Content{Text: "old"},
		Source: schema.Source{Kind: schema.SourceTyped, Ref: "pre"},
		Timestamp: ts,
	}
	if err := bus.Produce(context.Background(), tkafka.TopicName(hash, tkafka.TopicThoughtsRaw), "k", pre); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) && cache.Count("T") == 0 {
		time.Sleep(5 * time.Millisecond)
	}

	s := &Service{Hash: hash, Cache: cache, Logger: silent()}
	got := s.latestThoughtTimestamp()
	if !got.Equal(ts) {
		t.Errorf("latest = %s, want %s", got, ts)
	}
	// Sanity: round-trip through JSON marshaling preserves the iso.
	b, _ := json.Marshal(pre)
	var back map[string]interface{}
	_ = json.Unmarshal(b, &back)
	if back["timestamp"] != ts.Format(time.RFC3339Nano) {
		t.Logf("iso form: %v", back["timestamp"])
	}
}
