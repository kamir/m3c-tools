package sink

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
	"github.com/kamir/m3c-tools/internal/thinking/er1"
	tkafka "github.com/kamir/m3c-tools/internal/thinking/kafka"
	"github.com/kamir/m3c-tools/internal/thinking/schema"
)

// fakeER1 records calls + returns scripted results. Implements er1.Client.
type fakeER1 struct {
	mu       sync.Mutex
	calls    int
	failN    int   // first N calls fail with `failErr`
	failErr  error // error to return for failing calls
	lastArt  schema.Artifact
	lastCtx  string
	refToRet string
}

func (f *fakeER1) GetItem(ctxID, docID string) (er1.Item, error) { return er1.Item{}, nil }
func (f *fakeER1) ListItemsSince(ctxID string, since time.Time, limit int) ([]er1.Item, error) {
	return nil, nil
}
func (f *fakeER1) CreateArtifact(ctxID string, a schema.Artifact) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.lastArt = a
	f.lastCtx = ctxID
	if f.calls <= f.failN {
		return "", f.failErr
	}
	if f.refToRet != "" {
		return f.refToRet, nil
	}
	return "er1://test/items/" + a.ArtifactID, nil
}

// silentLogger returns a log.Logger that discards output so tests stay clean.
func silentLogger() *log.Logger { return log.New(io.Discard, "", 0) }

func TestBackoffMath(t *testing.T) {
	s := &Sinker{cfg: Config{BaseBackoff: 100 * time.Millisecond, MaxBackoff: 10 * time.Second}}
	cases := []struct {
		attempt int
		want    time.Duration
	}{
		{0, 100 * time.Millisecond},
		{1, 200 * time.Millisecond},
		{2, 400 * time.Millisecond},
		{3, 800 * time.Millisecond},
		{4, 1600 * time.Millisecond},
	}
	for _, c := range cases {
		got := s.backoff(c.attempt)
		if got != c.want {
			t.Errorf("backoff(%d) = %s, want %s", c.attempt, got, c.want)
		}
	}
}

func TestBackoffCapped(t *testing.T) {
	s := &Sinker{cfg: Config{BaseBackoff: 100 * time.Millisecond, MaxBackoff: 500 * time.Millisecond}}
	if got := s.backoff(10); got != 500*time.Millisecond {
		t.Errorf("expected capped backoff = 500ms, got %s", got)
	}
}

func TestPersistWithRetrySucceedsAfterRetries(t *testing.T) {
	f := &fakeER1{failN: 2, failErr: errors.New("transient")}
	s := New(Config{
		Hash: mustHash("user-A"), OwnerID: "user-A",
		Bus: nil, ER1: f, Logger: silentLogger(),
		MaxAttempts: 5, BaseBackoff: 1 * time.Millisecond, MaxBackoff: 2 * time.Millisecond,
	})
	ref, err := s.persistWithRetry(context.Background(), schema.Artifact{ArtifactID: "a-1"})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if f.calls != 3 {
		t.Errorf("expected 3 calls (2 fail + 1 success), got %d", f.calls)
	}
	if ref == "" {
		t.Errorf("empty ref")
	}
}

func TestPersistWithRetryGivesUp(t *testing.T) {
	f := &fakeER1{failN: 100, failErr: errors.New("boom")}
	s := New(Config{
		Hash: mustHash("user-A"), OwnerID: "user-A",
		Bus: nil, ER1: f, Logger: silentLogger(),
		MaxAttempts: 5, BaseBackoff: 1 * time.Millisecond, MaxBackoff: 2 * time.Millisecond,
	})
	_, err := s.persistWithRetry(context.Background(), schema.Artifact{ArtifactID: "a-1"})
	if err == nil {
		t.Fatal("expected error after exhausting retries")
	}
	if f.calls != 5 {
		t.Errorf("expected 5 attempts, got %d", f.calls)
	}
}

func TestPersistWithRetryStopsOn4xx(t *testing.T) {
	f := &fakeER1{failN: 100, failErr: &er1.HTTPError{Status: 400, Body: "bad"}}
	s := New(Config{
		Hash: mustHash("user-A"), OwnerID: "user-A",
		Bus: nil, ER1: f, Logger: silentLogger(),
		MaxAttempts: 5, BaseBackoff: 1 * time.Millisecond, MaxBackoff: 2 * time.Millisecond,
	})
	_, err := s.persistWithRetry(context.Background(), schema.Artifact{ArtifactID: "a-1"})
	if err == nil {
		t.Fatal("expected error")
	}
	if f.calls != 1 {
		t.Errorf("expected 1 attempt for 4xx, got %d", f.calls)
	}
}

func TestEndToEndEmitsArtifactPersisted(t *testing.T) {
	raw, _ := mctx.NewRaw("user-A")
	hash := raw.Hash()

	innerBus := tkafka.NewMemBus(hash)
	bus, err := tkafka.NewValidatingBus(innerBus, nil)
	if err != nil {
		t.Fatal(err)
	}

	f := &fakeER1{refToRet: "er1://user-A/items/a-42"}
	s := New(Config{
		Hash: hash, OwnerID: "user-A",
		Bus: bus, ER1: f, Logger: silentLogger(),
		BaseBackoff: time.Millisecond, MaxBackoff: 2 * time.Millisecond,
	})

	// Subscribe to process.events to catch the ArtifactPersisted event.
	eventsCh := make(chan schema.ProcessEvent, 4)
	evtTopic := tkafka.TopicName(hash, tkafka.TopicProcessEvents)
	_, err = bus.Subscribe(evtTopic, func(ctx context.Context, m tkafka.Message) error {
		var ev schema.ProcessEvent
		if err := json.Unmarshal(m.Value, &ev); err != nil {
			return err
		}
		eventsCh <- ev
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()

	// Publish an Artifact to artifacts.created — the schema-validating
	// bus will validate, and the sinker will pick it up.
	art := schema.Artifact{
		SchemaVer: schema.CurrentSchemaVer, ArtifactID: "a-42",
		InsightIDs: []string{"i-1"},
		Format:     schema.FormatSummary, Audience: schema.AudienceHuman,
		Content: map[string]interface{}{"tl_dr": "ok"}, Version: 1,
		Provenance: schema.ArtifactProvenance{TIDs: []string{"t-1"}, RIDs: []string{"r-1"}, IIDs: []string{"i-1"}},
		Timestamp:  time.Now().UTC(), ProcessID: "p-1",
	}
	artTopic := tkafka.TopicName(hash, tkafka.TopicArtifactsCreated)
	if err := bus.Produce(context.Background(), artTopic, "k", art); err != nil {
		t.Fatal(err)
	}

	select {
	case ev := <-eventsCh:
		if ev.Event != "ArtifactPersisted" {
			t.Errorf("expected ArtifactPersisted, got %s", ev.Event)
		}
		if ev.Detail["artifact_id"] != "a-42" {
			t.Errorf("detail missing artifact_id: %+v", ev.Detail)
		}
		if ev.Detail["er1_ref"] != "er1://user-A/items/a-42" {
			t.Errorf("detail wrong er1_ref: %+v", ev.Detail)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no ArtifactPersisted event within 2s")
	}

	if f.calls != 1 {
		t.Errorf("expected 1 ER1 call, got %d", f.calls)
	}
}

func TestEndToEndEmitsFailureAfterCap(t *testing.T) {
	raw, _ := mctx.NewRaw("user-A")
	hash := raw.Hash()

	innerBus := tkafka.NewMemBus(hash)
	bus, err := tkafka.NewValidatingBus(innerBus, nil)
	if err != nil {
		t.Fatal(err)
	}

	f := &fakeER1{failN: 100, failErr: errors.New("ER1 down")}
	s := New(Config{
		Hash: hash, OwnerID: "user-A",
		Bus: bus, ER1: f, Logger: silentLogger(),
		MaxAttempts: 3, BaseBackoff: 1 * time.Millisecond, MaxBackoff: 2 * time.Millisecond,
	})

	evCh := make(chan schema.ProcessEvent, 4)
	evtTopic := tkafka.TopicName(hash, tkafka.TopicProcessEvents)
	_, _ = bus.Subscribe(evtTopic, func(ctx context.Context, m tkafka.Message) error {
		var ev schema.ProcessEvent
		_ = json.Unmarshal(m.Value, &ev)
		evCh <- ev
		return nil
	})

	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()

	art := schema.Artifact{
		SchemaVer: schema.CurrentSchemaVer, ArtifactID: "a-99",
		InsightIDs: []string{"i-1"},
		Format:     schema.FormatSummary, Audience: schema.AudienceHuman,
		Content: map[string]interface{}{"tl_dr": "ok"}, Version: 1,
		Provenance: schema.ArtifactProvenance{TIDs: []string{"t-1"}, RIDs: []string{"r-1"}, IIDs: []string{"i-1"}},
		Timestamp:  time.Now().UTC(), ProcessID: "p-9",
	}
	artTopic := tkafka.TopicName(hash, tkafka.TopicArtifactsCreated)
	if err := bus.Produce(context.Background(), artTopic, "k", art); err != nil {
		t.Fatal(err)
	}

	select {
	case ev := <-evCh:
		if ev.Event != "ArtifactPersistenceFailed" {
			t.Errorf("expected ArtifactPersistenceFailed, got %s", ev.Event)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no failure event within 3s")
	}

	if f.calls != 3 {
		t.Errorf("expected 3 attempts (MaxAttempts), got %d", f.calls)
	}
}

func TestEnabledToggle(t *testing.T) {
	cases := []struct {
		val  string
		want bool
	}{
		{"", false},
		{"0", false},
		{"no", false},
		{"1", true},
		{"true", true},
		{"TRUE", true},
	}
	for _, c := range cases {
		got := Enabled(func(k string) string {
			if k == "ENABLE_ER1_SINK" {
				return c.val
			}
			return ""
		})
		if got != c.want {
			t.Errorf("Enabled(%q) = %v, want %v", c.val, got, c.want)
		}
	}
}

// TestCtxGuardPassesThrough asserts the sinker uses the configured
// OwnerID (not anything from the artifact payload) — so ctx-guard on
// the ER1 client stays symmetric with the engine's own ctx.
func TestSinkUsesConfiguredCtx(t *testing.T) {
	raw, _ := mctx.NewRaw("user-A")
	hash := raw.Hash()

	innerBus := tkafka.NewMemBus(hash)
	bus, _ := tkafka.NewValidatingBus(innerBus, nil)

	var ctxSeen atomic.Value
	f := &fakeER1{}
	fWrap := &ctxCaptor{inner: f, seen: &ctxSeen}

	s := New(Config{
		Hash: hash, OwnerID: "user-A",
		Bus: bus, ER1: fWrap, Logger: silentLogger(),
		BaseBackoff: time.Millisecond, MaxBackoff: 2 * time.Millisecond,
	})
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()

	art := schema.Artifact{
		SchemaVer: schema.CurrentSchemaVer, ArtifactID: "a-7",
		InsightIDs: []string{"i-1"},
		Format:     schema.FormatSummary, Audience: schema.AudienceHuman,
		Content: map[string]interface{}{"tl_dr": "ok"}, Version: 1,
		Provenance: schema.ArtifactProvenance{TIDs: []string{"t-1"}, RIDs: []string{"r-1"}, IIDs: []string{"i-1"}},
		Timestamp:  time.Now().UTC(), ProcessID: "p-1",
	}
	_ = bus.Produce(context.Background(), tkafka.TopicName(hash, tkafka.TopicArtifactsCreated), "k", art)

	// Give the async handler a moment.
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		if v := ctxSeen.Load(); v != nil {
			if got := v.(string); got != "user-A" {
				t.Errorf("ER1 saw ctx=%q, want user-A", got)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("ER1 was never called")
}

type ctxCaptor struct {
	inner er1.Client
	seen  *atomic.Value
}

func (c *ctxCaptor) GetItem(ctxID, docID string) (er1.Item, error) { return c.inner.GetItem(ctxID, docID) }
func (c *ctxCaptor) ListItemsSince(ctxID string, since time.Time, limit int) ([]er1.Item, error) {
	return c.inner.ListItemsSince(ctxID, since, limit)
}
func (c *ctxCaptor) CreateArtifact(ctxID string, a schema.Artifact) (string, error) {
	c.seen.Store(ctxID)
	return c.inner.CreateArtifact(ctxID, a)
}

func mustHash(s string) mctx.Hash {
	r, err := mctx.NewRaw(s)
	if err != nil {
		panic(err)
	}
	return r.Hash()
}
