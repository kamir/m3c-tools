package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
	tkafka "github.com/kamir/m3c-tools/internal/thinking/kafka"
)

func newTestHashAndBus(t *testing.T) (mctx.Hash, tkafka.Bus) {
	raw, err := mctx.NewRaw("cache-user")
	if err != nil {
		t.Fatal(err)
	}
	h := raw.Hash()
	inner := tkafka.NewMemBus(h)
	vb, err := tkafka.NewValidatingBus(inner, nil)
	if err != nil {
		t.Fatal(err)
	}
	return h, vb
}

func TestCacheIngestAndList(t *testing.T) {
	st, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	h, bus := newTestHashAndBus(t)
	c, err := NewCache(CacheConfig{Store: st, Bus: bus, Hash: h})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	defer c.Stop()

	ts := time.Now().UTC().Format(time.RFC3339Nano)
	t1 := map[string]any{
		"schema_ver": 1, "thought_id": "t-1", "type": "observation",
		"content": "hello", "source": map[string]any{"kind": "typed", "ref": "m"},
		"timestamp": ts,
	}
	topic := tkafka.TopicName(h, tkafka.TopicThoughtsRaw)
	if err := bus.Produce(context.Background(), topic, "t-1", t1); err != nil {
		t.Fatal(err)
	}

	// in-memory dispatch is async; poll briefly.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && c.Count("T") == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if c.Count("T") != 1 {
		t.Fatalf("expected 1 T item, got %d", c.Count("T"))
	}
	items := c.List("T", time.Time{}, "", 10)
	if len(items) != 1 {
		t.Fatalf("List len = %d", len(items))
	}
	var decoded map[string]any
	_ = json.Unmarshal(items[0], &decoded)
	if decoded["thought_id"] != "t-1" {
		t.Errorf("bad id: %v", decoded["thought_id"])
	}
}

func TestCacheParentFilter(t *testing.T) {
	st, _ := Open(":memory:")
	defer st.Close()
	h, bus := newTestHashAndBus(t)
	c, _ := NewCache(CacheConfig{Store: st, Bus: bus, Hash: h})
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	defer c.Stop()

	ts := time.Now().UTC().Format(time.RFC3339Nano)
	r1 := map[string]any{
		"schema_ver": 1, "reflection_id": "r-1", "thought_ids": []string{"t-1", "t-2"},
		"strategy": "compare", "content": map[string]any{},
		"trace": map[string]any{"prompt_id": "p", "model": "m"}, "timestamp": ts,
	}
	r2 := map[string]any{
		"schema_ver": 1, "reflection_id": "r-2", "thought_ids": []string{"t-3"},
		"strategy": "compare", "content": map[string]any{},
		"trace": map[string]any{"prompt_id": "p", "model": "m"}, "timestamp": ts,
	}
	rt := tkafka.TopicName(h, tkafka.TopicReflectionsGenerated)
	_ = bus.Produce(context.Background(), rt, "r-1", r1)
	_ = bus.Produce(context.Background(), rt, "r-2", r2)

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && c.Count("R") < 2 {
		time.Sleep(10 * time.Millisecond)
	}

	// Filter for reflections by thought_id t-2 — must only return r-1.
	out := c.List("R", time.Time{}, "t-2", 10)
	if len(out) != 1 {
		t.Fatalf("expected 1, got %d", len(out))
	}
	var decoded map[string]any
	_ = json.Unmarshal(out[0], &decoded)
	if decoded["reflection_id"] != "r-1" {
		t.Errorf("wrong reflection: %v", decoded["reflection_id"])
	}
}

func TestCacheWarmsFromStore(t *testing.T) {
	st, _ := Open(":memory:")
	defer st.Close()
	h, bus := newTestHashAndBus(t)

	now := time.Now().UTC()
	seed := MsgCacheRow{
		ID: "t-seed", Layer: "T",
		Payload: []byte(`{"thought_id":"t-seed"}`), Timestamp: now,
	}
	if err := st.UpsertMsgCache(seed); err != nil {
		t.Fatal(err)
	}

	c, err := NewCache(CacheConfig{Store: st, Bus: bus, Hash: h})
	if err != nil {
		t.Fatal(err)
	}
	if c.Count("T") != 1 {
		t.Errorf("expected warmed T count 1, got %d", c.Count("T"))
	}
}

func TestPromptCacheRoundtrip(t *testing.T) {
	st, _ := Open(":memory:")
	defer st.Close()
	row := PromptCacheRow{
		ID: "p-1", Version: 3, Body: "hello", Model: "gpt-4o-mini",
		ETag: "etag-v3", FetchedAt: time.Now().UTC(),
	}
	if err := st.UpsertPromptCache(row); err != nil {
		t.Fatal(err)
	}
	// Update (version bump) should overwrite.
	row.Version = 4
	row.Body = "hello v4"
	if err := st.UpsertPromptCache(row); err != nil {
		t.Fatal(err)
	}
	all, err := st.LoadPromptCache()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Fatalf("expected 1, got %d", len(all))
	}
	if all[0].Version != 4 || all[0].Body != "hello v4" {
		t.Errorf("upsert not applied: %+v", all[0])
	}
}
