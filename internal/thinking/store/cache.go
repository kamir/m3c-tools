// cache.go — consumer-side read cache.
//
// The Thinking Engine publishes T/R/I/A onto dedicated topics.
// Listing endpoints (/v1/thoughts, /v1/reflections, /v1/insights,
// /v1/artifacts) and the Trace walker (Week 3) need fast,
// indexed access — not a full Kafka log replay.
//
// This cache subscribes to the four topics, maintains a capped
// in-memory windowed index, and mirrors to SQLite (store.msg_cache)
// so the engine survives restarts without having to re-read the
// log from offset 0.
//
// Design notes:
//   - Ordering: we key on id, so late messages overwrite earlier
//     (shouldn't happen in practice — Kafka is append-only — but
//     if it does the later write wins).
//   - Validation is the ValidatingBus's job. This cache trusts
//     payloads because it subscribed via the validated bus.
//   - Windowed: the in-memory window keeps the last N items per
//     layer (default 1000). SQLite keeps everything until a
//     retention job comes along (out of Phase 1 scope).
package store

import (
	"context"
	"encoding/json"
	"log"
	"sort"
	"sync"
	"time"

	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
	tkafka "github.com/kamir/m3c-tools/internal/thinking/kafka"
)

// DefaultCacheWindow is the in-memory cap per layer.
const DefaultCacheWindow = 1000

// Cache subscribes to T/R/I/A topics and serves list queries from a
// windowed in-memory index + SQLite mirror.
type Cache struct {
	store  *Store
	bus    tkafka.Bus
	hash   mctx.Hash
	log    *log.Logger
	window int

	mu    sync.RWMutex
	items map[string][]cacheItem // layer → newest-first slice

	stops []func()
}

type cacheItem struct {
	ID        string
	Payload   []byte
	Timestamp time.Time
	ParentIDs []string
}

// CacheConfig wires a new Cache. Bus MUST already be a ValidatingBus
// so payloads are known good by the time this cache sees them.
type CacheConfig struct {
	Store  *Store
	Bus    tkafka.Bus
	Hash   mctx.Hash
	Logger *log.Logger
	Window int // defaults to DefaultCacheWindow
}

// NewCache creates the cache and warms it from SQLite. Call Start to
// begin consuming live.
func NewCache(cfg CacheConfig) (*Cache, error) {
	if cfg.Store == nil {
		return nil, errMissing("store")
	}
	if cfg.Bus == nil {
		return nil, errMissing("bus")
	}
	if cfg.Window <= 0 {
		cfg.Window = DefaultCacheWindow
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.Default()
	}
	c := &Cache{
		store:  cfg.Store,
		bus:    cfg.Bus,
		hash:   cfg.Hash,
		log:    logger,
		window: cfg.Window,
		items:  map[string][]cacheItem{"T": {}, "R": {}, "I": {}, "A": {}},
	}
	// Warm in-memory index from SQLite (newest first, capped to window).
	for _, layer := range []string{"T", "R", "I", "A"} {
		rows, err := cfg.Store.ListMsgCache(layer, time.Time{}, "", cfg.Window)
		if err != nil {
			return nil, err
		}
		seed := make([]cacheItem, 0, len(rows))
		for _, r := range rows {
			seed = append(seed, cacheItem{
				ID: r.ID, Payload: r.Payload, Timestamp: r.Timestamp, ParentIDs: r.ParentIDs,
			})
		}
		c.items[layer] = seed
	}
	return c, nil
}

// Start subscribes to the four T/R/I/A topics.
func (c *Cache) Start() error {
	subs := []struct {
		layer  string
		suffix tkafka.TopicSuffix
		parent func(map[string]interface{}) []string
	}{
		{"T", tkafka.TopicThoughtsRaw, nil},
		{"R", tkafka.TopicReflectionsGenerated, parentsFromKey("thought_ids")},
		{"I", tkafka.TopicInsightsGenerated, parentsFromKey("input_ids")},
		{"A", tkafka.TopicArtifactsCreated, parentsFromInsightIDs},
	}
	for _, s := range subs {
		topic := tkafka.TopicName(c.hash, s.suffix)
		layer := s.layer
		parent := s.parent
		stop, err := c.bus.Subscribe(topic, func(ctx context.Context, m tkafka.Message) error {
			return c.ingest(layer, m, parent)
		})
		if err != nil {
			return err
		}
		c.stops = append(c.stops, stop)
	}
	return nil
}

// Stop unsubscribes from all topics.
func (c *Cache) Stop() {
	for _, s := range c.stops {
		if s != nil {
			s()
		}
	}
	c.stops = nil
}

func (c *Cache) ingest(layer string, m tkafka.Message, parentFn func(map[string]interface{}) []string) error {
	var parsed map[string]interface{}
	if err := json.Unmarshal(m.Value, &parsed); err != nil {
		c.log.Printf("cache: malformed %s payload: %v", layer, err)
		return nil
	}
	id := idForLayer(layer, parsed)
	if id == "" {
		return nil
	}
	ts := timestampFrom(parsed)
	var parents []string
	if parentFn != nil {
		parents = parentFn(parsed)
	}

	item := cacheItem{ID: id, Payload: append([]byte(nil), m.Value...), Timestamp: ts, ParentIDs: parents}

	c.mu.Lock()
	list := c.items[layer]
	// Overwrite by id if exists.
	replaced := false
	for i, existing := range list {
		if existing.ID == id {
			list[i] = item
			replaced = true
			break
		}
	}
	if !replaced {
		list = append(list, item)
	}
	// Sort newest-first and trim to window.
	sort.Slice(list, func(i, j int) bool { return list[i].Timestamp.After(list[j].Timestamp) })
	if len(list) > c.window {
		list = list[:c.window]
	}
	c.items[layer] = list
	c.mu.Unlock()

	// Best-effort mirror to SQLite. A failure here doesn't block the
	// in-memory index; we log and continue.
	if err := c.store.UpsertMsgCache(MsgCacheRow{
		ID: id, Layer: layer, Payload: item.Payload, Timestamp: ts, ParentIDs: parents,
	}); err != nil {
		c.log.Printf("cache: sqlite mirror %s/%s: %v", layer, id, err)
	}
	return nil
}

// List returns raw payloads for the given layer, newest first,
// optionally filtered by timestamp-since and/or parentID. Payloads
// are the JSON wire-format — the caller decodes into schema types.
func (c *Cache) List(layer string, since time.Time, parentID string, limit int) [][]byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	list := c.items[layer]
	out := make([][]byte, 0, len(list))
	for _, item := range list {
		if !since.IsZero() && item.Timestamp.Before(since) {
			continue
		}
		if parentID != "" {
			ok := false
			for _, p := range item.ParentIDs {
				if p == parentID {
					ok = true
					break
				}
			}
			if !ok {
				continue
			}
		}
		out = append(out, item.Payload)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

// Count returns the current in-memory count for a layer.
func (c *Cache) Count(layer string) int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items[layer])
}

// ----- helpers -----

func idForLayer(layer string, m map[string]interface{}) string {
	var key string
	switch layer {
	case "T":
		key = "thought_id"
	case "R":
		key = "reflection_id"
	case "I":
		key = "insight_id"
	case "A":
		key = "artifact_id"
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func timestampFrom(m map[string]interface{}) time.Time {
	s, ok := m["timestamp"].(string)
	if !ok {
		return time.Now().UTC()
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t, err = time.Parse(time.RFC3339, s)
		if err != nil {
			return time.Now().UTC()
		}
	}
	return t
}

func parentsFromKey(k string) func(map[string]interface{}) []string {
	return func(m map[string]interface{}) []string {
		raw, ok := m[k].([]interface{})
		if !ok {
			return nil
		}
		out := make([]string, 0, len(raw))
		for _, v := range raw {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
}

func parentsFromInsightIDs(m map[string]interface{}) []string {
	raw, ok := m["insight_ids"].([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func errMissing(field string) error { return &missingFieldErr{field: field} }

type missingFieldErr struct{ field string }

func (e *missingFieldErr) Error() string { return "store/cache: missing required field: " + e.field }
