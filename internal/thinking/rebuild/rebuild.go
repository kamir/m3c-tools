// Package rebuild implements the SPEC-0167 §Reconciler cold-start
// path: `POST /v1/rebuild` reads ER1 for items newer than the latest
// T on the topic, emits missing ThoughtCreated events, and queues a
// default linear ProcessSpec against each new T.
//
// This is the admin-only recovery path for a fresh cluster: the engine
// can rebuild its working set without replaying a full Kafka log.
package rebuild

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
	"github.com/kamir/m3c-tools/internal/thinking/er1"
	tkafka "github.com/kamir/m3c-tools/internal/thinking/kafka"
	"github.com/kamir/m3c-tools/internal/thinking/orchestrator"
	"github.com/kamir/m3c-tools/internal/thinking/schema"
	"github.com/kamir/m3c-tools/internal/thinking/store"
)

// DefaultLimit is the per-rebuild scan size sent to ER1.
const DefaultLimit = 500

// Service is the long-lived admin surface. Exposed through the HTTP
// `/v1/rebuild` route in internal/thinking/api.
type Service struct {
	Hash    mctx.Hash
	OwnerID string // raw user_context_id (for ER1 ctx-guard)
	Bus     tkafka.Bus
	ER1     er1.Client
	Orc     *orchestrator.Orchestrator
	Cache   *store.Cache
	Logger  *log.Logger

	// Limit is the per-call scan cap. Zero → DefaultLimit.
	Limit int
}

// Result is the reply shape from Run.
type Result struct {
	RebuildID      string   `json:"rebuild_id"`
	Scanned        int      `json:"scanned"`
	NewThoughts    int      `json:"new_thoughts"`
	QueuedProcesses []string `json:"queued_processes,omitempty"`
	Since          string   `json:"since_iso,omitempty"`
}

// Run executes one rebuild pass. Intended to be invoked from the
// HTTP handler; it is synchronous but bounded by DefaultTimeout via
// the ER1 client.
func (s *Service) Run(ctx context.Context) (Result, error) {
	limit := s.Limit
	if limit <= 0 {
		limit = DefaultLimit
	}

	since := s.latestThoughtTimestamp()
	items, err := s.ER1.ListItemsSince(s.OwnerID, since, limit)
	if err != nil {
		return Result{}, fmt.Errorf("rebuild: list ER1: %w", err)
	}
	s.log().Printf("rebuild: scanned %d ER1 items since %s", len(items), since)

	existing := s.existingThoughtIDs()

	res := Result{
		RebuildID: uuid.NewString(),
		Scanned:   len(items),
		Since:     since.Format(time.RFC3339Nano),
	}

	for _, it := range items {
		if it.DocID == "" {
			continue
		}
		// Dedup: if the id already exists on the topic, skip.
		if existing[it.DocID] {
			continue
		}
		// Emit a minimal Thought onto thoughts.raw.
		th := thoughtFromItem(it)
		topic := tkafka.TopicName(s.Hash, tkafka.TopicThoughtsRaw)
		if err := s.Bus.Produce(ctx, topic, th.ThoughtID, th); err != nil {
			s.log().Printf("rebuild: produce T %s: %v", th.ThoughtID, err)
			continue
		}
		res.NewThoughts++

		// Submit a default linear ProcessSpec.
		spec := DefaultProcessSpec(th.ThoughtID)
		if err := s.Orc.Submit(ctx, spec); err != nil {
			s.log().Printf("rebuild: submit spec for %s: %v", th.ThoughtID, err)
			continue
		}
		res.QueuedProcesses = append(res.QueuedProcesses, spec.ProcessID)
	}
	return res, nil
}

// latestThoughtTimestamp returns the freshest timestamp observed on
// thoughts.raw, or zero time if none.
func (s *Service) latestThoughtTimestamp() time.Time {
	if s.Cache == nil {
		return time.Time{}
	}
	rows := s.Cache.List("T", time.Time{}, "", 1)
	if len(rows) == 0 {
		return time.Time{}
	}
	var th map[string]interface{}
	if err := json.Unmarshal(rows[0], &th); err != nil {
		return time.Time{}
	}
	ts, _ := th["timestamp"].(string)
	if ts == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		t, err = time.Parse(time.RFC3339, ts)
		if err != nil {
			return time.Time{}
		}
	}
	return t
}

// existingThoughtIDs returns the set of T.thought_id values currently
// in the cache. Used to skip already-present items during rebuild.
func (s *Service) existingThoughtIDs() map[string]bool {
	out := map[string]bool{}
	if s.Cache == nil {
		return out
	}
	rows := s.Cache.List("T", time.Time{}, "", 0)
	for _, r := range rows {
		var th map[string]interface{}
		if err := json.Unmarshal(r, &th); err != nil {
			continue
		}
		if id, ok := th["thought_id"].(string); ok {
			out[id] = true
		}
	}
	return out
}

func (s *Service) log() *log.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return log.Default()
}

// ----- helpers for the HTTP handler -----

// thoughtFromItem converts an ER1 item into a valid T-schema message.
// The content points at the item via an `er1://` ref so downstream
// consumers can lazily fetch the full body.
func thoughtFromItem(it er1.Item) schema.Thought {
	ts := it.CreatedAt
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	// If the item text is short, inline it; otherwise reference by uri.
	var content schema.Content
	if it.Summary != "" && len(it.Summary) < 512 {
		content = schema.Content{Text: it.Summary}
	} else {
		content = schema.Content{Ref: fmt.Sprintf("er1://%s/items/%s", it.CtxID, it.DocID)}
	}
	return schema.Thought{
		SchemaVer: schema.CurrentSchemaVer,
		ThoughtID: it.DocID,
		Type:      schema.ThoughtObservation,
		Content:   content,
		Source:    schema.Source{Kind: schema.SourceImport, Ref: fmt.Sprintf("er1://%s/items/%s", it.CtxID, it.DocID)},
		Tags:      it.Tags,
		Timestamp: ts,
		Provenance: &schema.Provenance{
			CapturedBy: "thinking-engine.rebuild",
		},
	}
}

// DefaultProcessSpec returns a default linear T→R.compare→I.pattern→A.summary
// spec rooted on the given thought id.
func DefaultProcessSpec(thoughtID string) schema.ProcessSpec {
	return schema.ProcessSpec{
		SchemaVer: schema.CurrentSchemaVer,
		ProcessID: uuid.NewString(),
		Intent:    "rebuild:auto-ingest " + thoughtID,
		Mode:      schema.ModeLinear,
		Depth:     1,
		Steps: []schema.Step{
			{Layer: schema.LayerR, Strategy: "compare"},
			{Layer: schema.LayerI, Strategy: "pattern"},
			{Layer: schema.LayerA, Strategy: "summary"},
		},
		CreatedAt: time.Now().UTC(),
		CreatedBy: "thinking-engine.rebuild",
	}
}

// Guard against accidental concurrent rebuilds on the same Service —
// cheap lock, loud refusal rather than queueing.
var runningMu sync.Mutex
var running = map[*Service]bool{}

// TryBegin marks this Service as mid-rebuild; returns false if one is
// already running. Callers must call End to release the lock.
func TryBegin(s *Service) bool {
	runningMu.Lock()
	defer runningMu.Unlock()
	if running[s] {
		return false
	}
	running[s] = true
	return true
}

// End releases the in-progress mark.
func End(s *Service) {
	runningMu.Lock()
	defer runningMu.Unlock()
	delete(running, s)
}
