// Package sink implements the D2 async ER1 sinker.
//
// SPEC-0167 §Locked Decisions §D2 says artifacts.created on Kafka is
// the record; ER1 is a projection. This package runs the projection:
//
//   - Subscribes to `m3c.<ctx>.artifacts.created`.
//   - Calls `er1.CreateArtifact` for each.
//   - On success: emits `ArtifactPersisted` on `process.events`.
//   - On failure: exponential backoff, cap 5 attempts; after the cap
//     emits `ArtifactPersistenceFailed` with the error and leaves the
//     Kafka message in place for a future rebuild.
//
// The sinker is opt-in via `ENABLE_ER1_SINK=1`. Default ON in Phase 1
// deployments, OFF in tests (see the environment guard in Main.go).
package sink

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"sync"
	"time"

	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
	"github.com/kamir/m3c-tools/internal/thinking/er1"
	tkafka "github.com/kamir/m3c-tools/internal/thinking/kafka"
	"github.com/kamir/m3c-tools/internal/thinking/observability"
	"github.com/kamir/m3c-tools/internal/thinking/schema"
)

// Config wires a new Sinker.
type Config struct {
	Hash   mctx.Hash
	OwnerID string // raw user_context_id (required to pass ctx-guard)
	Bus    tkafka.Bus
	ER1    er1.Client
	Logger *log.Logger

	// MaxAttempts caps the retry loop. Zero → DefaultMaxAttempts.
	MaxAttempts int
	// BaseBackoff is the starting backoff for attempt 0. Zero → DefaultBaseBackoff.
	BaseBackoff time.Duration
	// MaxBackoff caps any single sleep. Zero → DefaultMaxBackoff.
	MaxBackoff time.Duration

	// Metrics is the optional observability surface. nil disables
	// counter updates; ER1 persistence still proceeds unchanged.
	Metrics observability.Metrics
}

// Defaults.
const (
	DefaultMaxAttempts = 5
	DefaultBaseBackoff = 200 * time.Millisecond
	DefaultMaxBackoff  = 10 * time.Second
)

// Sinker is the long-lived consumer.
type Sinker struct {
	cfg  Config
	stop func()

	mu      sync.Mutex
	stopped bool
}

// New builds a Sinker. Does not start consuming — call Start.
func New(cfg Config) *Sinker {
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = DefaultMaxAttempts
	}
	if cfg.BaseBackoff <= 0 {
		cfg.BaseBackoff = DefaultBaseBackoff
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = DefaultMaxBackoff
	}
	return &Sinker{cfg: cfg}
}

// Start subscribes to `artifacts.created` and begins projecting.
func (s *Sinker) Start(ctx context.Context) error {
	topic := tkafka.TopicName(s.cfg.Hash, tkafka.TopicArtifactsCreated)
	stop, err := s.cfg.Bus.Subscribe(topic, func(hctx context.Context, m tkafka.Message) error {
		return s.handle(ctx, m)
	})
	if err != nil {
		return fmt.Errorf("sink: subscribe: %w", err)
	}
	s.stop = stop
	s.cfg.Logger.Printf("sink: subscribed to %s", topic)
	return nil
}

// Stop unsubscribes.
func (s *Sinker) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return
	}
	s.stopped = true
	if s.stop != nil {
		s.stop()
	}
}

// handle decodes one artifact message and performs the projection
// with retry.
func (s *Sinker) handle(ctx context.Context, m tkafka.Message) error {
	var art schema.Artifact
	if err := json.Unmarshal(m.Value, &art); err != nil {
		s.cfg.Logger.Printf("sink: malformed artifact payload: %v", err)
		return nil
	}
	if art.ArtifactID == "" {
		s.cfg.Logger.Printf("sink: artifact missing id — dropping")
		return nil
	}

	ref, err := s.persistWithRetry(ctx, art)
	if err != nil {
		s.emitFailed(ctx, art, err)
		return nil
	}
	s.emitPersisted(ctx, art, ref)
	return nil
}

// persistWithRetry calls er1.CreateArtifact with exponential backoff.
// A 4xx HTTPError is treated as non-retriable (the body is
// permanently malformed) and fails the sink immediately.
func (s *Sinker) persistWithRetry(ctx context.Context, art schema.Artifact) (string, error) {
	var lastErr error
	for attempt := 0; attempt < s.cfg.MaxAttempts; attempt++ {
		ref, err := s.cfg.ER1.CreateArtifact(s.cfg.OwnerID, art)
		if err == nil {
			return ref, nil
		}
		lastErr = err
		// Non-retriable? Bail immediately.
		if httpErr, ok := err.(*er1.HTTPError); ok && httpErr.Status >= 400 && httpErr.Status < 500 {
			return "", err
		}

		// Sleep before next attempt (skip after last).
		if attempt+1 >= s.cfg.MaxAttempts {
			break
		}
		delay := s.backoff(attempt)
		s.cfg.Logger.Printf("sink: artifact=%s attempt=%d failed: %v (retrying in %s)",
			art.ArtifactID, attempt+1, err, delay)
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("sink: context cancelled after %d attempts: %w", attempt+1, err)
		case <-time.After(delay):
		}
	}
	return "", lastErr
}

// backoff returns the sleep before attempt+1. Attempt 0 → BaseBackoff,
// each subsequent attempt doubles, capped at MaxBackoff.
func (s *Sinker) backoff(attempt int) time.Duration {
	// math.Pow to keep intent clear; attempt is small so no overflow risk.
	factor := math.Pow(2, float64(attempt))
	d := time.Duration(float64(s.cfg.BaseBackoff) * factor)
	if d > s.cfg.MaxBackoff {
		d = s.cfg.MaxBackoff
	}
	return d
}

func (s *Sinker) emitPersisted(ctx context.Context, art schema.Artifact, ref string) {
	ev := schema.ProcessEvent{
		SchemaVer: schema.CurrentSchemaVer,
		ProcessID: art.ProcessID,
		Event:     schema.ProcessEventName("ArtifactPersisted"),
		Detail: map[string]interface{}{
			"artifact_id": art.ArtifactID,
			"er1_ref":     ref,
			"format":      string(art.Format),
		},
		Timestamp: time.Now().UTC(),
	}
	topic := tkafka.TopicName(s.cfg.Hash, tkafka.TopicProcessEvents)
	if err := s.cfg.Bus.Produce(ctx, topic, art.ProcessID, ev); err != nil {
		s.cfg.Logger.Printf("sink: emit ArtifactPersisted: %v", err)
	}
	if s.cfg.Metrics != nil {
		s.cfg.Metrics.RecordArtifactCreated(string(art.Format))
	}
}

func (s *Sinker) emitFailed(ctx context.Context, art schema.Artifact, cause error) {
	ev := schema.ProcessEvent{
		SchemaVer: schema.CurrentSchemaVer,
		ProcessID: art.ProcessID,
		Event:     schema.ProcessEventName("ArtifactPersistenceFailed"),
		Detail: map[string]interface{}{
			"artifact_id": art.ArtifactID,
			"error":       cause.Error(),
		},
		Timestamp: time.Now().UTC(),
	}
	topic := tkafka.TopicName(s.cfg.Hash, tkafka.TopicProcessEvents)
	if err := s.cfg.Bus.Produce(ctx, topic, art.ProcessID, ev); err != nil {
		s.cfg.Logger.Printf("sink: emit ArtifactPersistenceFailed: %v", err)
	}
	if s.cfg.Metrics != nil {
		s.cfg.Metrics.RecordER1SinkFailure()
	}
}

// Enabled reports whether the sinker should run based on the
// ENABLE_ER1_SINK env var. Exposed for cmd/thinking-engine/main.go
// and tests.
func Enabled(getenv func(string) string) bool {
	if getenv == nil {
		return false
	}
	v := getenv("ENABLE_ER1_SINK")
	return v == "1" || v == "true" || v == "TRUE"
}
