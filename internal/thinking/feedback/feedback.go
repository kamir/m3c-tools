// Package feedback closes the cognitive loop: when the I-processor
// emits a contradiction follow-up Thought of type=question onto
// m3c.<ctx>.thoughts.raw, this consumer picks it up and launches a
// fresh default ProcessSpec so the engine reflects on its own output.
//
// SPEC-0167 §Stream 3a — "Consumer subscribed to
// m3c.<ctx>.thoughts.raw. Filters: only T messages with type ==
// 'question' AND provenance.parent_artifact_id != null (the
// contradiction-follow-ups emitted by I-proc in Week 2). Behavior:
// constructs a default linear ProcessSpec T → R.clarify → I.decision
// → A.summary and posts it to /v1/process via the same HTTP handler
// the public API uses (internal dispatch, no self-signed HMAC). Cap:
// per-user feedback rate limit at 10/hour."
//
// The rate limit is enforced against store.feedback_counters so it
// survives restarts. Over the cap the consumer drops the message
// with a warn log — the follow-up question still lives on
// thoughts.raw and the user can pick it up manually.
package feedback

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/google/uuid"
	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
	tkafka "github.com/kamir/m3c-tools/internal/thinking/kafka"
	"github.com/kamir/m3c-tools/internal/thinking/orchestrator"
	"github.com/kamir/m3c-tools/internal/thinking/schema"
	"github.com/kamir/m3c-tools/internal/thinking/store"
)

// DefaultRateLimitPerHour is the SPEC-0167 §Stream 3a hourly cap.
// Kept as a const so tests can reference the same number.
const DefaultRateLimitPerHour = 10

// Consumer subscribes to thoughts.raw, filters contradiction
// follow-ups, enforces the hourly rate limit, and posts a default
// ProcessSpec to the orchestrator.
type Consumer struct {
	hash    mctx.Hash
	bus     tkafka.Bus
	orc     *orchestrator.Orchestrator
	store   *store.Store
	log     *log.Logger
	limit   int
	stop    func()
}

// Config wires a new Consumer. RateLimit defaults to
// DefaultRateLimitPerHour when zero or negative.
type Config struct {
	Hash         mctx.Hash
	Bus          tkafka.Bus
	Orchestrator *orchestrator.Orchestrator
	Store        *store.Store
	Logger       *log.Logger
	RateLimit    int
}

// New returns a Consumer ready to Start.
func New(cfg Config) (*Consumer, error) {
	if cfg.Bus == nil {
		return nil, fmt.Errorf("feedback: bus required")
	}
	if cfg.Orchestrator == nil {
		return nil, fmt.Errorf("feedback: orchestrator required")
	}
	if cfg.Store == nil {
		return nil, fmt.Errorf("feedback: store required")
	}
	limit := cfg.RateLimit
	if limit <= 0 {
		limit = DefaultRateLimitPerHour
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.Default()
	}
	return &Consumer{
		hash:  cfg.Hash,
		bus:   cfg.Bus,
		orc:   cfg.Orchestrator,
		store: cfg.Store,
		log:   logger,
		limit: limit,
	}, nil
}

// Start subscribes to thoughts.raw. Safe to call multiple times;
// only the first call registers a subscription.
func (c *Consumer) Start(ctx context.Context) error {
	if c.stop != nil {
		return nil
	}
	topic := tkafka.TopicName(c.hash, tkafka.TopicThoughtsRaw)
	stop, err := c.bus.Subscribe(topic, func(hctx context.Context, m tkafka.Message) error {
		return c.onThought(ctx, m)
	})
	if err != nil {
		return fmt.Errorf("feedback: subscribe: %w", err)
	}
	c.stop = stop
	c.log.Printf("feedback: subscribed to %s (rate_limit=%d/hour)", topic, c.limit)
	return nil
}

// Stop unsubscribes.
func (c *Consumer) Stop() {
	if c.stop != nil {
		c.stop()
		c.stop = nil
	}
}

// onThought is the per-message handler. It:
//   1. decodes the Thought,
//   2. runs MatchFilter to decide whether this is a feedback-loop T,
//   3. enforces the hourly rate limit in the store,
//   4. constructs a default linear ProcessSpec and submits via orchestrator.
func (c *Consumer) onThought(ctx context.Context, m tkafka.Message) error {
	var th schema.Thought
	if err := json.Unmarshal(m.Value, &th); err != nil {
		// Corrupt payload: ignored. Validation already ran upstream.
		return nil
	}
	if !MatchFilter(th) {
		return nil
	}

	count, err := c.store.IncrementFeedbackCounter()
	if err != nil {
		c.log.Printf("feedback: counter increment failed: %v", err)
		return nil
	}
	if count > c.limit {
		c.log.Printf("feedback: rate-limit exceeded (count=%d > cap=%d) — dropping follow-up thought=%s", count, c.limit, th.ThoughtID)
		return nil
	}

	spec := DefaultFeedbackSpec(th)
	if err := c.orc.Submit(ctx, spec); err != nil {
		c.log.Printf("feedback: orchestrator submit failed: %v", err)
		return nil
	}
	c.log.Printf("feedback: launched process_id=%s from thought=%s", spec.ProcessID, th.ThoughtID)
	return nil
}

// MatchFilter returns true iff th is a contradiction-follow-up
// emitted by the engine (type=question AND
// provenance.parent_artifact_id is non-nil and non-empty).
//
// Exposed for unit tests and for external consumers that want to
// replicate the same filter semantics.
func MatchFilter(th schema.Thought) bool {
	if th.Type != schema.ThoughtQuestion {
		return false
	}
	if th.Provenance == nil {
		return false
	}
	if th.Provenance.ParentArtifactID == nil {
		return false
	}
	if strings.TrimSpace(*th.Provenance.ParentArtifactID) == "" {
		return false
	}
	return true
}

// DefaultFeedbackSpec returns the canonical feedback ProcessSpec the
// engine runs in response to a contradiction follow-up: T → R.clarify
// → I.decision → A.summary. Linear mode — every step runs as soon as
// the command hits the topic (Week 3 keeps the feedback loop simple;
// semi_linear ordering is available for the composer UI to use
// deliberately).
//
// The resulting spec is seeded with a fresh process_id and carries
// the triggering thought id in intent + step.scope.entities so the
// processors can cite it.
func DefaultFeedbackSpec(th schema.Thought) schema.ProcessSpec {
	refs := []string{th.ThoughtID}
	scope := &schema.StepContextScope{Entities: refs}
	ctxForRI := &schema.StepContext{Scope: scope}
	return schema.ProcessSpec{
		SchemaVer: schema.CurrentSchemaVer,
		ProcessID: uuid.NewString(),
		Intent:    fmt.Sprintf("feedback loop for contradiction follow-up %s", th.ThoughtID),
		Mode:      schema.ModeLinear,
		Depth:     1,
		Steps: []schema.Step{
			{Layer: schema.LayerR, Strategy: "clarify", Context: ctxForRI},
			{Layer: schema.LayerI, Strategy: "decision", Context: ctxForRI},
			{Layer: schema.LayerA, Strategy: "summary", Context: ctxForRI},
		},
		CreatedBy: "thinking-engine/feedback",
	}
}
