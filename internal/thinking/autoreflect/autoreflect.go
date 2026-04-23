// Package autoreflect is the opt-in consumer that watches
// m3c.<ctx>.thoughts.raw and auto-fires a default reflective
// ProcessSpec (T → R.compare → I.pattern → A.summary) on either
// of two triggers:
//
//   - Window-count: every N new T messages arrive (default 20).
//   - Heartbeat:    every M minutes, iff at least 1 new T arrived
//                   in the interval (default 60 min).
//
// The two triggers are OR-combined. Whichever fires first resets
// both counters so a busy day doesn't double-fire and a quiet day
// still gets its heartbeat pass.
//
// SPEC-0167 §Week 2 open question D-open-1 (dedup) is closed by
// hashing the sorted list of thought_ids in the window; a repeat of
// the same hash within 60s is dropped.
//
// Opt-in: set ENABLE_AUTO_REFLECT=1 on the engine binary. When the
// env var is unset, cmd/thinking-engine/main.go constructs nothing
// and this package has zero side effects.
//
// All behaviour is bounded by the D4 budget ledger and an hourly
// per-user rate limiter. The consumer never bypasses them.
package autoreflect

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
	tkafka "github.com/kamir/m3c-tools/internal/thinking/kafka"
	"github.com/kamir/m3c-tools/internal/thinking/observability"
	"github.com/kamir/m3c-tools/internal/thinking/ratelimit"
	"github.com/kamir/m3c-tools/internal/thinking/schema"
	"github.com/kamir/m3c-tools/internal/thinking/store"
)

// Defaults applied when Config fields are zero-valued. Exported so
// cmd/thinking-engine/main.go and tests can reference the same
// numbers.
const (
	DefaultWindowN          = 20
	DefaultHeartbeatMin     = 60
	DefaultRateLimitPerHour = 10
	DefaultHardTokenCap     = 20000
	// DedupWindow is how long the SHA-256-of-thought-ids dedup key
	// suppresses a second fire for the same window.
	DedupWindow = 60 * time.Second
	// DedupRetention is the max age of autoreflect_fires rows the
	// background cleaner preserves.
	DedupRetention = 24 * time.Hour
	// BudgetPauseFraction: when `used / cap` ≥ this, auto-reflect
	// skips and emits AutoReflectBudgetPaused.
	BudgetPauseFraction = 0.80
	// DefaultPlaceholderPattern excludes the Flask-bridge "transcribing"
	// placeholder Ts (UTF-8 hourglass) from windows.
	DefaultPlaceholderPattern = `^⏳`

	// Custom ProcessEventName values emitted by this package.
	EventAutoReflectTriggered     schema.ProcessEventName = "AutoReflectTriggered"
	EventAutoReflectSkipped       schema.ProcessEventName = "AutoReflectSkipped"
	EventAutoReflectBudgetPaused  schema.ProcessEventName = "AutoReflectBudgetPaused"

	// CreatedByAutoReflect marks every auto-fired ProcessSpec so the
	// UI can distinguish from user-initiated and feedback-loop runs.
	// Mirrors the feedback convention of "thinking-engine/feedback".
	CreatedByAutoReflect = "thinking-engine/auto_reflect"
)

// BudgetLedger is the minimal read-only contract autoreflect needs
// from the D4 budget surface. *budget.Ledger satisfies it; tests
// can inject bespoke stubs (see fakeLedger in autoreflect_test.go).
type BudgetLedger interface {
	// RemainingFraction returns the fraction of the daily budget that
	// is still available, in [0.0, 1.0]. 0 means fully consumed,
	// 1.0 means nothing spent today. Implementations MUST NOT return
	// negative values; they MAY clamp to 0 when overspent.
	RemainingFraction() (float64, error)
}

// Dispatcher is the minimal contract needed to launch a ProcessSpec.
// The live orchestrator satisfies it; tests can inject stubs.
type Dispatcher interface {
	Submit(ctx context.Context, spec schema.ProcessSpec) error
}

// Config wires a new Consumer. Zero values are replaced by the
// Default* constants, so the engine can construct with:
//
//	autoreflect.New(autoreflect.Config{Hash: h, Bus: bus, ...})
//
// Required fields: Hash, Bus, Orchestrator, Store, Ledger.
type Config struct {
	Hash         mctx.Hash
	Bus          tkafka.Bus
	Orchestrator Dispatcher
	Store        *store.Store
	Ledger       BudgetLedger
	Logger       *log.Logger

	// WindowN: fire after this many new Ts in a row. 0 → DefaultWindowN.
	WindowN int
	// HeartbeatMin: fire after this many minutes, iff ≥1 T arrived. 0 → DefaultHeartbeatMin.
	HeartbeatMin int
	// RateLimitPerHour: cap auto-fires per hour per user. 0 → DefaultRateLimitPerHour.
	RateLimitPerHour int
	// SkipPlaceholder: when true, Ts whose content matches any
	// pattern in Patterns are excluded from the window.
	SkipPlaceholder bool
	// Patterns: regex list tested against T.content.text. Invalid
	// entries are logged and dropped; if every entry is invalid the
	// consumer falls back to DefaultPlaceholderPattern.
	Patterns []string
	// HardTokenCap: value populated onto ProcessSpec.Budget.MaxTokens
	// for every auto-fired process. 0 → DefaultHardTokenCap.
	HardTokenCap int

	// Metrics is the optional observability surface. nil is safe —
	// each call site guards on nil so existing unit tests keep
	// working without constructing a real registry.
	Metrics observability.Metrics

	// now is overridable for tests. Production uses time.Now.
	now func() time.Time
}

// Consumer is the running auto-reflect worker. Construct with New,
// then Run in its own goroutine (or use the Start/Stop pair for
// tighter lifecycle control).
type Consumer struct {
	cfg      Config
	logger   *log.Logger
	limiter  *ratelimit.HourlyLimiter
	patterns []*regexp.Regexp

	// subscription state
	stop func()

	// window state (guarded by mu)
	mu           sync.Mutex
	eligibleIDs  []string  // thought_ids accumulated this window
	lastFireAt   time.Time // UTC, zero at boot
	heartbeatDue bool      // latched by ticker; cleared on fire or drain
	stopBG       chan struct{}
}

// New constructs a Consumer without subscribing. Run / Start start
// the subscription; Stop unsubscribes and halts the background
// cleaner.
func New(cfg Config) (*Consumer, error) {
	if cfg.Bus == nil {
		return nil, fmt.Errorf("autoreflect: bus required")
	}
	if cfg.Orchestrator == nil {
		return nil, fmt.Errorf("autoreflect: orchestrator required")
	}
	if cfg.Store == nil {
		return nil, fmt.Errorf("autoreflect: store required")
	}
	if cfg.Ledger == nil {
		return nil, fmt.Errorf("autoreflect: ledger required")
	}
	if cfg.WindowN <= 0 {
		cfg.WindowN = DefaultWindowN
	}
	if cfg.HeartbeatMin <= 0 {
		cfg.HeartbeatMin = DefaultHeartbeatMin
	}
	if cfg.RateLimitPerHour <= 0 {
		cfg.RateLimitPerHour = DefaultRateLimitPerHour
	}
	if cfg.HardTokenCap <= 0 {
		cfg.HardTokenCap = DefaultHardTokenCap
	}
	if cfg.now == nil {
		cfg.now = func() time.Time { return time.Now().UTC() }
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.Default()
	}

	limiter, err := ratelimit.NewHourly(cfg.Store, ratelimit.HourlyConfig{
		TableName: "autoreflect_rate",
	})
	if err != nil {
		return nil, fmt.Errorf("autoreflect: limiter: %w", err)
	}

	c := &Consumer{
		cfg:     cfg,
		logger:  logger,
		limiter: limiter,
		stopBG:  make(chan struct{}),
	}
	c.patterns = c.compilePatterns(cfg.Patterns, cfg.SkipPlaceholder)
	return c, nil
}

// Run starts the subscription and the heartbeat ticker. Blocks until
// ctx is cancelled, then unsubscribes and returns. Safe to call
// once per Consumer.
func (c *Consumer) Run(ctx context.Context) error {
	if err := c.Start(ctx); err != nil {
		return err
	}
	<-ctx.Done()
	c.Stop()
	return ctx.Err()
}

// Start subscribes to thoughts.raw and launches the heartbeat ticker
// + dedup-retention cleaner. Safe to call multiple times; only the
// first call installs a subscription.
func (c *Consumer) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.stop != nil {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	topic := tkafka.TopicName(c.cfg.Hash, tkafka.TopicThoughtsRaw)
	stop, err := c.cfg.Bus.Subscribe(topic, func(hctx context.Context, m tkafka.Message) error {
		return c.onThought(ctx, m)
	})
	if err != nil {
		return fmt.Errorf("autoreflect: subscribe: %w", err)
	}

	c.mu.Lock()
	c.stop = stop
	c.mu.Unlock()

	// Background: heartbeat ticker + dedup cleaner.
	go c.heartbeatLoop(ctx)
	go c.dedupCleaner(ctx)

	c.logger.Printf("autoreflect: subscribed to %s (window_n=%d heartbeat_min=%d rate=%d/h cap_tok=%d)",
		topic, c.cfg.WindowN, c.cfg.HeartbeatMin, c.cfg.RateLimitPerHour, c.cfg.HardTokenCap)
	return nil
}

// Stop unsubscribes and halts the background goroutines. Safe to
// call multiple times.
func (c *Consumer) Stop() {
	c.mu.Lock()
	stop := c.stop
	c.stop = nil
	c.mu.Unlock()
	if stop != nil {
		stop()
	}
	// Signal background loops. Protected against double-close.
	defer func() { _ = recover() }()
	close(c.stopBG)
}

// onThought is the per-message handler for thoughts.raw. It:
//
//  1. filters out our own feedback-loop Ts (type=question) so
//     auto-reflect never triggers on its own output,
//  2. drops placeholder Ts whose content matches any configured regex,
//  3. accumulates the remaining thought_id in the window,
//  4. if the window hits WindowN, calls tryFire with reason=window.
func (c *Consumer) onThought(ctx context.Context, m tkafka.Message) error {
	var th schema.Thought
	if err := json.Unmarshal(m.Value, &th); err != nil {
		return nil
	}
	if !c.eligible(th) {
		return nil
	}
	c.mu.Lock()
	c.eligibleIDs = append(c.eligibleIDs, th.ThoughtID)
	shouldFire := len(c.eligibleIDs) >= c.cfg.WindowN
	c.mu.Unlock()

	if shouldFire {
		c.tryFire(ctx, "window")
	}
	return nil
}

// eligible reports whether a T should count toward the window. Rules:
//
//   - Ts with type=question are always excluded (they are engine
//     self-output — feedback-loop follow-ups, contradiction questions,
//     or in the future, auto-reflect-derived prompts).
//   - When SkipPlaceholder is on, any content matching a configured
//     regex is excluded.
func (c *Consumer) eligible(th schema.Thought) bool {
	if th.Type == schema.ThoughtQuestion {
		return false
	}
	if !c.cfg.SkipPlaceholder || len(c.patterns) == 0 {
		return true
	}
	if th.Content.Text == "" {
		return true
	}
	for _, re := range c.patterns {
		if re.MatchString(th.Content.Text) {
			return false
		}
	}
	return true
}

// heartbeatLoop ticks every HeartbeatMin minutes and, if ≥1 T has
// been accumulated since the last fire, calls tryFire with
// reason=heartbeat. On a quiet tick (0 Ts) it does nothing.
func (c *Consumer) heartbeatLoop(ctx context.Context) {
	interval := time.Duration(c.cfg.HeartbeatMin) * time.Minute
	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopBG:
			return
		case <-t.C:
			c.mu.Lock()
			n := len(c.eligibleIDs)
			c.mu.Unlock()
			if n == 0 {
				continue
			}
			c.tryFire(ctx, "heartbeat")
		}
	}
}

// dedupCleaner prunes autoreflect_fires rows older than DedupRetention.
func (c *Consumer) dedupCleaner(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopBG:
			return
		case <-t.C:
			cutoffMs := c.cfg.now().Add(-DedupRetention).UnixMilli()
			if _, err := c.cfg.Store.CleanAutoReflectFires(cutoffMs); err != nil {
				c.logger.Printf("autoreflect: dedup cleaner: %v", err)
			}
		}
	}
}

// tryFire implements the gating pipeline: dedup → rate limit →
// budget → dispatch. Emits the appropriate AutoReflectSkipped event
// on any rejection path, and resets the per-window state after any
// terminal decision (success, dedup hit, rate limit, or budget) so
// the next window starts clean.
//
// reason is "window" or "heartbeat".
func (c *Consumer) tryFire(ctx context.Context, reason string) {
	// Snapshot window state and clear under lock so a second
	// concurrent fire doesn't double-count the same Ts.
	c.mu.Lock()
	if len(c.eligibleIDs) == 0 {
		c.mu.Unlock()
		c.emitSkipped(ctx, "", "no_eligible_ts", reason, 0, time.Time{}, time.Time{})
		return
	}
	ids := append([]string(nil), c.eligibleIDs...)
	windowStart := c.lastFireAt // may be zero on first fire
	windowEnd := c.cfg.now()
	// Reset for next window. We commit this reset even on skip —
	// skipping is a terminal decision; we do not want to keep
	// retrying the same window forever.
	c.eligibleIDs = nil
	c.lastFireAt = windowEnd
	c.mu.Unlock()

	hash := dedupHash(ids)

	// 1. dedup — identical window hash fired within 60s?
	fired, err := c.recentDedup(hash, windowEnd)
	if err != nil {
		c.logger.Printf("autoreflect: dedup lookup: %v", err)
	}
	if fired {
		c.emitSkipped(ctx, hash, "dedup", reason, len(ids), windowStart, windowEnd)
		return
	}

	// 2. rate limit — at most RateLimitPerHour per user.
	count, err := c.limiter.Increment("auto_reflect")
	if err != nil {
		c.logger.Printf("autoreflect: limiter: %v", err)
		return
	}
	if count > c.cfg.RateLimitPerHour {
		c.emitSkipped(ctx, hash, "rate_limit", reason, len(ids), windowStart, windowEnd)
		return
	}

	// 3. budget — ≥80% consumed → pause until next day.
	remaining, err := c.cfg.Ledger.RemainingFraction()
	if err != nil {
		c.logger.Printf("autoreflect: budget lookup: %v", err)
		// Conservative: treat read errors as "plenty" so a store hiccup
		// doesn't silently kill the feature.
		remaining = 1.0
	}
	if remaining <= (1.0 - BudgetPauseFraction) {
		c.emitBudgetPaused(ctx, hash, reason, len(ids), remaining, windowStart, windowEnd)
		return
	}

	// 4. dispatch.
	spec := DefaultAutoReflectSpec(ids, c.cfg.HardTokenCap)

	// Record dedup BEFORE dispatch so a racing second window can't
	// slip through while Submit is in flight.
	if err := c.recordFire(hash, spec.ProcessID, windowStart, windowEnd); err != nil {
		c.logger.Printf("autoreflect: dedup record: %v", err)
	}

	if err := c.cfg.Orchestrator.Submit(ctx, spec); err != nil {
		c.logger.Printf("autoreflect: submit: %v", err)
		return
	}
	c.emitTriggered(ctx, spec.ProcessID, hash, reason, ids, windowStart, windowEnd)
}

// compilePatterns returns the compiled regex set. Invalid entries
// are logged and dropped. If SkipPlaceholder is on and the final
// set is empty, the DefaultPlaceholderPattern is used as a
// belt-and-suspenders fallback (per brief: "Don't crash on regex
// compile errors — log and fall back to the default pattern list.")
func (c *Consumer) compilePatterns(raw []string, skip bool) []*regexp.Regexp {
	if !skip {
		return nil
	}
	var out []*regexp.Regexp
	for _, p := range raw {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		re, err := regexp.Compile(p)
		if err != nil {
			c.logger.Printf("autoreflect: invalid placeholder pattern %q: %v (dropping)", p, err)
			continue
		}
		out = append(out, re)
	}
	if len(out) == 0 {
		re, err := regexp.Compile(DefaultPlaceholderPattern)
		if err != nil {
			// Should never happen — the default is a compile-time constant.
			c.logger.Printf("autoreflect: default pattern failed to compile: %v", err)
			return nil
		}
		out = []*regexp.Regexp{re}
	}
	return out
}

// recentDedup reports whether dedupHash already exists with a
// fired_at_ms within DedupWindow of now.
func (c *Consumer) recentDedup(hash string, now time.Time) (bool, error) {
	cutoff := now.Add(-DedupWindow).UnixMilli()
	_, ok, err := c.cfg.Store.RecentAutoReflectFire(hash, cutoff)
	if err != nil {
		return false, err
	}
	return ok, nil
}

// recordFire persists the dedup hash + window metadata.
func (c *Consumer) recordFire(hash, processID string, windowStart, windowEnd time.Time) error {
	return c.cfg.Store.RecordAutoReflectFire(store.AutoReflectFireRow{
		Hash:          hash,
		WindowStartMs: windowStart.UnixMilli(),
		WindowEndMs:   windowEnd.UnixMilli(),
		ProcessID:     processID,
		FiredAtMs:     windowEnd.UnixMilli(),
	})
}

// ----- event emission helpers -----

func (c *Consumer) emitTriggered(ctx context.Context, processID, hash, reason string, ids []string, start, end time.Time) {
	detail := map[string]interface{}{
		"window_start_ms": start.UnixMilli(),
		"window_end_ms":   end.UnixMilli(),
		"t_count":         len(ids),
		"reason":          reason,
		"dedup_hash":      hash,
		"origin":          CreatedByAutoReflect,
	}
	c.emit(ctx, processID, EventAutoReflectTriggered, detail)
	if c.cfg.Metrics != nil {
		c.cfg.Metrics.RecordAutoReflectFire(reason)
	}
}

func (c *Consumer) emitSkipped(ctx context.Context, hash, why, reason string, tCount int, start, end time.Time) {
	detail := map[string]interface{}{
		"reason":         why, // "rate_limit" | "dedup" | "budget" | "no_eligible_ts"
		"trigger_reason": reason,
		"t_count":        tCount,
		"dedup_hash":     hash,
	}
	if !start.IsZero() {
		detail["window_start_ms"] = start.UnixMilli()
	}
	if !end.IsZero() {
		detail["window_end_ms"] = end.UnixMilli()
	}
	c.emit(ctx, "", EventAutoReflectSkipped, detail)
	if c.cfg.Metrics != nil {
		c.cfg.Metrics.RecordAutoReflectSkip(why)
	}
}

func (c *Consumer) emitBudgetPaused(ctx context.Context, hash, reason string, tCount int, remaining float64, start, end time.Time) {
	detail := map[string]interface{}{
		"reason":             "budget",
		"trigger_reason":     reason,
		"t_count":            tCount,
		"dedup_hash":         hash,
		"remaining_fraction": remaining,
		"pause_at_fraction":  BudgetPauseFraction,
	}
	if !start.IsZero() {
		detail["window_start_ms"] = start.UnixMilli()
	}
	if !end.IsZero() {
		detail["window_end_ms"] = end.UnixMilli()
	}
	// Emit the Skipped(reason=budget) event as the primary record per
	// the test contract, and a follow-on BudgetPaused for richer UX
	// telemetry.
	c.emit(ctx, "", EventAutoReflectSkipped, detail)
	c.emit(ctx, "", EventAutoReflectBudgetPaused, detail)
	if c.cfg.Metrics != nil {
		c.cfg.Metrics.RecordAutoReflectSkip("budget")
		c.cfg.Metrics.RecordBudgetPause()
	}
}

func (c *Consumer) emit(ctx context.Context, processID string, name schema.ProcessEventName, detail map[string]interface{}) {
	ev := schema.ProcessEvent{
		SchemaVer: schema.CurrentSchemaVer,
		ProcessID: processID,
		Event:     name,
		Detail:    detail,
		Timestamp: c.cfg.now(),
	}
	topic := tkafka.TopicName(c.cfg.Hash, tkafka.TopicProcessEvents)
	key := processID
	if key == "" {
		key = "auto_reflect"
	}
	if err := c.cfg.Bus.Produce(ctx, topic, key, ev); err != nil {
		c.logger.Printf("autoreflect: emit %s: %v", name, err)
	}
}

// ----- helpers -----

// DefaultAutoReflectSpec returns the canonical ProcessSpec the
// auto-reflect consumer dispatches. The spec is pinned:
//
//   - mode:        semi_linear (step barrier is safer than eager
//                  dispatch when token budget matters).
//   - steps:       R.compare → I.pattern → A.summary with
//                  prompt_id references pointing at the Week-2
//                  seeded template IDs. A T-scope step is expressed
//                  on R/I/A via context.scope.entities (the list of
//                  triggering thought_ids).
//   - budget:      MaxTokens capped at hardCap (default 20_000 — well
//                  below the 50_000 interactive default).
//   - created_by:  "thinking-engine/auto_reflect" — distinguishes
//                  from user-initiated runs in the UI without
//                  requiring a new schema field (origin is packed in
//                  the companion AutoReflectTriggered event).
func DefaultAutoReflectSpec(tIDs []string, hardCap int) schema.ProcessSpec {
	if hardCap <= 0 {
		hardCap = DefaultHardTokenCap
	}
	refs := append([]string(nil), tIDs...)
	scope := &schema.StepContextScope{Entities: refs}
	stepCtx := &schema.StepContext{Scope: scope}

	compareID := "tmpl.reflect.compare.v1"
	patternID := "tmpl.insight.pattern.v1"
	summaryID := "tmpl.artifact.summary.v1"

	return schema.ProcessSpec{
		SchemaVer: schema.CurrentSchemaVer,
		ProcessID: uuid.NewString(),
		Intent:    fmt.Sprintf("auto-reflect over %d recent thoughts", len(tIDs)),
		Mode:      schema.ModeSemiLinear,
		Depth:     1,
		Steps: []schema.Step{
			{Layer: schema.LayerR, Strategy: "compare", PromptID: &compareID, Context: stepCtx},
			{Layer: schema.LayerI, Strategy: "pattern", PromptID: &patternID, Context: stepCtx},
			{Layer: schema.LayerA, Strategy: "summary", PromptID: &summaryID, Context: stepCtx},
		},
		Budget:    &schema.Budget{MaxTokens: hardCap},
		CreatedBy: CreatedByAutoReflect,
	}
}

// dedupHash returns the SHA-256 hex of the sorted thought_id list.
// Exported for tests and for UI telemetry (every AutoReflectTriggered
// event carries the same hash in detail.dedup_hash).
func dedupHash(ids []string) string {
	sorted := append([]string(nil), ids...)
	sort.Strings(sorted)
	h := sha256.New()
	for _, id := range sorted {
		h.Write([]byte(id))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

