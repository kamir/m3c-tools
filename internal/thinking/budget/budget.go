// Package budget enforces D4's two-layer cap:
//
//  1. Per-process hard cap: max_tokens taken from ProcessSpec.budget
//     (default 50k). Step estimate > remaining → step fails cleanly.
//  2. Per-day-per-user soft cap: default $5/day tracked in the local
//     store. When hit, the engine refuses to start new processes.
//
// Phase 2 will integrate the SPEC-0158 capability-aware delegation
// queue so hitting the cap can *schedule* instead of failing.
package budget

import (
	"fmt"
	"sync"
	"time"

	"github.com/kamir/m3c-tools/internal/thinking/store"
)

// DefaultDailyUSD is the D4 soft per-day-per-user default.
const DefaultDailyUSD = 5.0

// Estimator computes token/USD cost estimates for a prospective step.
// Kept minimal for Week 1; real implementation will take the prompt
// body, input size, and model cost card.
type Estimator interface {
	EstimateStep(promptID, model string, inputTokens int) (tokens int, costUSD float64)
}

// StubEstimator returns a fixed, tiny cost so Week 1 can exercise
// the enforcement path without a real cost card.
type StubEstimator struct{}

func (StubEstimator) EstimateStep(_ , _ string, inputTokens int) (int, float64) {
	// Assume output ~= input, $0.0001/1k tokens. Deterministic stub.
	total := inputTokens * 2
	if total < 500 {
		total = 500
	}
	return total, float64(total) / 1000.0 * 0.0001
}

// Controller orchestrates the two caps for one process.
type Controller struct {
	mu              sync.Mutex
	processID       string
	processCapTok   int
	processUsedTok  int
	dailyCapUSD     float64
	store           *store.Store
	estimator       Estimator
}

// New returns a fresh controller. processCapTok comes from
// ProcessSpec.EffectiveMaxTokens(). dailyCapUSD defaults to
// DefaultDailyUSD when zero.
func New(processID string, processCapTok int, dailyCapUSD float64, s *store.Store, e Estimator) *Controller {
	if dailyCapUSD <= 0 {
		dailyCapUSD = DefaultDailyUSD
	}
	if e == nil {
		e = StubEstimator{}
	}
	return &Controller{
		processID:     processID,
		processCapTok: processCapTok,
		dailyCapUSD:   dailyCapUSD,
		store:         s,
		estimator:     e,
	}
}

// Reserve checks both caps. On success, records the estimated spend
// against both the in-memory per-process counter and the daily
// counter (so failures halfway through a process don't over-count,
// we reserve optimistically per step).
//
// Returns a detailed error the API layer can surface verbatim.
//
// Spend is NOT tagged with (layer, strategy) on this path — use
// ReserveTagged from call sites that have that context (see
// /v1/budget/today top_consumers).
func (c *Controller) Reserve(promptID, model string, inputTokens int) error {
	return c.ReserveTagged(promptID, model, "", "", inputTokens)
}

// ReserveTagged behaves like Reserve but also attributes the estimated
// spend to (layer, strategy) in the llm_ledger table. Empty layer or
// strategy strings are treated as "untagged" and excluded from the
// /v1/budget/today top_consumers aggregate (PLAN-0168 P1).
func (c *Controller) ReserveTagged(promptID, model, layer, strategy string, inputTokens int) error {
	tokens, costUSD := c.estimator.EstimateStep(promptID, model, inputTokens)

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.processCapTok > 0 && c.processUsedTok+tokens > c.processCapTok {
		return fmt.Errorf(
			"budget: per-process token cap exceeded (used=%d + est=%d > cap=%d) — SPEC-0167 D4",
			c.processUsedTok, tokens, c.processCapTok,
		)
	}

	if c.store != nil {
		_, dayCost, err := c.store.GetBudgetSpend()
		if err != nil {
			return fmt.Errorf("budget: read daily spend: %w", err)
		}
		if dayCost+costUSD > c.dailyCapUSD {
			return fmt.Errorf(
				"budget: per-day USD cap exceeded (today=$%.4f + est=$%.4f > cap=$%.2f) — SPEC-0167 D4",
				dayCost, costUSD, c.dailyCapUSD,
			)
		}
		if err := c.store.AddBudgetSpend(tokens, costUSD); err != nil {
			return fmt.Errorf("budget: record spend: %w", err)
		}
		// Per-tag ledger — non-fatal on error so a schema hiccup can't
		// break the cognitive path. Untagged (empty layer/strategy) is
		// still written so the row count agrees with budget_counters,
		// but those rows are excluded from top_consumers.
		if err := c.store.AddLLMLedgerEntry(layer, strategy, tokens, costUSD); err != nil {
			// swallow — we already recorded the spend; tagging failure
			// is a visibility regression, not a correctness one.
			_ = err
		}
	}

	c.processUsedTok += tokens
	return nil
}

// Used returns current spend for this process (debug/telemetry).
func (c *Controller) Used() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.processUsedTok
}

// Ledger exposes read-only views of the D4 daily cap for callers
// (e.g. internal/thinking/autoreflect) that want to gate decisions
// on how much of today's budget is still available without taking a
// per-process Controller.
//
// Ledger is safe for concurrent use.
type Ledger struct {
	store   *store.Store
	dailyUSD float64
}

// NewLedger wraps the store with a read view. dailyCapUSD defaults
// to DefaultDailyUSD when ≤ 0 so callers can pass 0 in config and
// get the documented default.
func NewLedger(s *store.Store, dailyCapUSD float64) *Ledger {
	if dailyCapUSD <= 0 {
		dailyCapUSD = DefaultDailyUSD
	}
	return &Ledger{store: s, dailyUSD: dailyCapUSD}
}

// DailyCapUSD returns the configured daily USD ceiling.
func (l *Ledger) DailyCapUSD() float64 { return l.dailyUSD }

// SpentUSD returns today's USD spend (UTC day bucket).
func (l *Ledger) SpentUSD() (float64, error) {
	if l == nil || l.store == nil {
		return 0, nil
	}
	_, cost, err := l.store.GetBudgetSpend()
	return cost, err
}

// RemainingFraction returns (cap - spent) / cap in [0, 1]. An
// overspent day clamps to 0 — callers interpret "0 remaining" as
// "skip".
func (l *Ledger) RemainingFraction() (float64, error) {
	if l == nil || l.store == nil {
		return 1.0, nil
	}
	spent, err := l.SpentUSD()
	if err != nil {
		return 0, err
	}
	if l.dailyUSD <= 0 {
		return 1.0, nil
	}
	r := (l.dailyUSD - spent) / l.dailyUSD
	if r < 0 {
		return 0, nil
	}
	if r > 1.0 {
		return 1.0, nil
	}
	return r, nil
}

// PausedThreshold mirrors autoreflect.BudgetPauseFraction. Import cycle
// prevents us from referencing the autoreflect constant directly, so
// the budget package owns the source-of-truth for the threshold and
// autoreflect is expected to match. Callers reading Paused() outside
// autoreflect see the same value the consumer would use.
const PausedThreshold = 0.80

// Paused reports whether autoreflect should currently be paused by
// the D4 daily cap. Derived from fraction_used (= 1 - RemainingFraction)
// against PausedThreshold; the paused flag is NOT separately persisted
// — autoreflect recomputes it on every window tick. Exposing the same
// derivation here means /v1/budget/today stays consistent with
// autoreflect's own gating decision.
func (l *Ledger) Paused() (bool, error) {
	if l == nil {
		return false, nil
	}
	rem, err := l.RemainingFraction()
	if err != nil {
		return false, err
	}
	return (1.0 - rem) >= PausedThreshold, nil
}

// DaySpend is one calendar day of LLM spend, returned by History.
// PausedMinutes is present but always zero in Phase 1 — autoreflect
// does not currently persist per-day pause durations. The field is
// reserved for Phase 2 when the observability sink records them.
type DaySpend struct {
	Date          string  // "YYYY-MM-DD" (UTC)
	SpentUSD      float64
	CapUSD        float64
	PausedMinutes int
}

// LayerSpend is a top-consumer row, returned by TopConsumers.
type LayerSpend struct {
	Layer    string
	Strategy string
	USD      float64
	Count    int
}

// MaxHistoryDays bounds the /v1/budget/history API.
const MaxHistoryDays = 30

// DefaultHistoryDays is the default if the caller omits ?days=.
const DefaultHistoryDays = 7

// History returns the last `days` UTC calendar days of spend (newest
// first). days is clamped to [1, MaxHistoryDays]; days ≤ 0 defaults to
// DefaultHistoryDays. Days with no spend are omitted — the engine may
// be younger than the requested window, or the user may not have run
// anything that day.
//
// CapUSD is the current configured cap on every row; Phase 1 does not
// persist historical cap changes.
func (l *Ledger) History(days int) ([]DaySpend, error) {
	return l.historyAt(days, time.Now().UTC())
}

// historyAt is History with an injectable clock for tests.
func (l *Ledger) historyAt(days int, now time.Time) ([]DaySpend, error) {
	if l == nil || l.store == nil {
		return nil, nil
	}
	if days <= 0 {
		days = DefaultHistoryDays
	}
	if days > MaxHistoryDays {
		days = MaxHistoryDays
	}
	since := now.AddDate(0, 0, -(days - 1)).Format("2006-01-02")
	rows, err := l.store.ListBudgetSpendSince(since)
	if err != nil {
		return nil, err
	}
	out := make([]DaySpend, 0, len(rows))
	for _, r := range rows {
		out = append(out, DaySpend{
			Date:     r.DayUTC,
			SpentUSD: r.CostUSD,
			CapUSD:   l.dailyUSD,
		})
	}
	return out, nil
}

// TopConsumers returns the top-N (layer, strategy) tuples by cost_usd
// over the last `days` UTC calendar days (1..MaxHistoryDays). When the
// llm_ledger is empty (e.g. cold start, or pre-migration data only)
// this returns an empty slice, never nil-with-error.
//
// Legacy spend recorded before the llm_ledger migration lives in
// budget_counters only; it contributes to daily totals but cannot be
// attributed to a specific (layer, strategy) pair, so it is NOT
// surfaced here.
func (l *Ledger) TopConsumers(days, limit int) ([]LayerSpend, error) {
	return l.topConsumersAt(days, limit, time.Now().UTC())
}

// topConsumersAt is TopConsumers with an injectable clock for tests.
func (l *Ledger) topConsumersAt(days, limit int, now time.Time) ([]LayerSpend, error) {
	if l == nil || l.store == nil {
		return nil, nil
	}
	if days <= 0 {
		days = 1
	}
	if days > MaxHistoryDays {
		days = MaxHistoryDays
	}
	if limit <= 0 {
		limit = 5
	}
	since := now.AddDate(0, 0, -(days - 1)).Format("2006-01-02")
	rows, err := l.store.TopLLMConsumers(since, limit)
	if err != nil {
		return nil, err
	}
	out := make([]LayerSpend, 0, len(rows))
	for _, r := range rows {
		out = append(out, LayerSpend{
			Layer:    r.Layer,
			Strategy: r.Strategy,
			USD:      r.CostUSD,
			Count:    r.Count,
		})
	}
	return out, nil
}
