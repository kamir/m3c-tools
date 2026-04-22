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
func (c *Controller) Reserve(promptID, model string, inputTokens int) error {
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
