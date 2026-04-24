// budget.go — read-only budget surface for SPEC-0167 P1 (PLAN-0168).
//
// Exposes two endpoints behind the standard HMAC middleware:
//
//	GET /v1/budget/today
//	GET /v1/budget/history?days=N
//
// Both are pure projections of the D4 ledger state owned by
// internal/thinking/budget.Ledger — no state lives in this file.
// Enforcement of the cap continues to happen in budget.Controller;
// these endpoints are read-only mirrors for the UI and operators.
//
// Shape invariants (frozen for the aims-core UI pill):
//
//   - date, reset_at are always UTC.
//   - reset_at is the next UTC midnight relative to the engine's clock.
//   - fraction_used is clamped to [0, 1] even on cap breaches.
//   - paused is derived (not stored) from fraction_used >= 0.80,
//     matching autoreflect.BudgetPauseFraction. See budget.Paused().
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/kamir/m3c-tools/internal/thinking/budget"
)

// budgetClock is the injectable time source for the today/history
// handlers. Tests override it via Server.nowFn to exercise UTC day
// rollover deterministically; production code leaves it nil and the
// real wall clock is used.
type budgetClock func() time.Time

func (s *Server) now() time.Time {
	if s.nowFn != nil {
		return s.nowFn().UTC()
	}
	return time.Now().UTC()
}

// BudgetTodayResponse mirrors the PLAN-0168 shape. Fields are
// populated in the order the UI expects; do not rename without
// updating aims-core thinking_bridge.
type BudgetTodayResponse struct {
	Date          string              `json:"date"`
	SpentUSD      float64             `json:"spent_usd"`
	CapUSD        float64             `json:"cap_usd"`
	RemainingUSD  float64             `json:"remaining_usd"`
	FractionUsed  float64             `json:"fraction_used"`
	Paused        bool                `json:"paused"`
	ResetAt       string              `json:"reset_at"`
	TopConsumers  []TopConsumerEntry  `json:"top_consumers"`
}

// TopConsumerEntry is one row in the top_consumers aggregate.
type TopConsumerEntry struct {
	Layer    string  `json:"layer"`
	Strategy string  `json:"strategy"`
	USD      float64 `json:"usd"`
	Count    int     `json:"count"`
}

// BudgetHistoryEntry is one day in the /v1/budget/history response.
type BudgetHistoryEntry struct {
	Date          string  `json:"date"`
	SpentUSD      float64 `json:"spent_usd"`
	CapUSD        float64 `json:"cap_usd"`
	PausedMinutes int     `json:"paused_minutes"`
}

func (s *Server) budgetToday(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.cfg.Ledger == nil {
		http.Error(w, "budget ledger not configured", http.StatusServiceUnavailable)
		return
	}

	now := s.now()
	spent, err := s.cfg.Ledger.SpentUSD()
	if err != nil {
		http.Error(w, "budget: "+err.Error(), http.StatusInternalServerError)
		return
	}
	cap := s.cfg.Ledger.DailyCapUSD()
	fraction := 0.0
	if cap > 0 {
		fraction = spent / cap
	}
	if fraction < 0 {
		fraction = 0
	}
	if fraction > 1 {
		fraction = 1
	}
	remaining := cap - spent
	if remaining < 0 {
		remaining = 0
	}
	paused := fraction >= budget.PausedThreshold

	// Top consumers: request yesterday+today so late-night UTC flips
	// still attribute to the correct day bucket. Empty slice (not null)
	// when ledger has nothing.
	top := []TopConsumerEntry{}
	if rows, err := s.cfg.Ledger.TopConsumers(1, 5); err == nil {
		for _, r := range rows {
			top = append(top, TopConsumerEntry{
				Layer: r.Layer, Strategy: r.Strategy,
				USD: r.USD, Count: r.Count,
			})
		}
	}

	// Reset at next UTC midnight.
	reset := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, 1)

	resp := BudgetTodayResponse{
		Date:         now.Format("2006-01-02"),
		SpentUSD:     round4(spent),
		CapUSD:       round4(cap),
		RemainingUSD: round4(remaining),
		FractionUsed: round4(fraction),
		Paused:       paused,
		ResetAt:      reset.Format(time.RFC3339),
		TopConsumers: top,
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) budgetHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.cfg.Ledger == nil {
		http.Error(w, "budget ledger not configured", http.StatusServiceUnavailable)
		return
	}

	days := budget.DefaultHistoryDays
	if q := r.URL.Query().Get("days"); q != "" {
		// Best-effort parse. Invalid or out-of-range values silently
		// snap to defaults/limits — the endpoint MUST be a simple GET
		// for the UI pill.
		var n int
		if _, err := fmt.Sscanf(q, "%d", &n); err == nil {
			days = n
		}
	}
	if days <= 0 {
		days = budget.DefaultHistoryDays
	}
	if days > budget.MaxHistoryDays {
		days = budget.MaxHistoryDays
	}

	rows, err := s.cfg.Ledger.History(days)
	if err != nil {
		http.Error(w, "budget: "+err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]BudgetHistoryEntry, 0, len(rows))
	for _, r := range rows {
		out = append(out, BudgetHistoryEntry{
			Date:          r.Date,
			SpentUSD:      round4(r.SpentUSD),
			CapUSD:        round4(r.CapUSD),
			PausedMinutes: r.PausedMinutes,
		})
	}
	// Always return a JSON array (never null) — the UI expects to
	// iterate unconditionally.
	if out == nil {
		out = []BudgetHistoryEntry{}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(out)
}

// round4 truncates a float to 4 decimal places. USD values never need
// more precision than that and the extra digits pollute JSON output.
func round4(x float64) float64 {
	// Multiply-round-divide gives us the same value with fewer mantissa
	// bits set; json.Encode then emits a short literal.
	const m = 1e4
	if x >= 0 {
		return float64(int64(x*m+0.5)) / m
	}
	return float64(int64(x*m-0.5)) / m
}
