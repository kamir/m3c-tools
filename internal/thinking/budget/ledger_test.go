// ledger_test.go — unit tests for the budget.Ledger read view.
//
// Focus areas (PLAN-0168 P1 acceptance):
//   - History returns UTC day rows ordered newest-first.
//   - History respects the days parameter (default, clamped).
//   - TopConsumers aggregates by (layer, strategy) and orders by USD.
//   - TopConsumers returns empty slice (never nil) on cold storage.
//   - Paused() mirrors autoreflect.BudgetPauseFraction.
//   - RemainingFraction still works through the new paths.
package budget

import (
	"testing"
	"time"

	"github.com/kamir/m3c-tools/internal/thinking/store"
)

func mkStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestHistoryEmpty(t *testing.T) {
	s := mkStore(t)
	l := NewLedger(s, 5.0)
	rows, err := l.History(7)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Errorf("empty ledger → 0 rows, got %d", len(rows))
	}
}

func TestHistoryReturnsTodaySpend(t *testing.T) {
	s := mkStore(t)
	if err := s.AddBudgetSpend(1000, 0.123); err != nil {
		t.Fatal(err)
	}
	l := NewLedger(s, 5.0)
	rows, err := l.History(7)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	today := time.Now().UTC().Format("2006-01-02")
	if rows[0].Date != today {
		t.Errorf("date = %s, want %s", rows[0].Date, today)
	}
	if rows[0].CapUSD != 5.0 {
		t.Errorf("cap = %f, want 5.0", rows[0].CapUSD)
	}
	if rows[0].SpentUSD < 0.122 || rows[0].SpentUSD > 0.124 {
		t.Errorf("spent = %f, want ~0.123", rows[0].SpentUSD)
	}
	if rows[0].PausedMinutes != 0 {
		t.Errorf("paused minutes must be 0 in Phase 1, got %d", rows[0].PausedMinutes)
	}
}

func TestHistoryDaysBounded(t *testing.T) {
	s := mkStore(t)
	l := NewLedger(s, 5.0)

	// days <= 0 → DefaultHistoryDays
	// days > MaxHistoryDays → MaxHistoryDays
	// Both must not error.
	for _, days := range []int{0, -1, 100, 1, 7, 30} {
		if _, err := l.History(days); err != nil {
			t.Errorf("days=%d: %v", days, err)
		}
	}
}

func TestTopConsumersEmpty(t *testing.T) {
	s := mkStore(t)
	l := NewLedger(s, 5.0)
	top, err := l.TopConsumers(1, 5)
	if err != nil {
		t.Fatal(err)
	}
	if top == nil {
		t.Errorf("expected empty slice, got nil")
	}
	if len(top) != 0 {
		t.Errorf("expected 0 rows, got %d", len(top))
	}
}

func TestTopConsumersAggregatesAndOrders(t *testing.T) {
	s := mkStore(t)
	// Seed three different (layer, strategy) pairs with known costs.
	if err := s.AddLLMLedgerEntry("r", "compare", 500, 0.30); err != nil {
		t.Fatal(err)
	}
	if err := s.AddLLMLedgerEntry("r", "compare", 500, 0.50); err != nil {
		t.Fatal(err)
	}
	if err := s.AddLLMLedgerEntry("i", "pattern", 200, 0.40); err != nil {
		t.Fatal(err)
	}
	if err := s.AddLLMLedgerEntry("a", "report", 100, 0.10); err != nil {
		t.Fatal(err)
	}
	// Untagged row must be summed by AddBudgetSpend but excluded here.
	if err := s.AddLLMLedgerEntry("", "", 999, 5.00); err != nil {
		t.Fatal(err)
	}

	l := NewLedger(s, 5.0)
	top, err := l.TopConsumers(1, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(top) != 3 {
		t.Fatalf("expected 3 tagged rows, got %d (untagged leaked?): %+v", len(top), top)
	}
	// Order: r/compare (0.80), i/pattern (0.40), a/report (0.10).
	if top[0].Layer != "r" || top[0].Strategy != "compare" {
		t.Errorf("rank 1 wrong: %+v", top[0])
	}
	if top[0].USD < 0.79 || top[0].USD > 0.81 {
		t.Errorf("rank 1 USD = %f, want ~0.80", top[0].USD)
	}
	if top[0].Count != 2 {
		t.Errorf("rank 1 count = %d, want 2", top[0].Count)
	}
	if top[1].Layer != "i" || top[1].Strategy != "pattern" {
		t.Errorf("rank 2 wrong: %+v", top[1])
	}
	if top[2].Layer != "a" || top[2].Strategy != "report" {
		t.Errorf("rank 3 wrong: %+v", top[2])
	}
}

func TestTopConsumersLimit(t *testing.T) {
	s := mkStore(t)
	for i, pair := range []struct{ l, st string; cost float64 }{
		{"r", "compare", 0.50},
		{"r", "contrast", 0.40},
		{"i", "pattern", 0.30},
		{"i", "synthesis", 0.20},
		{"a", "report", 0.10},
	} {
		if err := s.AddLLMLedgerEntry(pair.l, pair.st, 100, pair.cost); err != nil {
			t.Fatalf("seed[%d]: %v", i, err)
		}
	}
	l := NewLedger(s, 5.0)
	top, err := l.TopConsumers(1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(top) != 2 {
		t.Fatalf("limit=2 → 2 rows, got %d", len(top))
	}
	if top[0].Layer != "r" || top[0].Strategy != "compare" {
		t.Errorf("rank 1 wrong: %+v", top[0])
	}
}

func TestPausedDerivedFromFraction(t *testing.T) {
	s := mkStore(t)
	l := NewLedger(s, 1.0) // $1 daily cap makes thresholds easy

	// Nothing spent → not paused.
	paused, err := l.Paused()
	if err != nil {
		t.Fatal(err)
	}
	if paused {
		t.Errorf("expected not paused at 0 spend")
	}

	// 70% spent → not paused.
	if err := s.AddBudgetSpend(0, 0.70); err != nil {
		t.Fatal(err)
	}
	paused, err = l.Paused()
	if err != nil {
		t.Fatal(err)
	}
	if paused {
		t.Errorf("expected not paused at 70%%")
	}

	// 85% spent → paused (fraction_used 0.85 ≥ PausedThreshold 0.80).
	if err := s.AddBudgetSpend(0, 0.15); err != nil {
		t.Fatal(err)
	}
	paused, err = l.Paused()
	if err != nil {
		t.Fatal(err)
	}
	if !paused {
		t.Errorf("expected paused at 85%%")
	}
}

func TestReserveTaggedRecordsInLedger(t *testing.T) {
	s := mkStore(t)
	c := New("p-1", 100000, 100.0, s, StubEstimator{})
	if err := c.ReserveTagged("pid", "stub", "r", "compare", 100); err != nil {
		t.Fatal(err)
	}
	// untagged path still works
	if err := c.ReserveTagged("pid", "stub", "", "", 100); err != nil {
		t.Fatal(err)
	}

	l := NewLedger(s, 100.0)
	top, err := l.TopConsumers(1, 5)
	if err != nil {
		t.Fatal(err)
	}
	// Only one tagged row should surface.
	if len(top) != 1 {
		t.Fatalf("expected 1 tagged row, got %d: %+v", len(top), top)
	}
	if top[0].Layer != "r" || top[0].Strategy != "compare" {
		t.Errorf("wrong tagged row: %+v", top[0])
	}
	if top[0].Count != 1 {
		t.Errorf("count = %d, want 1", top[0].Count)
	}
}

func TestHistoryMultipleDaysWithFakeClock(t *testing.T) {
	// Seed three explicit day buckets via direct SQL so the test is
	// deterministic without needing to manipulate time.Now().
	s := mkStore(t)
	for _, day := range []struct {
		date string
		usd  float64
	}{
		{"2026-04-21", 0.50},
		{"2026-04-22", 1.00},
		{"2026-04-23", 0.25},
	} {
		if err := s.InsertBudgetDayForTest(day.date, 0, day.usd); err != nil {
			t.Fatal(err)
		}
	}

	l := NewLedger(s, 5.0)
	// Ask for 7 days "as of" 2026-04-23 → all three rows visible.
	now := time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)
	rows, err := l.historyAt(7, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected 3 rows, got %d: %+v", len(rows), rows)
	}
	// Newest first.
	if rows[0].Date != "2026-04-23" {
		t.Errorf("first row should be 2026-04-23, got %s", rows[0].Date)
	}
	if rows[2].Date != "2026-04-21" {
		t.Errorf("last row should be 2026-04-21, got %s", rows[2].Date)
	}

	// Ask for 2 days "as of" 2026-04-23 → only 22nd and 23rd.
	rows, err = l.historyAt(2, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("days=2 → 2 rows, got %d: %+v", len(rows), rows)
	}
	if rows[0].Date != "2026-04-23" || rows[1].Date != "2026-04-22" {
		t.Errorf("window wrong: %+v", rows)
	}
}

