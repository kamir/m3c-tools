// budget_test.go — HTTP contract tests for /v1/budget/today + /history.
//
// Covers PLAN-0168 P1 acceptance gates:
//   - HMAC enforcement (missing/foreign token → 401).
//   - today shape: all fields present, types correct.
//   - date + reset_at are UTC and consistent with a faked clock.
//   - fraction_used clamped to [0, 1] on breach.
//   - paused mirrors the 0.80 threshold.
//   - history days param: default (omitted), negative, zero, over-cap (>30).
//   - top_consumers empty slice (never null) when ledger is cold.
//   - 503 when ledger is not wired (belt-and-suspenders).
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/internal/thinking/budget"
	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
	tkafka "github.com/kamir/m3c-tools/internal/thinking/kafka"
	"github.com/kamir/m3c-tools/internal/thinking/store"
)

// newBudgetTestServer wires an api.Server whose only meaningful state
// is a real sqlite store + budget.Ledger. The bus is an in-memory
// stub because the budget handlers don't consume any events.
func newBudgetTestServer(t *testing.T) (*Server, []byte, string, *store.Store) {
	t.Helper()
	secret := []byte("test-secret")
	raw, err := mctx.NewRaw("budget-test-user")
	if err != nil {
		t.Fatal(err)
	}
	hash := raw.Hash()

	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	innerBus := tkafka.NewMemBus(hash)
	bus, err := tkafka.NewValidatingBus(innerBus, nil)
	if err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		OwnerRaw:  raw,
		Hash:      hash,
		Secret:    secret,
		Bus:       bus,
		Store:     st,
		BuildInfo: "test",
		Ledger:    budget.NewLedger(st, 5.0),
	}
	srv := New(cfg)
	return srv, secret, raw.Value(), st
}

func signTokenFor(t *testing.T, secret []byte, ctxID string) string {
	t.Helper()
	return SignToken(secret, Claims{
		CtxID:  ctxID,
		Expiry: time.Now().Add(time.Minute),
		Nonce:  "n-budget",
	})
}

func TestBudgetTodayRequiresAuth(t *testing.T) {
	srv, _, _, _ := newBudgetTestServer(t)

	// No token → 401.
	req := httptest.NewRequest("GET", "/v1/budget/today", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no-token → want 401, got %d body=%s", rec.Code, rec.Body.String())
	}

	// Foreign ctx → 401.
	srv2, secret, _, _ := newBudgetTestServer(t)
	foreign := SignToken(secret, Claims{
		CtxID: "someone-else", Expiry: time.Now().Add(time.Minute), Nonce: "n",
	})
	req = httptest.NewRequest("GET", "/v1/budget/today", nil)
	req.Header.Set("Authorization", "Bearer "+foreign)
	rec = httptest.NewRecorder()
	srv2.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("foreign-ctx → want 401, got %d", rec.Code)
	}
}

func TestBudgetTodayShapeAndDefaults(t *testing.T) {
	srv, secret, ctxID, _ := newBudgetTestServer(t)
	tok := signTokenFor(t, secret, ctxID)

	req := httptest.NewRequest("GET", "/v1/budget/today", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("content-type = %q, want application/json", ct)
	}

	var got BudgetTodayResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}

	// Date must be today in UTC, ISO YYYY-MM-DD.
	today := time.Now().UTC().Format("2006-01-02")
	if got.Date != today {
		t.Errorf("date = %s, want %s", got.Date, today)
	}
	// reset_at parses as RFC3339 + is UTC midnight of the next day.
	reset, err := time.Parse(time.RFC3339, got.ResetAt)
	if err != nil {
		t.Errorf("reset_at not RFC3339: %q (%v)", got.ResetAt, err)
	} else {
		if reset.Location() != time.UTC {
			t.Errorf("reset_at not UTC: %v", reset.Location())
		}
		if reset.Hour() != 0 || reset.Minute() != 0 || reset.Second() != 0 {
			t.Errorf("reset_at not midnight: %v", reset)
		}
	}
	if got.CapUSD != 5.0 {
		t.Errorf("cap_usd = %f, want 5.0", got.CapUSD)
	}
	if got.SpentUSD != 0 {
		t.Errorf("spent_usd = %f, want 0", got.SpentUSD)
	}
	if got.RemainingUSD != 5.0 {
		t.Errorf("remaining_usd = %f, want 5.0", got.RemainingUSD)
	}
	if got.FractionUsed != 0 {
		t.Errorf("fraction_used = %f, want 0", got.FractionUsed)
	}
	if got.Paused {
		t.Errorf("paused must be false at 0 spend")
	}
	if got.TopConsumers == nil {
		t.Errorf("top_consumers must be [] not null at empty state")
	}
}

func TestBudgetTodayReflectsSpend(t *testing.T) {
	srv, secret, ctxID, st := newBudgetTestServer(t)
	// $4 of $5 cap → fraction 0.8 → paused=true.
	if err := st.AddBudgetSpend(1000, 4.00); err != nil {
		t.Fatal(err)
	}
	if err := st.AddLLMLedgerEntry("r", "compare", 800, 3.00); err != nil {
		t.Fatal(err)
	}
	if err := st.AddLLMLedgerEntry("i", "pattern", 200, 1.00); err != nil {
		t.Fatal(err)
	}
	tok := signTokenFor(t, secret, ctxID)

	req := httptest.NewRequest("GET", "/v1/budget/today", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var got BudgetTodayResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.SpentUSD != 4.00 {
		t.Errorf("spent = %f, want 4.00", got.SpentUSD)
	}
	if got.RemainingUSD != 1.00 {
		t.Errorf("remaining = %f, want 1.00", got.RemainingUSD)
	}
	if got.FractionUsed < 0.79 || got.FractionUsed > 0.81 {
		t.Errorf("fraction_used = %f, want ~0.80", got.FractionUsed)
	}
	if !got.Paused {
		t.Errorf("paused must be true at fraction 0.80")
	}
	if len(got.TopConsumers) != 2 {
		t.Fatalf("expected 2 top_consumers, got %d: %+v", len(got.TopConsumers), got.TopConsumers)
	}
	if got.TopConsumers[0].Layer != "r" || got.TopConsumers[0].Strategy != "compare" {
		t.Errorf("top1 wrong: %+v", got.TopConsumers[0])
	}
}

func TestBudgetTodayFractionClampedOnBreach(t *testing.T) {
	srv, secret, ctxID, st := newBudgetTestServer(t)
	// Overspend — $10 against a $5 cap.
	if err := st.AddBudgetSpend(9999, 10.00); err != nil {
		t.Fatal(err)
	}
	tok := signTokenFor(t, secret, ctxID)

	req := httptest.NewRequest("GET", "/v1/budget/today", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	var got BudgetTodayResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.FractionUsed != 1.0 {
		t.Errorf("fraction_used must clamp to 1.0 on breach, got %f", got.FractionUsed)
	}
	if got.RemainingUSD != 0 {
		t.Errorf("remaining_usd must clamp to 0 on breach, got %f", got.RemainingUSD)
	}
	if !got.Paused {
		t.Errorf("paused must be true on breach")
	}
}

func TestBudgetTodayDateStableWithFakeClock(t *testing.T) {
	srv, secret, ctxID, _ := newBudgetTestServer(t)
	// Pin clock to a specific UTC instant.
	fixed := time.Date(2026, 4, 23, 15, 30, 0, 0, time.UTC)
	srv.nowFn = func() time.Time { return fixed }
	tok := signTokenFor(t, secret, ctxID)

	req := httptest.NewRequest("GET", "/v1/budget/today", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	var got BudgetTodayResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Date != "2026-04-23" {
		t.Errorf("date = %s, want 2026-04-23", got.Date)
	}
	if !strings.HasPrefix(got.ResetAt, "2026-04-24T00:00:00") {
		t.Errorf("reset_at should be 2026-04-24T00:00:00Z, got %s", got.ResetAt)
	}

	// Advance past UTC midnight → new day.
	srv.nowFn = func() time.Time {
		return time.Date(2026, 4, 24, 0, 1, 0, 0, time.UTC)
	}
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Date != "2026-04-24" {
		t.Errorf("after rollover: date = %s, want 2026-04-24", got.Date)
	}
}

func TestBudgetHistoryDaysParam(t *testing.T) {
	srv, secret, ctxID, st := newBudgetTestServer(t)
	// Seed 10 explicit days relative to today so we can assert clamping.
	now := time.Now().UTC()
	for i := 0; i < 10; i++ {
		d := now.AddDate(0, 0, -i).Format("2006-01-02")
		if err := st.InsertBudgetDayForTest(d, 0, 0.10*float64(i+1)); err != nil {
			t.Fatal(err)
		}
	}
	tok := signTokenFor(t, secret, ctxID)

	cases := []struct {
		q        string
		expected int // -1 means "don't assert exact count, just bounds"
		maxRows  int
	}{
		{"", 7, 7},        // default 7
		{"?days=3", 3, 3}, // explicit
		{"?days=0", 7, 7}, // treated as default
		{"?days=-5", 7, 7},
		{"?days=1", 1, 1},
		{"?days=200", 10, 30}, // capped to 30, but only 10 seeded
		{"?days=abc", 7, 7},   // best-effort parse → default
	}
	for _, c := range cases {
		req := httptest.NewRequest("GET", "/v1/budget/history"+c.q, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("%q: want 200, got %d: %s", c.q, rec.Code, rec.Body.String())
			continue
		}
		var got []BudgetHistoryEntry
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Errorf("%q: decode: %v", c.q, err)
			continue
		}
		if len(got) > c.maxRows {
			t.Errorf("%q: len=%d > max=%d", c.q, len(got), c.maxRows)
		}
		if c.expected >= 0 && len(got) != c.expected {
			t.Errorf("%q: len=%d, want %d", c.q, len(got), c.expected)
		}
	}
}

func TestBudgetHistoryReturnsEmptyArrayNotNull(t *testing.T) {
	srv, secret, ctxID, _ := newBudgetTestServer(t)
	tok := signTokenFor(t, secret, ctxID)

	req := httptest.NewRequest("GET", "/v1/budget/history?days=7", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	body := strings.TrimSpace(rec.Body.String())
	// Must be a JSON array literal — UI iterates unconditionally.
	if !strings.HasPrefix(body, "[") || !strings.HasSuffix(body, "]") {
		t.Errorf("body must be JSON array, got %q", body)
	}
}

func TestBudgetHistoryOrderNewestFirst(t *testing.T) {
	srv, secret, ctxID, st := newBudgetTestServer(t)
	// Seed three distinct days.
	days := []struct {
		date string
		usd  float64
	}{
		{time.Now().UTC().AddDate(0, 0, -2).Format("2006-01-02"), 0.20},
		{time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02"), 0.40},
		{time.Now().UTC().Format("2006-01-02"), 0.60},
	}
	for _, d := range days {
		if err := st.InsertBudgetDayForTest(d.date, 0, d.usd); err != nil {
			t.Fatal(err)
		}
	}
	tok := signTokenFor(t, secret, ctxID)

	req := httptest.NewRequest("GET", "/v1/budget/history?days=7", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	var got []BudgetHistoryEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 rows, got %d: %+v", len(got), got)
	}
	// got[0] is today, got[2] is -2 days.
	if got[0].Date != days[2].date {
		t.Errorf("newest first broken: got[0] = %s, want %s", got[0].Date, days[2].date)
	}
	if got[2].Date != days[0].date {
		t.Errorf("newest first broken: got[2] = %s, want %s", got[2].Date, days[0].date)
	}
	// CapUSD from ledger carries through on every row.
	for _, r := range got {
		if r.CapUSD != 5.0 {
			t.Errorf("cap_usd = %f, want 5.0 on %s", r.CapUSD, r.Date)
		}
	}
}

func TestBudgetRejectsNonGET(t *testing.T) {
	srv, secret, ctxID, _ := newBudgetTestServer(t)
	tok := signTokenFor(t, secret, ctxID)

	for _, path := range []string{"/v1/budget/today", "/v1/budget/history"} {
		req := httptest.NewRequest("POST", path, strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s POST → want 405, got %d", path, rec.Code)
		}
	}
}

func TestBudget503WhenLedgerNotWired(t *testing.T) {
	// Construct a Server with Ledger explicitly nil.
	secret := []byte("s")
	raw, _ := mctx.NewRaw("nil-ledger-user")
	hash := raw.Hash()
	st, _ := store.Open(":memory:")
	t.Cleanup(func() { _ = st.Close() })
	innerBus := tkafka.NewMemBus(hash)
	bus, _ := tkafka.NewValidatingBus(innerBus, nil)
	srv := New(Config{
		OwnerRaw: raw, Hash: hash, Secret: secret, Bus: bus, Store: st,
		Ledger: nil, // explicit
	})
	tok := SignToken(secret, Claims{CtxID: raw.Value(), Expiry: time.Now().Add(time.Minute), Nonce: "n"})

	for _, path := range []string{"/v1/budget/today", "/v1/budget/history"} {
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s nil-ledger → want 503, got %d", path, rec.Code)
		}
	}
}
