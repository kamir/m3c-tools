package registry

import (
	"testing"
	"time"
)

// TestParsePullSince covers the --since parser shared by both pull carriers.
func TestParsePullSince(t *testing.T) {
	if got, err := parsePullSince(""); err != nil || !got.IsZero() {
		t.Errorf("empty => zero/no-error, got %v / %v", got, err)
	}
	if got, err := parsePullSince("2026-08-01T00:00:00Z"); err != nil || got.Year() != 2026 || got.Month() != 8 {
		t.Errorf("RFC3339 parse: %v / %v", got, err)
	}
	if got, err := parsePullSince("2026-08-01"); err != nil || got.Year() != 2026 || got.Day() != 1 {
		t.Errorf("date parse: %v / %v", got, err)
	}
	if got, err := parsePullSince("168h"); err != nil || time.Since(got) < 167*time.Hour {
		t.Errorf("duration parse: %v / %v", got, err)
	}
	if _, err := parsePullSince("not-a-time"); err == nil {
		t.Error("garbage should error")
	}
	// A negative duration would invert --since into a future cutoff — reject it.
	if _, err := parsePullSince("-24h"); err == nil {
		t.Error("negative duration must error (would silently exclude everything)")
	}
	// A positive duration still yields a PAST cutoff.
	if got, err := parsePullSince("1h"); err != nil || !got.Before(time.Now()) {
		t.Errorf("positive duration => past cutoff, got %v / %v", got, err)
	}
}

// TestEventOlderThan covers the best-effort admit-timestamp filter: only a
// parseable occurred_at strictly before the cutoff is dropped; everything else
// (zero cutoff, absent/unparseable timestamp) is kept — it is never a gate.
func TestEventOlderThan(t *testing.T) {
	cutoff := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	older := map[string]any{"occurred_at": "2026-07-01T00:00:00Z"}
	newer := map[string]any{"occurred_at": "2026-09-01T00:00:00Z"}

	if !eventOlderThan(older, cutoff) {
		t.Error("2026-07 event should be older than the 2026-08 cutoff")
	}
	if eventOlderThan(newer, cutoff) {
		t.Error("2026-09 event should NOT be older than the 2026-08 cutoff")
	}
	if eventOlderThan(older, time.Time{}) {
		t.Error("a zero cutoff must keep every event")
	}
	if eventOlderThan(map[string]any{}, cutoff) {
		t.Error("an absent occurred_at must be kept (best-effort, not a gate)")
	}
	if eventOlderThan(map[string]any{"occurred_at": "nonsense"}, cutoff) {
		t.Error("an unparseable occurred_at must be kept")
	}
}
