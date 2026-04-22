package budget

import (
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/internal/thinking/store"
)

func TestPerProcessCapEnforced(t *testing.T) {
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	c := New("p-1", 1000, 100.0, s, StubEstimator{})
	// stub returns 500 tokens for inputTokens<250 — two should push over cap 1000? Actually 500+500=1000, third exceeds.
	if err := c.Reserve("pid", "stub", 100); err != nil {
		t.Fatal(err)
	}
	if err := c.Reserve("pid", "stub", 100); err != nil {
		t.Fatal(err)
	}
	if err := c.Reserve("pid", "stub", 100); err == nil {
		t.Errorf("expected per-process cap error")
	} else if !strings.Contains(err.Error(), "per-process") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestDailyUSDCapEnforced(t *testing.T) {
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// preload the day's counter so the first Reserve trips the daily cap.
	// StubEstimator for inputTokens=100 → tokens=500, cost=500/1000*0.0001=0.00005.
	// Set daily cap very low (0.00001) so any reserve trips it.
	c := New("p-1", 100000, 0.00001, s, StubEstimator{})
	err = c.Reserve("pid", "stub", 100)
	if err == nil {
		t.Fatalf("expected daily cap error")
	}
	if !strings.Contains(err.Error(), "per-day") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestUsedTracksSpend(t *testing.T) {
	s, _ := store.Open(":memory:")
	defer s.Close()
	c := New("p-1", 100000, 100.0, s, StubEstimator{})
	_ = c.Reserve("pid", "stub", 100)
	if c.Used() == 0 {
		t.Errorf("Used() not tracking")
	}
}
