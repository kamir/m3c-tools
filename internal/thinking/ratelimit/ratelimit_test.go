// ratelimit_test.go — sanity tests for the keyed hourly limiter.
package ratelimit

import (
	"testing"

	"github.com/kamir/m3c-tools/internal/thinking/store"
)

func TestHourlyLimiterIncrements(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	l, err := NewHourly(st, HourlyConfig{TableName: "test"})
	if err != nil {
		t.Fatal(err)
	}

	for want := 1; want <= 3; want++ {
		got, err := l.Increment("feat-a")
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("Increment #%d: got %d, want %d", want, got, want)
		}
	}
}

func TestHourlyLimiterKeysAreIndependent(t *testing.T) {
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	l, _ := NewHourly(st, HourlyConfig{})

	// feat-a → 3 hits; feat-b → 1 hit; the two counters must not
	// share state.
	for i := 0; i < 3; i++ {
		if _, err := l.Increment("feat-a"); err != nil {
			t.Fatal(err)
		}
	}
	b, err := l.Increment("feat-b")
	if err != nil {
		t.Fatal(err)
	}
	if b != 1 {
		t.Errorf("feat-b first increment = %d, want 1 (keys leaked)", b)
	}
}

func TestNewHourlyRejectsNilStore(t *testing.T) {
	_, err := NewHourly(nil, HourlyConfig{})
	if err == nil {
		t.Fatalf("expected error when store is nil")
	}
}
