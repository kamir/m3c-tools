package auditevent

import (
	"sort"
	"testing"
	"time"
)

// restoreIDSeams resets the generator seams and monotonic state after a test
// that pinned them, so tests stay order-independent.
func restoreIDSeams(t *testing.T) {
	t.Helper()
	realNow, realRand := idNow, idRandRead
	t.Cleanup(func() {
		idNow, idRandRead = realNow, realRand
		idState.mu.Lock()
		idState.lastMS, idState.lastEnt = 0, [10]byte{}
		idState.mu.Unlock()
	})
}

// TestNewEventIDFormat checks length and alphabet: 26 Crockford base32 chars.
func TestNewEventIDFormat(t *testing.T) {
	id := NewEventID()
	if len(id) != 26 {
		t.Fatalf("event id length: got %d want 26 (%q)", len(id), id)
	}
	for i, r := range id {
		if strIndex(crockford, byte(r)) < 0 {
			t.Fatalf("id[%d]=%q not in Crockford alphabet (%q)", i, string(r), id)
		}
	}
}

// TestNewEventIDUniqueAndMonotonic proves ids are unique and lexically sortable
// in generation order, INCLUDING many draws inside a single pinned millisecond
// (the monotonic-increment path). This backs AUD-04 (stable, ordered identity).
func TestNewEventIDUniqueAndMonotonic(t *testing.T) {
	restoreIDSeams(t)
	// Pin the clock to one instant so every id shares a timestamp prefix and the
	// only thing that can advance them is the 80-bit monotonic counter.
	fixed := time.Date(2099, 1, 2, 3, 4, 5, 0, time.UTC)
	idNow = func() time.Time { return fixed }
	// Reset monotonic state so the first draw takes a fresh random suffix.
	idState.mu.Lock()
	idState.lastMS, idState.lastEnt = 0, [10]byte{}
	idState.mu.Unlock()

	const n = 2000
	ids := make([]string, n)
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		id := NewEventID()
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate id at %d: %q", i, id)
		}
		seen[id] = struct{}{}
		ids[i] = id
	}
	if !sort.StringsAreSorted(ids) {
		t.Fatalf("ids within one millisecond are not monotonically increasing")
	}
}

// TestNewEventIDBackwardsClock proves a clock that goes backwards still yields
// advancing (unique, ordered) ids instead of colliding.
func TestNewEventIDBackwardsClock(t *testing.T) {
	restoreIDSeams(t)
	idState.mu.Lock()
	idState.lastMS, idState.lastEnt = 0, [10]byte{}
	idState.mu.Unlock()

	seq := []time.Time{
		time.Date(2099, 5, 5, 5, 5, 5, 0, time.UTC),
		time.Date(2099, 5, 5, 5, 5, 4, 0, time.UTC), // one second BACK.
		time.Date(2099, 5, 5, 5, 5, 3, 0, time.UTC), // and again.
	}
	i := 0
	idNow = func() time.Time { tt := seq[i]; return tt }

	var got []string
	for i = 0; i < len(seq); i++ {
		got = append(got, NewEventID())
	}
	if !sort.StringsAreSorted(got) {
		t.Fatalf("backwards clock broke monotonicity: %v", got)
	}
	if got[0] == got[1] || got[1] == got[2] {
		t.Fatalf("backwards clock produced a collision: %v", got)
	}
}

// strIndex returns the index of b in s, or -1.
func strIndex(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
