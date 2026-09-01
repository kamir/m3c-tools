// pragma_test.go proves the R-2.4 hot-path constraint on the PURE-GO (modernc)
// driver path: with a competing writer holding the file's write lock, the hot
// Append must return within the pinned busy_timeout (~250ms) — NEVER the 5000ms
// house default (a 5s stall would freeze the hook and the harness could read the
// non-return as ALLOW, AC-3). The caller then spools.
//
// This test is nocgo-only because the modernc `_pragma=` DSN pin is the path
// that would silently fail if we relied on mattn's `_busy_timeout` spelling.
//
//go:build !cgo

package outbox

import (
	"testing"
	"time"
)

func TestBusyTimeoutBoundedModernc(t *testing.T) {
	home := t.TempDir()
	s, err := Open(home)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	// A SECOND independent handle to the same file (the cross-process
	// contention R-2.4 addresses — each process has its own pinned connection).
	blocker, err := openHotPathDB(DBPath(home))
	if err != nil {
		t.Fatalf("open blocker: %v", err)
	}
	defer blocker.Close()

	tx, err := blocker.Begin()
	if err != nil {
		t.Fatalf("begin blocker tx: %v", err)
	}
	// Acquire and HOLD the WAL write lock.
	if _, err := tx.Exec(`INSERT INTO sync_state(k,v) VALUES('lock','1')`); err != nil {
		t.Fatalf("blocker write: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	rec, pj, ph := makeRecord(t, 99, "2026-07-08T10:00:00Z")
	start := time.Now()
	err = s.Append(rec, pj, ph)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected SQLITE_BUSY while the write lock is held")
	}
	// The discriminator: 250ms pin returns fast; the 5000ms default would blow
	// past 2s. A generous 2s ceiling keeps the test stable on slow CI.
	if elapsed > 2*time.Second {
		t.Fatalf("busy_timeout not pinned to ~250ms: Append took %v (house default would be ~5s)", elapsed)
	}

	// And the caller's fallback (spool) still records the row → decision returns
	// regardless (R-2.4 / R-8.1 default).
	if serr := s.Spool(rec, pj, ph); serr != nil {
		t.Fatalf("spool fallback failed: %v", serr)
	}
}
