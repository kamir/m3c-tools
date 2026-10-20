package outbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSpoolThenReconcileOrdersByOccurredAt(t *testing.T) {
	s := openTemp(t)

	// Spool three rows OUT of occurred_at order.
	recC, pjC, phC := makeRecord(t, 30, "2026-07-08T10:03:00Z")
	recA, pjA, phA := makeRecord(t, 10, "2026-07-08T10:01:00Z")
	recB, pjB, phB := makeRecord(t, 20, "2026-07-08T10:02:00Z")
	if err := s.Spool(recC, pjC, phC); err != nil {
		t.Fatal(err)
	}
	if err := s.Spool(recA, pjA, phA); err != nil {
		t.Fatal(err)
	}
	if err := s.Spool(recB, pjB, phB); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(s.SpoolPath()); err != nil {
		t.Fatalf("spool file should exist: %v", err)
	}

	drained, err := s.Reconcile()
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if drained != 3 {
		t.Fatalf("want 3 drained, got %d", drained)
	}

	// Spool file removed after a clean drain.
	if _, err := os.Stat(s.SpoolPath()); !os.IsNotExist(err) {
		t.Fatalf("spool file should be gone after reconcile: %v", err)
	}

	batch, err := s.PendingBatch(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch) != 3 {
		t.Fatalf("want 3 rows, got %d", len(batch))
	}
	// PendingBatch orders by occurred_at ASC → A, B, C.
	wantOrder := []string{recA.EventID, recB.EventID, recC.EventID}
	for i, id := range wantOrder {
		if batch[i].EventID != id {
			t.Fatalf("row %d: want %s got %s", i, id, batch[i].EventID)
		}
	}
}

func TestReconcileIdempotentAndDedups(t *testing.T) {
	s := openTemp(t)
	rec, pj, ph := makeRecord(t, 40, "2026-07-08T10:00:00Z")

	// Same row directly appended AND spooled → reconcile must dedup on event_id.
	if err := s.Append(rec, pj, ph); err != nil {
		t.Fatal(err)
	}
	if err := s.Spool(rec, pj, ph); err != nil {
		t.Fatal(err)
	}
	drained, err := s.Reconcile()
	if err != nil {
		t.Fatal(err)
	}
	if drained != 1 {
		t.Fatalf("want 1 drained, got %d", drained)
	}
	if n, _ := s.PendingCount(); n != 1 {
		t.Fatalf("dedup failed: want 1 row got %d", n)
	}

	// Reconcile on an empty/absent spool is a clean no-op.
	drained, err = s.Reconcile()
	if err != nil {
		t.Fatalf("reconcile empty: %v", err)
	}
	if drained != 0 {
		t.Fatalf("want 0 drained on empty spool, got %d", drained)
	}
}

func TestReconcileRetainsMalformedLine(t *testing.T) {
	s := openTemp(t)
	rec, pj, ph := makeRecord(t, 50, "2026-07-08T10:00:00Z")
	if err := s.Spool(rec, pj, ph); err != nil {
		t.Fatal(err)
	}
	// Append a garbage line directly to the spool file.
	f, err := os.OpenFile(s.SpoolPath(), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("{not json\n")
	_ = f.Close()

	drained, err := s.Reconcile()
	if err == nil || !strings.Contains(err.Error(), "malformed line") {
		t.Fatalf("Reconcile must report preserved garbage: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(s.dir, "spool.pending.jsonl")); err != nil || !bytes.Contains(b, []byte("{not json")) {
		t.Fatalf("malformed evidence was not retained: %q, %v", b, err)
	}
	if drained != 1 {
		t.Fatalf("want 1 valid row drained, got %d", drained)
	}
	if n, _ := s.PendingCount(); n != 1 {
		t.Fatalf("want 1 row, got %d", n)
	}
}

func TestAppendOrSpoolUsesDBWhenHealthy(t *testing.T) {
	s := openTemp(t)
	rec, pj, ph := makeRecord(t, 60, "2026-07-08T10:00:00Z")
	if err := s.AppendOrSpool(rec, pj, ph); err != nil {
		t.Fatalf("AppendOrSpool: %v", err)
	}
	// Healthy db → no spool file created.
	if _, err := os.Stat(s.SpoolPath()); !os.IsNotExist(err) {
		t.Fatalf("healthy AppendOrSpool must not spool: %v", err)
	}
	if n, _ := s.PendingCount(); n != 1 {
		t.Fatalf("want 1 row, got %d", n)
	}
}

// The subprocess uses the public fallback without opening the database. This
// catches synchronization that only protects goroutines in the current process.
func TestSpoolProcessHelper(t *testing.T) {
	home := os.Getenv("M3C_SPOOL_TEST_HOME")
	if home == "" {
		return
	}
	switch os.Getenv("M3C_SPOOL_TEST_MODE") {
	case "lock-exit":
		if _, err := acquireSpoolLock(filepath.Join(dirName(home), "spool.lock")); err != nil {
			t.Fatal(err)
		}
		os.Exit(0) // Exercise OS lock release after a process exits without Close.
	case "expect-busy":
		rec, pj, ph := makeRecord(t, 901, "2026-07-08T10:00:00Z")
		if err := SpoolTo(home, rec, pj, ph); err == nil {
			t.Fatal("another process holds the lock; append must fail explicitly")
		}
	default:
		for i := 0; i < 4; i++ {
			rec, pj, ph := makeRecord(t, 910+i, "2026-07-08T10:00:00Z")
			if err := SpoolTo(home, rec, pj, ph); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func runSpoolProcess(t *testing.T, home, mode string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSpoolProcessHelper$")
	cmd.Env = append(os.Environ(), "M3C_SPOOL_TEST_HOME="+home, "M3C_SPOOL_TEST_MODE="+mode)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("spool subprocess: %v: %s", err, out)
	}
}

func TestSpoolWriterProcessSurvivesConcurrentReconcile(t *testing.T) {
	s := openTemp(t)
	rec, pj, ph := makeRecord(t, 900, "2026-07-08T10:00:00Z")
	if err := s.Spool(rec, pj, ph); err != nil {
		t.Fatal(err)
	}
	// Reserve the only SQL connection. Reconcile rotates and reads its batch,
	// then waits for SQL while the independent writer appends to a new file.
	conn, err := s.db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	go func() { n, err := s.Reconcile(); done <- result{n, err} }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(s.dir, "spool.pending.jsonl")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("reconcile did not rotate the batch")
		}
		time.Sleep(time.Millisecond)
	}
	runSpoolProcess(t, s.home, "write")
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if r := <-done; r.err != nil || r.n != 1 {
		t.Fatalf("first drain: %+v", r)
	}
	if n, err := s.Reconcile(); err != nil || n != 4 {
		t.Fatalf("concurrent writer rows: n=%d, err=%v", n, err)
	}
	if n, err := s.PendingCount(); err != nil || n != 5 {
		t.Fatalf("expected all 5 events, n=%d, err=%v", n, err)
	}
}

func TestSpoolProcessLockBoundedAndReleasedOnExit(t *testing.T) {
	s := openTemp(t)
	lock, err := acquireSpoolLock(filepath.Join(s.dir, "spool.lock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lock.Close() })
	start := time.Now()
	runSpoolProcess(t, s.home, "expect-busy")
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("lock contention exceeded bounded wait: %s", elapsed)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	runSpoolProcess(t, s.home, "lock-exit")
	runSpoolProcess(t, s.home, "write")
	if n, err := s.Reconcile(); err != nil || n != 4 {
		t.Fatalf("lock remained held after process exit: n=%d err=%v", n, err)
	}
}

func TestReconcileLegacyAndInterruptedPendingBatch(t *testing.T) {
	s := openTemp(t)
	rec, pj, ph := makeRecord(t, 950, "2026-07-08T10:00:00Z")
	line, err := json.Marshal(spoolEntry{Record: rec, PayloadJSON: pj, PayloadHash: ph})
	if err != nil {
		t.Fatal(err)
	}
	// A legacy spool is ingested using exactly its original envelope.
	if err := os.WriteFile(s.SpoolPath(), append(line, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	pending, err := s.rotateSpool()
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a completed SQL insert followed by a crash before cleanup.
	if err := s.Append(rec, pj, ph); err != nil {
		t.Fatal(err)
	}
	if n, err := s.Reconcile(); err != nil || n != 1 {
		t.Fatalf("replay: %d, %v", n, err)
	}
	if n, err := s.PendingCount(); err != nil || n != 1 {
		t.Fatalf("dedup: %d, %v", n, err)
	}
	if _, err := os.Stat(pending); !os.IsNotExist(err) {
		t.Fatalf("pending batch not removed: %v", err)
	}
}

type failingSpoolWriter struct {
	writeN                      int
	writeErr, syncErr, closeErr error
	synced, closed              bool
}

func (f *failingSpoolWriter) Write([]byte) (int, error) { return f.writeN, f.writeErr }
func (f *failingSpoolWriter) Sync() error               { f.synced = true; return f.syncErr }
func (f *failingSpoolWriter) Close() error              { f.closed = true; return f.closeErr }

func TestPersistSpoolLinePropagatesDurabilityErrors(t *testing.T) {
	failure := errors.New("injected storage failure")
	for _, tc := range []struct {
		name     string
		writer   failingSpoolWriter
		want     error
		wantSync bool
	}{
		{"write", failingSpoolWriter{writeErr: failure}, failure, false},
		{"short-write", failingSpoolWriter{writeN: 1}, io.ErrShortWrite, false},
		{"sync", failingSpoolWriter{writeN: 2, syncErr: failure}, failure, true},
		{"close", failingSpoolWriter{writeN: 2, closeErr: failure}, failure, true},
		{"success", failingSpoolWriter{writeN: 2}, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := persistSpoolLine(&tc.writer, []byte("x\n"))
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v got %v", tc.want, err)
			}
			if !tc.writer.closed || tc.writer.synced != tc.wantSync {
				t.Fatalf("sync=%v close=%v", tc.writer.synced, tc.writer.closed)
			}
		})
	}
}
