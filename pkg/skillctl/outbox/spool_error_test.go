package outbox

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSpoolStoragePreparationFailures(t *testing.T) {
	dir := t.TempDir()
	blocked := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(blocked, []byte("preserve this file"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{blocked, filepath.Join(blocked, "child")} {
		if err := ensureSpoolDir(path); err == nil {
			t.Fatalf("accepted unusable spool directory %s", path)
		}
	}
	if _, err := acquireSpoolLock(filepath.Join(blocked, "spool.lock")); err == nil {
		t.Fatal("lock open failure must reach the caller")
	}
	if err := writeSpoolLine(dir, []byte("event\n")); err == nil {
		t.Fatal("cannot append an event to a directory")
	}
	if err := syncSpoolDir(filepath.Join(dir, "absent")); runtime.GOOS != "windows" && err == nil {
		t.Fatal("missing directory sync must fail")
	}
	got, err := os.ReadFile(blocked)
	if err != nil || string(got) != "preserve this file" {
		t.Fatalf("failed preparation changed existing storage: %q, %v", got, err)
	}

	// A fresh nested home exercises persistence through each created ancestor.
	home := filepath.Join(dir, "new", "nested", "home")
	rec, pj, ph := makeRecord(t, 1001, "2026-07-08T10:00:00Z")
	if err := SpoolTo(home, rec, pj, ph); err != nil {
		t.Fatalf("prepare fresh spool hierarchy: %v", err)
	}
	if err := SpoolTo(blocked, rec, pj, ph); err == nil {
		t.Fatal("unusable home must not acknowledge durable evidence")
	}
}

func TestSpoolLockAndWriteOpenFailures(t *testing.T) {
	for _, filename := range []string{"spool.lock", "spool.jsonl"} {
		t.Run(filename, func(t *testing.T) {
			s := openTemp(t)
			if err := os.Mkdir(filepath.Join(s.dir, filename), 0o700); err != nil {
				t.Fatal(err)
			}
			rec, pj, ph := makeRecord(t, 1002, "2026-07-08T10:00:00Z")
			if err := s.Spool(rec, pj, ph); err == nil {
				t.Fatal("spool must not acknowledge a failed lock or write open")
			}
		})
	}
	for _, filename := range []string{"spool.drain.lock", "spool.lock"} {
		t.Run("reconcile-"+filename, func(t *testing.T) {
			s := openTemp(t)
			if err := os.Mkdir(filepath.Join(s.dir, filename), 0o700); err != nil {
				t.Fatal(err)
			}
			if n, err := s.Reconcile(); err == nil || n != 0 {
				t.Fatalf("failed reconcile lock: n=%d, err=%v", n, err)
			}
		})
	}
}

func TestReconcileUnreadablePendingPreservesActiveSpool(t *testing.T) {
	s := openTemp(t)
	rec, pj, ph := makeRecord(t, 1003, "2026-07-08T10:00:00Z")
	if err := s.Spool(rec, pj, ph); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(s.SpoolPath())
	if err != nil {
		t.Fatal(err)
	}
	pending := filepath.Join(s.dir, "spool.pending.jsonl")
	if err := os.Mkdir(pending, 0o700); err != nil {
		t.Fatal(err)
	}
	if n, err := s.Reconcile(); n != 0 || err == nil || !strings.Contains(err.Error(), "reconcile read") {
		t.Fatalf("unreadable pending: n=%d, err=%v", n, err)
	}
	after, err := os.ReadFile(s.SpoolPath())
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("active evidence changed on failed pending read: %v", err)
	}
	if err := os.Remove(pending); err != nil {
		t.Fatal(err)
	}
	if n, err := s.Reconcile(); n != 1 || err != nil {
		t.Fatalf("recovery after fixing pending path: n=%d, err=%v", n, err)
	}
}

func TestReconcileOversizedLineRetainsBothBatches(t *testing.T) {
	s := openTemp(t)
	rec, pj, ph := makeRecord(t, 1004, "2026-07-08T10:00:00Z")
	if err := s.Spool(rec, pj, ph); err != nil {
		t.Fatal(err)
	}
	pending := filepath.Join(s.dir, "spool.pending.jsonl")
	// An over-budget line may be damaged evidence. It must remain available for
	// recovery, with the active batch untouched and no false successful drain.
	oversized := bytes.Repeat([]byte("x"), (4<<20)+1)
	if err := os.WriteFile(pending, oversized, 0o600); err != nil {
		t.Fatal(err)
	}
	if n, err := s.Reconcile(); n != 0 || err == nil || !strings.Contains(err.Error(), "reconcile scan") {
		t.Fatalf("oversized pending line: n=%d, err=%v", n, err)
	}
	got, err := os.ReadFile(pending)
	if err != nil || !bytes.Equal(got, oversized) {
		t.Fatalf("oversized evidence was altered: %v", err)
	}
	if err := os.Remove(pending); err != nil {
		t.Fatal(err)
	}
	if n, err := s.Reconcile(); n != 1 || err != nil {
		t.Fatalf("active batch lost after scanner failure: n=%d, err=%v", n, err)
	}
}

func TestReconcileDatabaseFailureReplaysPendingBeforeActive(t *testing.T) {
	s := openTemp(t)
	rec, pj, ph := makeRecord(t, 1005, "2026-07-08T10:00:00Z")
	if err := s.Spool(rec, pj, ph); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if n, err := s.Reconcile(); n != 0 || err == nil || !strings.Contains(err.Error(), "reconcile append") {
		t.Fatalf("closed database: n=%d, err=%v", n, err)
	}
	pending := filepath.Join(s.dir, "spool.pending.jsonl")
	if _, err := os.Stat(pending); err != nil {
		t.Fatalf("failed database append lost pending evidence: %v", err)
	}
	rec2, pj2, ph2 := makeRecord(t, 1006, "2026-07-08T10:00:00Z")
	if err := s.Spool(rec2, pj2, ph2); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(s.home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	for i := 0; i < 2; i++ {
		if n, err := reopened.Reconcile(); n != 1 || err != nil {
			t.Fatalf("recovery drain %d: n=%d, err=%v", i, n, err)
		}
	}
	if n, err := reopened.PendingCount(); n != 2 || err != nil {
		t.Fatalf("recovered count=%d, err=%v", n, err)
	}
}
