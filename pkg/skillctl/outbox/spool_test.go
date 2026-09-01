package outbox

import (
	"os"
	"testing"
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

func TestReconcileSkipsMalformedLine(t *testing.T) {
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
	if err != nil {
		t.Fatalf("Reconcile should skip garbage, not fail: %v", err)
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
