package main

import (
	"path/filepath"
	"testing"

	"github.com/kamir/m3c-tools/pkg/plaud"
	"github.com/kamir/m3c-tools/pkg/tracking"
)

func TestPlaudStateSynced(t *testing.T) {
	if !plaudStateSynced(plaudSyncState{DocID: "x"}) {
		t.Error("a doc_id means synced")
	}
	if !plaudStateSynced(plaudSyncState{Status: "synced"}) {
		t.Error("server 'synced' means synced")
	}
	if plaudStateSynced(plaudSyncState{Status: "new"}) {
		t.Error("'new' is not synced")
	}
	if plaudStateSynced(plaudSyncState{}) {
		t.Error("empty state is not synced")
	}
}

// TestMigratePlaudDevLedger proves the legacy "plaud-dev" ledger rows are moved
// into the SHARED consumer format (plaud://<id>, importType "plaud") that the
// menubar's resolvePlaudSyncStates reads via GetByPath — so both tools agree.
func TestMigratePlaudDevLedger(t *testing.T) {
	db, err := tracking.OpenFilesDB(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	const recID, docID = "abc123def4567890", "DOC-XYZ"
	// Legacy write shape: RecordFile(name, recID, …, "plaud-dev", "") + upload.
	if _, err := db.RecordFile("2026-07-15 09:09", recID, 0, "plaud-dev", ""); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordUploadSuccess(recID, "plaud-dev", docID); err != nil {
		t.Fatal(err)
	}
	// Before migration the shared reader can't see it.
	if pf, _ := db.GetByPath("plaud://" + recID); pf != nil && pf.UploadDocID != "" {
		t.Fatal("precondition: shared row should not exist yet")
	}

	migratePlaudDevLedger(db)

	pf, err := db.GetByPath("plaud://" + recID)
	if err != nil || pf == nil || pf.UploadDocID != docID {
		t.Fatalf("after migration GetByPath(plaud://%s) = %+v (err %v), want doc %s", recID, pf, err, docID)
	}
	// Idempotent: a second run must not error or change the doc_id.
	migratePlaudDevLedger(db)
	if pf, _ := db.GetByPath("plaud://" + recID); pf == nil || pf.UploadDocID != docID {
		t.Error("migration is not idempotent")
	}
}

func TestParseIntRange(t *testing.T) {
	cases := []struct {
		in         string
		a, b       int
		ok         bool
	}{
		{"1-3", 1, 3, true},
		{"10-2", 10, 2, true}, // reversed is still a valid range (caller normalizes)
		{"5", 0, 0, false},
		{"1-", 0, 0, false},
		{"-3", 0, 0, false},
		{"a-b", 0, 0, false},
		{"", 0, 0, false},
	}
	for _, c := range cases {
		a, b, ok := parseIntRange(c.in)
		if ok != c.ok || (ok && (a != c.a || b != c.b)) {
			t.Errorf("parseIntRange(%q) = (%d,%d,%v), want (%d,%d,%v)", c.in, a, b, ok, c.a, c.b, c.ok)
		}
	}
}

func TestSortDevNewestFirst(t *testing.T) {
	recs := []plaud.DevRecording{
		{ID: "old", StartAt: "2026-01-01T10:00:00"},
		{ID: "new", StartAt: "2026-08-11T13:02:00"},
		{ID: "mid", StartAt: "2026-06-01T09:00:00"},
	}
	sortDevNewestFirst(recs)
	if recs[0].ID != "new" || recs[1].ID != "mid" || recs[2].ID != "old" {
		t.Errorf("sort order = %s,%s,%s; want new,mid,old", recs[0].ID, recs[1].ID, recs[2].ID)
	}
}

func TestResolveDevSelection(t *testing.T) {
	recs := []plaud.DevRecording{
		{ID: "A"}, {ID: "B"}, {ID: "C"}, {ID: "D"},
	}

	t.Run("numbers + range + id, deduped, order preserved", func(t *testing.T) {
		got, err := resolveDevSelection([]string{"1", "3-4", "B"}, recs)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"A", "C", "D", "B"}
		if len(got) != len(want) {
			t.Fatalf("got %d, want %d: %+v", len(got), len(want), got)
		}
		for i := range want {
			if got[i].ID != want[i] {
				t.Errorf("pos %d = %s, want %s", i, got[i].ID, want[i])
			}
		}
	})

	t.Run("duplicate selection is deduped", func(t *testing.T) {
		got, _ := resolveDevSelection([]string{"1", "1", "A"}, recs)
		if len(got) != 1 || got[0].ID != "A" {
			t.Errorf("expected single A, got %+v", got)
		}
	})

	t.Run("reversed range normalizes", func(t *testing.T) {
		got, err := resolveDevSelection([]string{"4-2"}, recs)
		if err != nil || len(got) != 3 || got[0].ID != "B" || got[2].ID != "D" {
			t.Errorf("4-2 → %+v (err %v), want B,C,D", got, err)
		}
	})

	t.Run("out of range errors", func(t *testing.T) {
		if _, err := resolveDevSelection([]string{"9"}, recs); err == nil {
			t.Error("expected out-of-range error")
		}
	})

	t.Run("unknown id errors", func(t *testing.T) {
		if _, err := resolveDevSelection([]string{"Z"}, recs); err == nil {
			t.Error("expected unknown-id error")
		}
	})
}
