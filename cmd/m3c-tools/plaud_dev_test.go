//go:build darwin

package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/plaud"
	"github.com/kamir/m3c-tools/pkg/tracking"
)

// TestFormatTranscriptionQueue proves the server-side-whisper progress render:
// the empty case, the populated case (per-status counts + per-item lines), the
// >15 truncation tail, and the malformed-body raw fallback — all offline, using
// the exact JSON shape aims-core's /transcription-queue returns.
func TestFormatTranscriptionQueue(t *testing.T) {
	t.Run("empty queue is a clean OK", func(t *testing.T) {
		out := formatTranscriptionQueue([]byte(`{"queue":[],"failed":[],"queue_count":0,"failed_count":0}`))
		if !strings.Contains(out, "empty") || !strings.Contains(out, "✅") {
			t.Errorf("empty queue not reported as clean: %q", out)
		}
	})

	t.Run("populated: counts + per-item progress", func(t *testing.T) {
		body := `{"queue":[
			{"doc_id":"DOC-AAAA","status":"transcribing","attempt":1,"max_attempts":3,"audio_duration_label":"12m3s","claimed_by":"worker-macpro-01"},
			{"doc_id":"DOC-BBBB","status":"queued","attempt":0,"max_attempts":3,"audio_duration_label":"4m0s"},
			{"doc_id":"DOC-CCCC","status":"queued","attempt":0,"max_attempts":3,"audio_duration_label":"1m2s"}
		],"failed":[{"doc_id":"DOC-DEAD"}],"queue_count":3,"failed_count":1}`
		out := formatTranscriptionQueue([]byte(body))
		for _, want := range []string{
			"3 active · 1 failed",
			"queued", "2", // 2 queued
			"transcribing", "1", // 1 transcribing
			"DOC-AAAA", "12m3s", "1/3", "worker-macpro-01",
			"DOC-BBBB", "DOC-CCCC",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("render missing %q:\n%s", want, out)
			}
		}
		// A status with zero items must not be printed.
		if strings.Contains(out, "detecting_language") {
			t.Errorf("printed a zero-count status:\n%s", out)
		}
	})

	t.Run("more than 15 items truncates with a tail", func(t *testing.T) {
		var sb strings.Builder
		sb.WriteString(`{"queue":[`)
		for i := 0; i < 20; i++ {
			if i > 0 {
				sb.WriteByte(',')
			}
			sb.WriteString(`{"doc_id":"D","status":"queued","attempt":0,"max_attempts":3,"audio_duration_label":"1m"}`)
		}
		sb.WriteString(`],"failed":[],"queue_count":20,"failed_count":0}`)
		out := formatTranscriptionQueue([]byte(sb.String()))
		if !strings.Contains(out, "and 5 more") {
			t.Errorf("expected '… and 5 more' tail for 20 items:\n%s", out)
		}
	})

	t.Run("malformed body falls back to raw", func(t *testing.T) {
		out := formatTranscriptionQueue([]byte(`not json`))
		if !strings.Contains(out, "raw response") {
			t.Errorf("expected raw fallback: %q", out)
		}
	})
}

// TestPlaudMaxAudioBytes proves the configurable audio cap that keeps oversized
// Plaud uploads under the ER1 ingress limit (the 413 fix): default, override,
// and rejection of invalid / non-positive values.
func TestPlaudMaxAudioBytes(t *testing.T) {
	const MB = 1024 * 1024
	cases := []struct {
		env  string
		want int
	}{
		{"", 30 * MB},        // unset → default 30 MB
		{"10", 10 * MB},      // raise/lower for important long recordings
		{"31", 31 * MB},      // push toward the ~32 MiB server cap
		{"garbage", 30 * MB}, // invalid → default
		{"0", 30 * MB},       // non-positive rejected → default
		{"-5", 30 * MB},      // negative rejected → default
	}
	for _, c := range cases {
		t.Setenv("PLAUD_MAX_AUDIO_MB", c.env)
		if got := plaudMaxAudioBytes(); got != c.want {
			t.Errorf("PLAUD_MAX_AUDIO_MB=%q → %d bytes, want %d", c.env, got, c.want)
		}
	}
}

func TestHumanMB(t *testing.T) {
	if got := humanMB(30 * 1024 * 1024); got != "30.0 MB" {
		t.Errorf("humanMB(30MiB) = %q, want %q", got, "30.0 MB")
	}
	if got := humanMB(0); got != "0.0 MB" {
		t.Errorf("humanMB(0) = %q, want %q", got, "0.0 MB")
	}
}

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
		in   string
		a, b int
		ok   bool
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
