package main

import (
	"testing"

	"github.com/kamir/m3c-tools/pkg/plaud"
)

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
