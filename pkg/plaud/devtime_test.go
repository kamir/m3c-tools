package plaud

import (
	"testing"
	"time"
)

// TestParseDevTimeIsUTC pins the fact FR-0095 turned on: the developer API's
// zone-less timestamps are UTC, so the parsed instant rendered in Europe/Berlin
// must move forward — two hours in CEST, ONE in CET. The winter case is in here
// deliberately: the bug was half as large in winter and correspondingly easier
// to dismiss as "close enough".
func TestParseDevTimeIsUTC(t *testing.T) {
	berlin, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Skipf("no tzdata for Europe/Berlin: %v", err)
	}

	cases := []struct {
		name      string
		in        string
		wantLocal string
	}{
		// The recording from the FR: shown as 13:50 in the importer, actually 15:50.
		{"summer CEST is +2", "2026-09-03T13:50:56", "2026-09-03 15:50:56"},
		{"winter CET is +1", "2026-01-15T13:50:56", "2026-01-15 14:50:56"},
		// A date crossing midnight in UTC belongs to the NEXT local day.
		{"late evening rolls the date", "2026-09-03T23:30:00", "2026-09-04 01:30:00"},
		// If Plaud ever starts sending an offset, honour it instead of assuming UTC.
		{"explicit offset is honoured", "2026-09-03T15:50:56+02:00", "2026-09-03 15:50:56"},
		{"explicit Z is honoured", "2026-09-03T13:50:56Z", "2026-09-03 15:50:56"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ParseDevTime(tc.in)
			if !ok {
				t.Fatalf("ParseDevTime(%q) failed to parse", tc.in)
			}
			if s := got.In(berlin).Format("2006-01-02 15:04:05"); s != tc.wantLocal {
				t.Errorf("ParseDevTime(%q) in Berlin = %s, want %s", tc.in, s, tc.wantLocal)
			}
		})
	}
}

// TestParseDevTimeRejectsGarbage: an unparsable value must be REPORTED, never
// silently replaced by a plausible-looking one. The display path shows the raw
// string and the backfill skips the item, so a Plaud format change becomes
// visible instead of quietly writing today's date into the corpus.
func TestParseDevTimeRejectsGarbage(t *testing.T) {
	for _, in := range []string{"", "not-a-time", "2026-09-03", "03.09.2026 13:50"} {
		if got, ok := ParseDevTime(in); ok {
			t.Errorf("ParseDevTime(%q) = %v, true; want failure", in, got)
		}
	}
}

// TestStartedAtLocal proves the helper the backfill relies on returns the local
// rendering of start_at — the value that must end up in ER1's zone-less
// current_time field.
func TestStartedAtLocal(t *testing.T) {
	prev := time.Local
	berlin, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Skipf("no tzdata for Europe/Berlin: %v", err)
	}
	time.Local = berlin
	defer func() { time.Local = prev }()

	r := DevRecording{ID: "x", StartAt: "2026-09-03T13:44:14"}
	got, ok := r.StartedAtLocal()
	if !ok {
		t.Fatal("StartedAtLocal failed on a well-formed start_at")
	}
	if s := got.Format("2006-01-02 15:04:05"); s != "2026-09-03 15:44:14" {
		t.Errorf("StartedAtLocal = %s, want 2026-09-03 15:44:14", s)
	}

	if _, ok := (DevRecording{StartAt: ""}).StartedAtLocal(); ok {
		t.Error("StartedAtLocal accepted an empty start_at")
	}
}
