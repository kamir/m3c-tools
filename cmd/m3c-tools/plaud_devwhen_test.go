//go:build darwin

package main

import (
	"testing"
	"time"
)

// TestDevWhenRendersLocal is the display half of FR-0095: the Plaud Sync window
// and `plaud dev list` must show the LOCAL recording time, not the UTC wall
// clock the API happens to send. The screenshot that started the report showed
// "13:50" for a recording made at 15:50 CEST.
func TestDevWhenRendersLocal(t *testing.T) {
	prev := time.Local
	berlin, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Skipf("no tzdata for Europe/Berlin: %v", err)
	}
	time.Local = berlin
	defer func() { time.Local = prev }()

	cases := []struct{ in, want string }{
		{"2026-09-03T13:50:56", "2026-09-03 15:50"}, // CEST: +2
		{"2026-01-15T13:50:56", "2026-01-15 14:50"}, // CET:  +1
		{"2026-09-03T23:30:00", "2026-09-04 01:30"}, // rolls into the next local day
	}
	for _, tc := range cases {
		if got := devWhen(tc.in); got != tc.want {
			t.Errorf("devWhen(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestDevWhenShowsUnparsableRaw: never guess. A format we cannot read is shown
// as-is, so it is obviously wrong rather than convincingly wrong.
func TestDevWhenShowsUnparsableRaw(t *testing.T) {
	for _, in := range []string{"", "tomorrow", "2026-09-03"} {
		if got := devWhen(in); got != in {
			t.Errorf("devWhen(%q) = %q, want the raw input back", in, got)
		}
	}
}
