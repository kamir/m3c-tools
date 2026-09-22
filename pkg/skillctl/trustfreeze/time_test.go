package trustfreeze

import (
	"errors"
	"testing"
	"time"
)

func TestFormatTime(t *testing.T) {
	plusOne := time.FixedZone("UTC+1", 3600)
	cases := []struct {
		in   time.Time
		want string
	}{
		{testTime, "2026-01-02T03:04:05Z"},
		{time.Date(2026, 1, 2, 4, 4, 5, 0, plusOne), "2026-01-02T03:04:05Z"},
		{testTime.Add(500 * time.Millisecond), "2026-01-02T03:04:05.5Z"},
		{testTime.Add(123456789), "2026-01-02T03:04:05.123456789Z"},
	}
	for _, tc := range cases {
		if got := FormatTime(tc.in); got != tc.want {
			t.Errorf("FormatTime(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestParseTimeStrict: only the exact FormatTime output parses, so signed
// bytes never depend on wall-clock formatting variations (SPEC-0470 TF05-R4).
func TestParseTimeStrict(t *testing.T) {
	good := []string{"2026-01-02T03:04:05Z", "2026-01-02T03:04:05.5Z", "2026-01-02T03:04:05.123456789Z"}
	for _, s := range good {
		got, err := ParseTime(s)
		if err != nil {
			t.Fatalf("ParseTime(%q): %v", s, err)
		}
		if FormatTime(got) != s || got.Location() != time.UTC {
			t.Fatalf("ParseTime(%q) round trip = %q in %v", s, FormatTime(got), got.Location())
		}
	}
	bad := []string{
		"", "2026-01-02T04:04:05+01:00", "2026-01-02T03:04:05+00:00",
		"2026-01-02T03:04:05.500Z", "2026-01-02T03:04:05.0Z", "2026-01-02 03:04:05Z",
		" 2026-01-02T03:04:05Z", "2026-01-02T03:04:05Z ", "2026-01-02T03:04:05z", "2026-01-02",
	}
	for _, s := range bad {
		if _, err := ParseTime(s); !errors.Is(err, ErrBadTime) {
			t.Errorf("ParseTime(%q) = %v, want ErrBadTime", s, err)
		}
	}
}

func TestClocks(t *testing.T) {
	var c Clock = FixedClock{T: testTime}
	if !c.Now().Equal(testTime) || !c.Now().Equal(c.Now()) {
		t.Fatal("FixedClock must return its time every call")
	}
	var s Clock = SystemClock{}
	if s.Now().IsZero() {
		t.Fatal("SystemClock returned the zero time")
	}
}
