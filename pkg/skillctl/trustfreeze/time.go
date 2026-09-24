package trustfreeze

import (
	"errors"
	"fmt"
	"time"
)

// ErrBadTime is wrapped by ParseTime.
var ErrBadTime = errors.New("trustfreeze: time is not in canonical form")

// FormatTime is the one time format of the model: UTC, RFC 3339 with
// nanoseconds and trailing zeros removed (SPEC-0466, SPEC-0470 TF05-R4).
func FormatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

// ParseTime parses s strictly: it must be exactly what FormatTime produces, so
// offsets other than "Z", lowercase letters, padded fractions and surrounding
// spaces are rejected.
func ParseTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %q: %w", ErrBadTime, s, err)
	}
	if FormatTime(t) != s {
		return time.Time{}, fmt.Errorf("%w: %q (want %q)", ErrBadTime, s, FormatTime(t))
	}
	return t.UTC(), nil
}

// Clock is the injected time source. Production code uses SystemClock; tests
// use FixedClock. No other code in Trust Freeze reads the wall clock.
type Clock interface {
	Now() time.Time
}

// SystemClock reads the wall clock.
type SystemClock struct{}

// Now returns the current time.
func (SystemClock) Now() time.Time { return time.Now() }

// FixedClock always returns T.
type FixedClock struct {
	T time.Time
}

// Now returns c.T.
func (c FixedClock) Now() time.Time { return c.T }
