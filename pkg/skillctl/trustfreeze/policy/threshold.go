package policy

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
)

// Threshold is the --fail-on value. It decides only Verdict.ThresholdExceeded,
// which the CLI maps to exit 0 or 1; it never changes a finding or the diff
// (SPEC-0469 R8).
type Threshold string

// Thresholds. ThresholdNone never trips.
const (
	ThresholdNone     Threshold = "none"
	ThresholdLow      Threshold = "low"
	ThresholdMedium   Threshold = "medium"
	ThresholdHigh     Threshold = "high"
	ThresholdCritical Threshold = "critical"
)

var thresholdValues = []Threshold{ThresholdNone, ThresholdLow, ThresholdMedium, ThresholdHigh, ThresholdCritical}

// Thresholds returns every threshold, lowest first.
func Thresholds() []Threshold { return slices.Clone(thresholdValues) }

// Valid reports whether t is a known threshold.
func (t Threshold) Valid() bool { return slices.Contains(thresholdValues, t) }

// ParseThreshold parses a threshold strictly (case-sensitive, no trimming).
func ParseThreshold(s string) (Threshold, error) {
	t := Threshold(s)
	if !t.Valid() {
		return "", fmt.Errorf("%w: fail-on threshold %q (want one of none, low, medium, high, critical)", trustfreeze.ErrInvalidEnum, s)
	}
	return t, nil
}

// Exceeded reports whether a finding of severity s is at or above t. It is
// false for ThresholdNone and for an empty or unknown severity.
func (t Threshold) Exceeded(s trustfreeze.Severity) bool {
	if t == ThresholdNone || !t.Valid() || !s.Valid() {
		return false
	}
	return s.Rank() >= trustfreeze.Severity(t).Rank()
}

// MarshalText refuses an empty or unknown threshold.
func (t Threshold) MarshalText() ([]byte, error) {
	if !t.Valid() {
		return nil, fmt.Errorf("%w: refusing to write fail-on threshold %q", trustfreeze.ErrInvalidEnum, string(t))
	}
	return []byte(t), nil
}

// UnmarshalText parses a threshold strictly.
func (t *Threshold) UnmarshalText(b []byte) error {
	v, err := ParseThreshold(string(b))
	if err != nil {
		return err
	}
	*t = v
	return nil
}

// UnmarshalJSON accepts only a JSON string holding a known threshold.
func (t *Threshold) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || b[0] != '"' {
		return fmt.Errorf("%w: fail-on threshold must be a JSON string", trustfreeze.ErrInvalidEnum)
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("%w: fail-on threshold: %w", trustfreeze.ErrInvalidEnum, err)
	}
	return t.UnmarshalText([]byte(s))
}
