// Package ratelimit is a tiny keyed hourly limiter backed by the
// engine's SQLite store. It exists so features beyond the feedback
// consumer (e.g. internal/thinking/autoreflect) can share a single
// cap surface instead of each rolling their own table.
//
// Scope (SPEC-0167 §Stream 3a):
//
//   - One row per (key, UTC-hour-bucket) in the shared
//     `hourly_rate_counters` table owned by the store package.
//   - Counters reset naturally at the top of each UTC hour — no
//     background GC needed for the hot path.
//
// The feedback package uses a parallel, key-less `feedback_counters`
// table that predates this one. Both continue to exist on purpose:
// migrating feedback to this surface is out of scope per the brief
// ("The feedback package stays untouched").
package ratelimit

import (
	"fmt"

	"github.com/kamir/m3c-tools/internal/thinking/store"
)

// HourlyConfig wires a new HourlyLimiter. TableName is accepted only
// to make the type self-documenting; under the hood every instance
// uses the same `hourly_rate_counters` store table.
type HourlyConfig struct {
	TableName string
}

// HourlyLimiter is a counter that lives in the shared store's
// `hourly_rate_counters` table. Safe for concurrent use by multiple
// goroutines because all mutation routes through a serialized SQLite
// transaction in store.IncrementHourlyCounter.
type HourlyLimiter struct {
	store *store.Store
}

// NewHourly builds a HourlyLimiter. Returns an error if s is nil so
// callers fail early at construction time rather than on first call.
func NewHourly(s *store.Store, _ HourlyConfig) (*HourlyLimiter, error) {
	if s == nil {
		return nil, fmt.Errorf("ratelimit: store required")
	}
	return &HourlyLimiter{store: s}, nil
}

// Increment bumps the counter for `key` in the current UTC hour and
// returns the post-increment value. The caller compares that value
// against its own cap. Returning the value rather than a bool lets
// callers distinguish "cap hit for the first time" (useful for
// telemetry) from "cap already exceeded" (drop silently).
func (l *HourlyLimiter) Increment(key string) (int, error) {
	return l.store.IncrementHourlyCounter(key)
}
