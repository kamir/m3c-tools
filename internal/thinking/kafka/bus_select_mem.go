//go:build !thinking_kafka

package kafka

import (
	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
)

// NewBus returns an in-memory Bus regardless of brokers. This file is
// selected when the `thinking_kafka` build tag is absent — used for
// unit tests and the default dev build. Pair with bus_select_franz.go
// for the real-Kafka build.
func NewBus(owner mctx.Hash, brokers []string) (Bus, error) {
	return NewMemBus(owner), nil
}
