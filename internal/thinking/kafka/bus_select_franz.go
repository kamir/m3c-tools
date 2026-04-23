//go:build thinking_kafka

package kafka

import (
	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
)

// NewBus returns a franz-go-backed Bus when brokers are given, falling
// back to the in-memory Bus when no brokers are configured (so
// `-tags thinking_kafka` tests without a broker still run).
func NewBus(owner mctx.Hash, brokers []string) (Bus, error) {
	if len(brokers) == 0 {
		return NewMemBus(owner), nil
	}
	return NewFranzBus(owner, brokers)
}
