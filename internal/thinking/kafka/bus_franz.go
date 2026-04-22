// bus_franz.go — franz-go-backed Bus.
//
// Compile with:  go build -tags thinking_kafka
//
// Intentionally behind a build tag so the default Week 1 build does
// not require franz-go (or a broker) to produce a usable binary.
// SPEC-0167 locks franz-go as the Phase 2 production driver; Phase 1
// scaffold ships the interface + in-memory implementation, with this
// file as the slot real infrastructure will inhabit.
//
//go:build thinking_kafka

package kafka

import (
	"context"
	"encoding/json"
	"errors"

	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
)

// NewFranzBus will return a franz-go-backed Bus bound to owner.
// The implementation is intentionally stubbed until the dependency
// is added to go.mod; callers opting into this build tag are
// expected to wire franz-go themselves. See SPEC-0167 Phase 2 plan.
func NewFranzBus(owner mctx.Hash, brokers []string) (Bus, error) {
	_ = owner
	_ = brokers
	return nil, errors.New("thinking/kafka: franz-go driver is Phase 2; see SPEC-0167")
}

// compile-only placeholder to keep json import referenced if the
// stub is expanded.
var _ = json.Marshal
var _ context.Context
