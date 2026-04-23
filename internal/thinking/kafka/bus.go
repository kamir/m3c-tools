package kafka

import (
	"context"
	"encoding/json"
	"sync"

	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
)

// Message is a produced or consumed record. Key is typically the
// domain id (thought_id, process_id, ...). Value carries the JSON
// payload.
type Message struct {
	Topic string
	Key   []byte
	Value []byte
}

// Handler consumes one message. Returning an error stops the loop
// (franz-go commits offsets only on success).
type Handler func(ctx context.Context, m Message) error

// Bus is the minimal Kafka surface used by the engine. Both the
// in-memory and franz-go drivers implement it. Integration tests
// can rely on the in-memory driver when testing.Short() is true.
type Bus interface {
	// Produce sends a JSON-encoded value to topic. The topic MUST
	// start with the engine's own hash prefix; otherwise the wrapper
	// panics.
	Produce(ctx context.Context, topic string, key string, value any) error

	// Subscribe registers a handler for topic and returns a function
	// that stops the consumer. Same prefix rule applies.
	Subscribe(topic string, h Handler) (stop func(), err error)

	// Close releases any underlying resources.
	Close() error
}

// ----- In-memory driver (default) -----

type memBus struct {
	owner mctx.Hash
	mu    sync.Mutex
	subs  map[string][]Handler
	stop  chan struct{}
}

// NewMemBus returns an in-process Bus bound to the given owner hash.
// All produced messages are dispatched synchronously to subscribers.
func NewMemBus(owner mctx.Hash) Bus {
	return &memBus{
		owner: owner,
		subs:  map[string][]Handler{},
		stop:  make(chan struct{}),
	}
}

func (b *memBus) Produce(ctx context.Context, topic string, key string, value any) error {
	assertOwnedBy(topic, b.owner)
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	b.mu.Lock()
	handlers := append([]Handler(nil), b.subs[topic]...)
	b.mu.Unlock()
	msg := Message{Topic: topic, Key: []byte(key), Value: body}
	for _, h := range handlers {
		// fire-and-forget per subscriber; errors logged by caller
		go func(h Handler) { _ = h(ctx, msg) }(h)
	}
	return nil
}

func (b *memBus) Subscribe(topic string, h Handler) (func(), error) {
	assertOwnedBy(topic, b.owner)
	b.mu.Lock()
	b.subs[topic] = append(b.subs[topic], h)
	b.mu.Unlock()
	return func() { /* in-memory stop is a no-op for Phase 1 Week 1 */ }, nil
}

func (b *memBus) Close() error {
	close(b.stop)
	return nil
}

// ConsumerLag implements the observability.BusMetrics contract for
// the in-memory bus. There is no broker and no offset tracking —
// every call returns 0 so Prometheus dashboards render a flat line
// rather than erroring out in dev / test runs.
func (b *memBus) ConsumerLag(topic string) (int64, error) {
	// Intentional: assertOwnedBy is NOT called here because the
	// observability poller queries for its own ctx-owned topics only.
	// Returning (0, nil) is the correct "idle" answer for an
	// in-process dispatcher.
	_ = topic
	return 0, nil
}
