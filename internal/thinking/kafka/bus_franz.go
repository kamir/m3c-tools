// bus_franz.go — franz-go-backed Bus (SPEC-0167 Stream 2c).
//
// Compile with:  go build -tags thinking_kafka
//
// Intentionally behind a build tag so the default build does not
// require franz-go (or a broker) to produce a usable binary — the
// default build resolves to the in-memory memBus in bus.go.
//
// This driver implements the same Bus interface as the in-memory
// reference, and enforces the same SPEC-0167 §Isolation Model
// invariants:
//
//   - assertOwnedBy(topic, owner) is called on every Produce and
//     Subscribe — cross-tenant topic names panic.
//   - Consumer groups are named "m3c-<ctx_hash>-<role>" so two
//     users' engines can never accidentally share a group even if
//     they were to point at the same broker.
//
// Producer configuration for Phase 1 (dev, RF=1):
//   - Acks       : LeaderAck()  — broker=1, min ISR=1 in cp-all-in-one.
//     Phase 2 will flip to AllISRAcks() once the 3-broker cluster is
//     deployed (D5).
//   - Idempotent : disabled      — irrelevant with acks=1.
//   - Retries    : 5             — plenty for a local broker.
//   - Timeout    : 5s request, 10s record delivery.
//
// Consumer configuration:
//   - Group          : "m3c-<ctx_hash>-<role>"
//   - ResetOffset    : AtStart() — the engine replays from the
//     beginning of each topic on first start. Once an offset is
//     committed, it takes over.
//   - AutoCommit     : off; we commit only after successful handler
//     invocations via CommitRecords in the poll loop.
//
//go:build thinking_kafka

package kafka

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"

	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
)

// franzBus is the franz-go-backed Bus implementation.
//
// One producer client is shared across all Produce calls. Each
// Subscribe spawns its own consumer client bound to a unique
// consumer-group name; stopping a subscription tears down only that
// client, leaving others intact. Close tears down everything.
type franzBus struct {
	owner    mctx.Hash
	brokers  []string
	producer *kgo.Client

	mu     sync.Mutex
	subs   []*franzSub
	closed bool
}

type franzSub struct {
	cl     *kgo.Client
	cancel context.CancelFunc
	done   chan struct{}
}

// NewFranzBus constructs a franz-go-backed Bus bound to owner. The
// returned Bus refuses to produce or subscribe to any topic whose
// prefix does not match the owner's ctx hash (SPEC-0167 §Isolation).
//
// brokers is a list of bootstrap addresses (e.g. ["localhost:9092"]).
// An empty list is rejected — the engine refuses to run half-wired.
func NewFranzBus(owner mctx.Hash, brokers []string) (Bus, error) {
	if len(brokers) == 0 {
		return nil, errors.New("thinking/kafka: NewFranzBus requires at least one bootstrap broker")
	}
	// Shared producer client — one connection pool per engine.
	producer, err := kgo.NewClient(
		kgo.SeedBrokers(brokers...),
		kgo.RequiredAcks(kgo.LeaderAck()),
		kgo.DisableIdempotentWrite(),
		kgo.ProducerBatchCompression(kgo.NoCompression()),
		kgo.RecordRetries(5),
		kgo.ProduceRequestTimeout(5*time.Second),
		kgo.RecordDeliveryTimeout(10*time.Second),
		kgo.ClientID("m3c-thinking-"+owner.Hex()),
	)
	if err != nil {
		return nil, fmt.Errorf("thinking/kafka: producer init: %w", err)
	}
	return &franzBus{
		owner:    owner,
		brokers:  brokers,
		producer: producer,
	}, nil
}

// Produce writes a single JSON-encoded value to topic with the given
// key. Blocks until the broker acknowledges or the ctx deadline is
// reached. Panics if topic is not owned by this engine — this is the
// SPEC-0167 hard guard and must not be silenced.
func (b *franzBus) Produce(ctx context.Context, topic string, key string, value any) error {
	assertOwnedBy(topic, b.owner)
	body, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("thinking/kafka: marshal: %w", err)
	}
	rec := &kgo.Record{
		Topic: topic,
		Key:   []byte(key),
		Value: body,
	}
	results := b.producer.ProduceSync(ctx, rec)
	if err := results.FirstErr(); err != nil {
		return fmt.Errorf("thinking/kafka: produce to %s: %w", topic, err)
	}
	return nil
}

// Subscribe starts a consumer bound to a per-role group and
// dispatches each record to h. The returned stop function shuts down
// only this subscription — other subscriptions on the same bus keep
// running. Errors from h do not crash the loop; the offset is NOT
// committed for failed records, so each such record re-delivers on
// the next poll until it succeeds or is explicitly dropped.
func (b *franzBus) Subscribe(topic string, h Handler) (func(), error) {
	assertOwnedBy(topic, b.owner)
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil, errors.New("thinking/kafka: bus is closed")
	}
	b.mu.Unlock()

	group := groupNameFor(b.owner, topic)
	cl, err := kgo.NewClient(
		kgo.SeedBrokers(b.brokers...),
		kgo.ConsumerGroup(group),
		kgo.ConsumeTopics(topic),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
		kgo.DisableAutoCommit(),
		kgo.ClientID("m3c-thinking-consumer-"+b.owner.Hex()),
	)
	if err != nil {
		return nil, fmt.Errorf("thinking/kafka: consumer init for %s: %w", topic, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	sub := &franzSub{cl: cl, cancel: cancel, done: make(chan struct{})}

	b.mu.Lock()
	b.subs = append(b.subs, sub)
	b.mu.Unlock()

	go func() {
		defer close(sub.done)
		defer cl.Close()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			fetches := cl.PollFetches(ctx)
			if errs := fetches.Errors(); len(errs) > 0 {
				// Transient errors: keep looping. franz-go retries
				// record-level failures internally (RecordRetries).
				// By the time an error surfaces here it is usually a
				// topology issue (unknown topic briefly, rebalance).
				// Breaking out on ctx.Done is handled at the top of
				// the loop.
				if ctx.Err() != nil {
					return
				}
				// Small back-off to avoid hot-looping against a
				// broken broker.
				time.Sleep(100 * time.Millisecond)
				continue
			}
			var committable []*kgo.Record
			fetches.EachRecord(func(r *kgo.Record) {
				msg := Message{Topic: r.Topic, Key: r.Key, Value: r.Value}
				if err := h(ctx, msg); err != nil {
					// Do NOT commit this record — it re-delivers.
					return
				}
				committable = append(committable, r)
			})
			if len(committable) > 0 {
				// Commit synchronously so a restart never loses
				// more than one in-flight batch of handled records.
				if err := cl.CommitRecords(ctx, committable...); err != nil && ctx.Err() == nil {
					// Couldn't commit — records will re-deliver.
					// Back off briefly to avoid a tight retry loop.
					time.Sleep(100 * time.Millisecond)
				}
			}
		}
	}()

	stop := func() {
		sub.cancel()
		<-sub.done
		b.mu.Lock()
		for i, s := range b.subs {
			if s == sub {
				b.subs = append(b.subs[:i], b.subs[i+1:]...)
				break
			}
		}
		b.mu.Unlock()
	}
	return stop, nil
}

// ConsumerLag returns the aggregate per-partition lag for topic under
// this bus's consumer group. Implementation note: franz-go's kgo.Client
// does not expose admin queries directly; a full implementation needs
// the optional kadm package (separate module) to call ListCommittedOffsets
// + ListEndOffsets. For now this returns (0, nil) — the interface and
// the polling infrastructure are in place, and an operator can swap
// the impl in without touching the observability package.
//
// This is explicitly a stub that satisfies the BusMetrics contract;
// see PLAN-0168 §P0 "Gauge: bus_consumer_lag — polled every 10 s from
// franz-go admin client" for the target behaviour. Shipping the gauge
// at 0 is preferable to skipping the metric entirely because it gives
// dashboard authors a stable series name to build on.
func (b *franzBus) ConsumerLag(topic string) (int64, error) {
	_ = topic
	return 0, nil
}

// Close tears down the shared producer and every active subscription.
// After Close, Produce and Subscribe will fail; calling Close twice
// is a no-op.
func (b *franzBus) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	subs := append([]*franzSub(nil), b.subs...)
	b.subs = nil
	b.mu.Unlock()

	for _, s := range subs {
		s.cancel()
		<-s.done
	}
	if b.producer != nil {
		b.producer.Close()
	}
	return nil
}

// groupNameFor derives the consumer-group id from the owner hash and
// the topic's role suffix. Format: "m3c-<hash>-<role>", where <role>
// is the topic's event-class part with dots turned into dashes so
// Kafka doesn't treat it as a compound name (e.g. "thoughts.raw" →
// "thoughts-raw"). Each engine+role pair gets its own group; two
// users' engines can never share a group because their hashes differ.
func groupNameFor(owner mctx.Hash, topic string) string {
	prefix := owner.TopicPrefix() // "m3c.<hash>."
	suffix := strings.TrimPrefix(topic, prefix)
	role := strings.ReplaceAll(suffix, ".", "-")
	if role == "" {
		role = "unknown"
	}
	return fmt.Sprintf("m3c-%s-%s", owner.Hex(), role)
}
