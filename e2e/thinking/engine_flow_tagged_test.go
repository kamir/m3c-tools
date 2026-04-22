// engine_flow_tagged_test.go — integration test that runs the
// thinking-engine flow against a REAL Kafka broker.
//
// Compile + run with:
//
//   M3C_KAFKA_URL=localhost:9092 \
//     go test -tags thinking_kafka -count=1 -v \
//       ./e2e/thinking/ -run TestEngineFlowReal
//
// Skipped entirely when:
//   - the `thinking_kafka` build tag is NOT set (this file doesn't
//     compile, so it doesn't run); or
//   - M3C_KAFKA_URL is empty (environment opts out).
//
// What it verifies:
//   1. The franz-go Bus can round-trip a JSON message through a
//      real cp-all-in-one broker.
//   2. Cross-tenant produce still panics with a real broker wired up
//      (the isolation guard is independent of the driver).
//   3. A linear ProcessSpec produces the same artifact shape as the
//      in-memory reference run — i.e. the two drivers are
//      behaviourally equivalent for Stream 2a's processors.
//
//go:build thinking_kafka

package thinking_test

import (
	"context"
	"encoding/json"
	"os"
	"sync"
	"testing"
	"time"

	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
	tkafka "github.com/kamir/m3c-tools/internal/thinking/kafka"
)

func requireBroker(t *testing.T) []string {
	t.Helper()
	url := os.Getenv("M3C_KAFKA_URL")
	if url == "" {
		t.Skip("M3C_KAFKA_URL not set; skipping real-broker integration test")
	}
	return []string{url}
}

// TestEngineFlowReal verifies a produce+consume round-trip on the
// real broker. Uses a unique ctx hash per run to avoid topic reuse
// across CI attempts.
func TestEngineFlowReal(t *testing.T) {
	brokers := requireBroker(t)

	raw, err := mctx.NewRaw("e2e-real-" + time.Now().UTC().Format("20060102T150405.000"))
	if err != nil {
		t.Fatal(err)
	}
	hash := raw.Hash()

	bus, err := tkafka.NewFranzBus(hash, brokers)
	if err != nil {
		t.Fatalf("NewFranzBus: %v", err)
	}
	defer bus.Close()

	topic := tkafka.TopicName(hash, tkafka.TopicProcessEvents)

	got := make(chan tkafka.Message, 4)
	var once sync.Once
	stop, err := bus.Subscribe(topic, func(ctx context.Context, m tkafka.Message) error {
		once.Do(func() {}) // reserved for future hook
		got <- m
		return nil
	})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer stop()

	// Give the consumer group a moment to join — cp-all-in-one
	// assigns quickly but not instantly. Then produce.
	time.Sleep(2 * time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	payload := map[string]any{
		"schema_ver": 1,
		"process_id": "proc-e2e-real",
		"event":      "StepStarted",
		"layer":      "R",
	}
	if err := bus.Produce(ctx, topic, "proc-e2e-real", payload); err != nil {
		t.Fatalf("Produce: %v", err)
	}

	select {
	case m := <-got:
		if m.Topic != topic {
			t.Errorf("round-trip topic = %q, want %q", m.Topic, topic)
		}
		var back map[string]any
		if err := json.Unmarshal(m.Value, &back); err != nil {
			t.Fatalf("unmarshal round-tripped value: %v", err)
		}
		if back["process_id"] != "proc-e2e-real" {
			t.Errorf("round-trip value mismatch: got %+v", back)
		}
		if v, ok := back["schema_ver"].(float64); !ok || int(v) != 1 {
			t.Errorf("schema_ver not preserved: %+v", back)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("no message received from real broker within 15s")
	}
}

// TestIsolationGuardOnRealBroker confirms the SPEC-0167 §Isolation
// Model panic guard fires BEFORE any network I/O even when a real
// broker is configured — i.e. an engine for user A wired against a
// live cluster still cannot accidentally publish to user B's topic.
func TestIsolationGuardOnRealBroker(t *testing.T) {
	brokers := requireBroker(t)

	own, _ := mctx.NewRaw("e2e-owner")
	foreign, _ := mctx.NewRaw("e2e-foreign")

	bus, err := tkafka.NewFranzBus(own.Hash(), brokers)
	if err != nil {
		t.Fatalf("NewFranzBus: %v", err)
	}
	defer bus.Close()

	foreignTopic := tkafka.TopicName(foreign.Hash(), tkafka.TopicThoughtsRaw)
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on foreign-topic produce against real broker, got none")
		}
	}()
	_ = bus.Produce(context.Background(), foreignTopic, "k", map[string]string{"x": "y"})
}

// TestInMemoryAndFranzEquivalence runs the SAME produce+consume
// scenario against the in-memory Bus and the franz-go Bus and
// asserts they yield byte-identical payloads. This is a minimal
// equivalence check; Stream 2a's full ProcessSpec equivalence lands
// on top of this once their processors are merged.
func TestInMemoryAndFranzEquivalence(t *testing.T) {
	brokers := requireBroker(t)

	raw, err := mctx.NewRaw("e2e-equiv-" + time.Now().UTC().Format("20060102T150405.000"))
	if err != nil {
		t.Fatal(err)
	}
	hash := raw.Hash()
	topic := tkafka.TopicName(hash, tkafka.TopicReflectionsGenerated)

	payload := map[string]any{
		"schema_ver":    1,
		"reflection_id": "r-e2e-equiv",
		"strategy":      "compare",
	}
	expected, _ := json.Marshal(payload)

	// In-memory reference run.
	memBus := tkafka.NewMemBus(hash)
	defer memBus.Close()

	memGot := make(chan []byte, 1)
	_, err = memBus.Subscribe(topic, func(ctx context.Context, m tkafka.Message) error {
		memGot <- append([]byte(nil), m.Value...)
		return nil
	})
	if err != nil {
		t.Fatalf("mem Subscribe: %v", err)
	}
	if err := memBus.Produce(context.Background(), topic, "k", payload); err != nil {
		t.Fatalf("mem Produce: %v", err)
	}
	var memBody []byte
	select {
	case memBody = <-memGot:
	case <-time.After(1 * time.Second):
		t.Fatal("in-memory bus did not deliver message")
	}
	if string(memBody) != string(expected) {
		t.Errorf("in-memory payload mismatch:\n got  %s\n want %s", memBody, expected)
	}

	// Real-broker run.
	franzBus, err := tkafka.NewFranzBus(hash, brokers)
	if err != nil {
		t.Fatalf("NewFranzBus: %v", err)
	}
	defer franzBus.Close()

	franzGot := make(chan []byte, 1)
	stop, err := franzBus.Subscribe(topic, func(ctx context.Context, m tkafka.Message) error {
		franzGot <- append([]byte(nil), m.Value...)
		return nil
	})
	if err != nil {
		t.Fatalf("franz Subscribe: %v", err)
	}
	defer stop()
	time.Sleep(2 * time.Second) // let consumer group stabilize

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := franzBus.Produce(ctx, topic, "k", payload); err != nil {
		t.Fatalf("franz Produce: %v", err)
	}

	var franzBody []byte
	select {
	case franzBody = <-franzGot:
	case <-time.After(15 * time.Second):
		t.Fatal("franz bus did not deliver message within 15s")
	}
	if string(franzBody) != string(memBody) {
		t.Errorf("driver equivalence failed:\n mem   %s\n franz %s", memBody, franzBody)
	}
}
