// bus_franz_test.go — unit tests for the franz-go Bus driver that
// can run without a broker.
//
// A broker-required integration test lives in
// e2e/thinking/engine_flow_tagged_test.go and is skipped unless
// M3C_KAFKA_URL is set.
//
//go:build thinking_kafka

package kafka

import (
	"context"
	"strings"
	"testing"

	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
)

// TestGroupNameFor locks in the SPEC-0167 consumer-group naming
// convention "m3c-<hash>-<role>" and the dot-to-dash rewrite.
func TestGroupNameFor(t *testing.T) {
	raw, err := mctx.NewRaw("user-A")
	if err != nil {
		t.Fatal(err)
	}
	h := raw.Hash()
	topic := TopicName(h, TopicThoughtsRaw) // m3c.<hash>.thoughts.raw
	got := groupNameFor(h, topic)
	want := "m3c-" + h.Hex() + "-thoughts-raw"
	if got != want {
		t.Errorf("groupNameFor = %q, want %q", got, want)
	}
}

// TestGroupNameForAllTopicsAreUnique confirms every one of the 8
// canonical topics yields a distinct group name under the same owner.
func TestGroupNameForAllTopicsAreUnique(t *testing.T) {
	raw, _ := mctx.NewRaw("user-A")
	h := raw.Hash()
	seen := map[string]TopicSuffix{}
	for _, s := range AllTopics() {
		topic := TopicName(h, s)
		name := groupNameFor(h, topic)
		if !strings.HasPrefix(name, "m3c-"+h.Hex()+"-") {
			t.Errorf("group %q missing owner prefix", name)
		}
		if existing, dup := seen[name]; dup {
			t.Errorf("group name collision: %q shared by %q and %q", name, existing, s)
		}
		seen[name] = s
	}
}

// TestGroupNameForDifferentOwnersDiffer guarantees two users'
// engines never share a group name, even for the same topic suffix.
func TestGroupNameForDifferentOwnersDiffer(t *testing.T) {
	rA, _ := mctx.NewRaw("user-A")
	rB, _ := mctx.NewRaw("user-B")
	tA := TopicName(rA.Hash(), TopicReflectionsGenerated)
	// Synthetic: if user B somehow received user A's topic name and
	// the guard were bypassed, the group name rooted in B's hash
	// still differs from A's — belt and suspenders.
	nameA := groupNameFor(rA.Hash(), tA)
	nameB := groupNameFor(rB.Hash(), tA) // different owner, same topic
	if nameA == nameB {
		t.Errorf("groupNameFor did not segregate by owner: %q == %q", nameA, nameB)
	}
}

// TestNewFranzBusRejectsEmptyBrokers locks in the "refuse to half-
// wire" invariant — no brokers, no bus.
func TestNewFranzBusRejectsEmptyBrokers(t *testing.T) {
	raw, _ := mctx.NewRaw("user-A")
	b, err := NewFranzBus(raw.Hash(), nil)
	if err == nil {
		_ = b.Close()
		t.Fatal("expected error for empty brokers, got nil")
	}
}

// TestFranzBusProducePanicsOnForeignTopic confirms the SPEC-0167
// §Isolation Model guard fires on the franz driver exactly like the
// in-memory one. Uses a bogus broker address — the guard runs before
// any network I/O, so no broker is required for this test.
func TestFranzBusProducePanicsOnForeignTopic(t *testing.T) {
	ownRaw, _ := mctx.NewRaw("user-A")
	foreignRaw, _ := mctx.NewRaw("user-B")
	b, err := NewFranzBus(ownRaw.Hash(), []string{"127.0.0.1:1"})
	if err != nil {
		t.Fatalf("NewFranzBus: %v", err)
	}
	defer b.Close()

	foreignTopic := TopicName(foreignRaw.Hash(), TopicThoughtsRaw)
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic on foreign topic, got none")
		}
	}()
	_ = b.Produce(context.Background(), foreignTopic, "k", map[string]string{"x": "y"})
}

// TestFranzBusSubscribePanicsOnForeignTopic — same as above, for
// the consumer side.
func TestFranzBusSubscribePanicsOnForeignTopic(t *testing.T) {
	ownRaw, _ := mctx.NewRaw("user-A")
	foreignRaw, _ := mctx.NewRaw("user-B")
	b, err := NewFranzBus(ownRaw.Hash(), []string{"127.0.0.1:1"})
	if err != nil {
		t.Fatalf("NewFranzBus: %v", err)
	}
	defer b.Close()

	foreignTopic := TopicName(foreignRaw.Hash(), TopicThoughtsRaw)
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic on foreign subscribe, got none")
		}
	}()
	_, _ = b.Subscribe(foreignTopic, func(ctx context.Context, m Message) error { return nil })
}

// TestFranzBusClose confirms the bus can be closed without a
// subscription or produce call (no network contact).
func TestFranzBusClose(t *testing.T) {
	raw, _ := mctx.NewRaw("user-A")
	b, err := NewFranzBus(raw.Hash(), []string{"127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	// Idempotent close.
	if err := b.Close(); err != nil {
		t.Errorf("Close (second call): %v", err)
	}
}
