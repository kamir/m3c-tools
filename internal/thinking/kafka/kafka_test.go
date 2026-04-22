package kafka

import (
	"context"
	"sync"
	"testing"

	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
)

func mkHash(t *testing.T, raw string) mctx.Hash {
	t.Helper()
	r, err := mctx.NewRaw(raw)
	if err != nil {
		t.Fatal(err)
	}
	return r.Hash()
}

func TestTopicNameFormat(t *testing.T) {
	h := mkHash(t, "user-A")
	got := TopicName(h, TopicThoughtsRaw)
	want := h.TopicPrefix() + "thoughts.raw"
	if got != want {
		t.Errorf("TopicName = %q, want %q", got, want)
	}
}

func TestProduceOnOwnedTopic(t *testing.T) {
	h := mkHash(t, "user-A")
	b := NewMemBus(h)
	topic := TopicName(h, TopicProcessEvents)
	if err := b.Produce(context.Background(), topic, "k", map[string]string{"x": "y"}); err != nil {
		t.Fatal(err)
	}
}

func TestProducePanicsOnForeignTopic(t *testing.T) {
	own := mkHash(t, "user-A")
	foreign := mkHash(t, "user-B")
	b := NewMemBus(own)
	foreignTopic := TopicName(foreign, TopicThoughtsRaw)

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic on foreign topic, got none")
		}
	}()
	_ = b.Produce(context.Background(), foreignTopic, "k", map[string]string{"x": "y"})
}

func TestSubscribePanicsOnForeignTopic(t *testing.T) {
	own := mkHash(t, "user-A")
	foreign := mkHash(t, "user-B")
	b := NewMemBus(own)
	foreignTopic := TopicName(foreign, TopicThoughtsRaw)

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic on foreign subscribe")
		}
	}()
	_, _ = b.Subscribe(foreignTopic, func(ctx context.Context, m Message) error { return nil })
}

func TestInMemoryDispatch(t *testing.T) {
	h := mkHash(t, "user-A")
	b := NewMemBus(h)
	topic := TopicName(h, TopicProcessCommands)

	var wg sync.WaitGroup
	wg.Add(1)
	got := make(chan Message, 1)
	_, err := b.Subscribe(topic, func(ctx context.Context, m Message) error {
		defer wg.Done()
		got <- m
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Produce(context.Background(), topic, "k", map[string]int{"n": 1}); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	m := <-got
	if m.Topic != topic {
		t.Errorf("topic mismatch: %s", m.Topic)
	}
}

func TestAllTopicsCount(t *testing.T) {
	if n := len(AllTopics()); n != 8 {
		t.Errorf("AllTopics() = %d, want 8 per SPEC-0167 Kafka Topology", n)
	}
}
