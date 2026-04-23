// e2e_test.go — in-memory end-to-end test for the auto-reflect
// consumer wired to the real orchestrator.
//
// Flow under test (matches the brief acceptance check):
//
//  1. Publish 20 eligible Ts onto thoughts.raw.
//  2. Auto-reflect fires a ProcessSpec (semi_linear, 3 steps, origin
//     = auto_reflect) onto the orchestrator.
//  3. A stub "processor" subscribed to process.commands simulates the
//     R/I/A cycle by emitting StepStarted / StepCompleted for each
//     dispatched command, then ProcessCompleted after the final step.
//  4. The eventSink observes AutoReflectTriggered and, downstream,
//     ProcessCompleted whose process_id matches the one dispatched
//     by autoreflect.
//
// This verifies the full on-box loop without touching a real LLM or
// broker.
package autoreflect

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"testing"
	"time"

	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
	tkafka "github.com/kamir/m3c-tools/internal/thinking/kafka"
	"github.com/kamir/m3c-tools/internal/thinking/orchestrator"
	"github.com/kamir/m3c-tools/internal/thinking/schema"
	"github.com/kamir/m3c-tools/internal/thinking/store"
)

// stubProcessor subscribes to process.commands and, for every command,
// emits StepStarted + StepCompleted. When the final step completes,
// it also emits ProcessCompleted so the downstream assertions can
// verify the spec ran end-to-end.
type stubProcessor struct {
	orc    *orchestrator.Orchestrator
	logger *log.Logger
}

func (s *stubProcessor) start(ctx context.Context, bus tkafka.Bus, hash mctx.Hash) (func(), error) {
	topic := tkafka.TopicName(hash, tkafka.TopicProcessCommands)
	return bus.Subscribe(topic, func(hctx context.Context, m tkafka.Message) error {
		var cmd schema.ProcessCommand
		if err := json.Unmarshal(m.Value, &cmd); err != nil {
			return nil
		}
		// Process asynchronously so we don't hold up other commands.
		go func() {
			_ = s.orc.EmitStepStarted(ctx, cmd.ProcessID, cmd.StepIndex, cmd.Step.Layer)
			_ = s.orc.EmitStepCompleted(ctx, cmd.ProcessID, cmd.StepIndex, cmd.Step.Layer, nil)
			if cmd.StepIndex == len(cmd.Spec.Steps)-1 {
				// Mimic A-processor closeout.
				_ = s.orc.Complete(ctx, cmd.ProcessID, nil)
			}
		}()
		return nil
	})
}

func TestE2EAutoReflectDispatchesAndCompletes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e under -short")
	}

	raw, _ := mctx.NewRaw("auto-reflect-e2e")
	h := raw.Hash()
	inner := tkafka.NewMemBus(h)
	bus, err := tkafka.NewValidatingBus(inner, nil)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	logger := log.New(os.Stderr, "[e2e] ", 0)
	orc := orchestrator.New(h, bus, st)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := orc.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer orc.Stop()

	// Hook up the stub processor so dispatched commands get completed.
	stub := &stubProcessor{orc: orc, logger: logger}
	stopStub, err := stub.start(ctx, bus, h)
	if err != nil {
		t.Fatal(err)
	}
	defer stopStub()

	// Collect process.events so we can assert on the lifecycle.
	sink := &eventSink{}
	if _, err := bus.Subscribe(tkafka.TopicName(h, tkafka.TopicProcessEvents), sink.hook); err != nil {
		t.Fatal(err)
	}

	// The e2e ledger is always in-the-clear.
	ledger := &fakeLedger{remaining: 1.0}

	c, err := New(Config{
		Hash:             h,
		Bus:              bus,
		Orchestrator:     orc,
		Store:            st,
		Ledger:           ledger,
		Logger:           logger,
		WindowN:          20,
		HeartbeatMin:     60,
		RateLimitPerHour: 10,
		SkipPlaceholder:  true,
		Patterns:         []string{DefaultPlaceholderPattern},
		HardTokenCap:     DefaultHardTokenCap,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer c.Stop()

	// Publish 20 eligible Ts to hit the window trigger.
	for i := 0; i < 20; i++ {
		topic := tkafka.TopicName(h, tkafka.TopicThoughtsRaw)
		th := observation(uniqueID(i), "e2e observation")
		if err := bus.Produce(ctx, topic, th.ThoughtID, th); err != nil {
			t.Fatal(err)
		}
	}

	// 1. AutoReflectTriggered must land within a reasonable timeout.
	if !sink.waitFor(EventAutoReflectTriggered, 2*time.Second) {
		t.Fatalf("AutoReflectTriggered did not arrive in time; events=%+v", sink.events)
	}

	// 2. A ProcessCompleted tied to the auto-reflect process_id must
	//    eventually arrive downstream.
	triggered := sink.byName(EventAutoReflectTriggered)
	if len(triggered) == 0 {
		t.Fatal("no AutoReflectTriggered captured")
	}
	autoProcessID := triggered[0].ProcessID

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		completed := sink.byName(schema.EventProcessCompleted)
		for _, ev := range completed {
			if ev.ProcessID == autoProcessID {
				// Also ensure the spec carried the auto_reflect origin
				// by looking up the stored spec.
				row, err := st.GetProcess(autoProcessID)
				if err != nil {
					t.Fatalf("GetProcess: %v", err)
				}
				var spec schema.ProcessSpec
				if err := json.Unmarshal(row.SpecJSON, &spec); err != nil {
					t.Fatalf("unmarshal spec: %v", err)
				}
				if spec.CreatedBy != CreatedByAutoReflect {
					t.Fatalf("spec.CreatedBy = %q, want %q", spec.CreatedBy, CreatedByAutoReflect)
				}
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("ProcessCompleted for auto-reflect process %s did not arrive in time; events=%+v",
		autoProcessID, sink.events)
}

// uniqueID returns a deterministic but collision-free T id.
func uniqueID(i int) string {
	return "t-e2e-" + string(rune('a'+(i/10))) + string(rune('a'+(i%10)))
}
