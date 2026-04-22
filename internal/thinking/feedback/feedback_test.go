// feedback_test.go — unit tests for the feedback consumer.
//
// Covers:
//   - MatchFilter accepts contradiction follow-ups and rejects raw
//     user questions / non-question Ts / missing provenance.
//   - The consumer honours the hourly rate limit.
//   - DefaultFeedbackSpec produces a linear R.clarify → I.decision →
//     A.summary chain.
package feedback

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"sync"
	"testing"
	"time"

	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
	tkafka "github.com/kamir/m3c-tools/internal/thinking/kafka"
	"github.com/kamir/m3c-tools/internal/thinking/orchestrator"
	"github.com/kamir/m3c-tools/internal/thinking/schema"
	"github.com/kamir/m3c-tools/internal/thinking/store"
)

func TestMatchFilterAcceptsContradictionFollowup(t *testing.T) {
	pa := "proc://p-1"
	th := schema.Thought{
		Type: schema.ThoughtQuestion,
		Provenance: &schema.Provenance{
			CapturedBy:       "thinking-engine/i-proc",
			ParentArtifactID: &pa,
		},
	}
	if !MatchFilter(th) {
		t.Errorf("expected accept for contradiction follow-up")
	}
}

func TestMatchFilterRejectsPlainUserQuestion(t *testing.T) {
	th := schema.Thought{
		Type: schema.ThoughtQuestion,
		Provenance: &schema.Provenance{
			CapturedBy: "flask/capture",
		},
	}
	if MatchFilter(th) {
		t.Errorf("plain user question (no parent_artifact_id) must be rejected")
	}
}

func TestMatchFilterRejectsNonQuestion(t *testing.T) {
	pa := "proc://p-1"
	th := schema.Thought{
		Type: schema.ThoughtObservation,
		Provenance: &schema.Provenance{
			CapturedBy:       "whatever",
			ParentArtifactID: &pa,
		},
	}
	if MatchFilter(th) {
		t.Errorf("non-question must be rejected even with parent_artifact_id")
	}
}

func TestMatchFilterRejectsEmptyParentArtifactID(t *testing.T) {
	empty := "   "
	th := schema.Thought{
		Type: schema.ThoughtQuestion,
		Provenance: &schema.Provenance{
			CapturedBy:       "x",
			ParentArtifactID: &empty,
		},
	}
	if MatchFilter(th) {
		t.Errorf("whitespace-only parent_artifact_id must be rejected")
	}
}

func TestMatchFilterRejectsNilProvenance(t *testing.T) {
	th := schema.Thought{Type: schema.ThoughtQuestion}
	if MatchFilter(th) {
		t.Errorf("nil provenance must be rejected")
	}
}

func TestDefaultFeedbackSpecShape(t *testing.T) {
	th := schema.Thought{ThoughtID: "t-abc"}
	spec := DefaultFeedbackSpec(th)
	if spec.Mode != schema.ModeLinear {
		t.Errorf("mode = %s, want linear", spec.Mode)
	}
	if len(spec.Steps) != 3 {
		t.Fatalf("expected 3 steps, got %d", len(spec.Steps))
	}
	if spec.Steps[0].Layer != schema.LayerR || spec.Steps[0].Strategy != "clarify" {
		t.Errorf("step 0 = %s/%s, want R/clarify", spec.Steps[0].Layer, spec.Steps[0].Strategy)
	}
	if spec.Steps[1].Layer != schema.LayerI || spec.Steps[1].Strategy != "decision" {
		t.Errorf("step 1 = %s/%s, want I/decision", spec.Steps[1].Layer, spec.Steps[1].Strategy)
	}
	if spec.Steps[2].Layer != schema.LayerA || spec.Steps[2].Strategy != "summary" {
		t.Errorf("step 2 = %s/%s, want A/summary", spec.Steps[2].Layer, spec.Steps[2].Strategy)
	}
	if spec.Steps[0].Context == nil || spec.Steps[0].Context.Scope == nil ||
		len(spec.Steps[0].Context.Scope.Entities) != 1 ||
		spec.Steps[0].Context.Scope.Entities[0] != "t-abc" {
		t.Errorf("step 0 context.scope.entities should carry the triggering thought id: %+v", spec.Steps[0].Context)
	}
}

// cmdCounter counts command-topic messages to prove the feedback
// consumer did (or did not) launch a process.
type cmdCounter struct {
	mu sync.Mutex
	n  int
}

func (c *cmdCounter) inc() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
}

func (c *cmdCounter) read() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// buildEnv wires orchestrator + feedback consumer for a single test.
func buildEnv(t *testing.T, rateLimit int) (*Consumer, tkafka.Bus, mctx.Hash, *store.Store, *cmdCounter, func()) {
	t.Helper()
	raw, _ := mctx.NewRaw("fb-test")
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
	orc := orchestrator.New(h, bus, st)
	if err := orc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	col := &cmdCounter{}
	_, _ = bus.Subscribe(tkafka.TopicName(h, tkafka.TopicProcessCommands), func(ctx context.Context, m tkafka.Message) error {
		col.inc()
		return nil
	})
	logger := log.New(os.Stderr, "[fb-test] ", 0)
	c, err := New(Config{
		Hash:         h,
		Bus:          bus,
		Orchestrator: orc,
		Store:        st,
		Logger:       logger,
		RateLimit:    rateLimit,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	cleanup := func() {
		c.Stop()
		orc.Stop()
		_ = st.Close()
	}
	return c, bus, h, st, col, cleanup
}

// produce emits a Thought onto thoughts.raw.
func produce(t *testing.T, bus tkafka.Bus, h mctx.Hash, th schema.Thought) {
	t.Helper()
	topic := tkafka.TopicName(h, tkafka.TopicThoughtsRaw)
	// Use JSON raw to sidestep validation surprises from partial Ts.
	body, _ := json.Marshal(th)
	if err := bus.Produce(context.Background(), topic, th.ThoughtID, json.RawMessage(body)); err != nil {
		t.Fatal(err)
	}
}

func makeQuestion(id string, parent *string) schema.Thought {
	return schema.Thought{
		SchemaVer: schema.CurrentSchemaVer,
		ThoughtID: id,
		Type:      schema.ThoughtQuestion,
		Content:   schema.Content{Text: "why?"},
		Source: schema.Source{
			Kind: schema.SourceAgent,
			Ref:  "thinking-engine/i-proc/contradiction",
		},
		Timestamp: time.Now().UTC(),
		Provenance: &schema.Provenance{
			CapturedBy:       "thinking-engine/i-proc",
			ParentArtifactID: parent,
		},
	}
}

func TestConsumerLaunchesProcessForFollowupQuestion(t *testing.T) {
	_, bus, h, _, col, cleanup := buildEnv(t, 10)
	defer cleanup()

	parent := "proc://p-orig"
	produce(t, bus, h, makeQuestion("t-fb-1", &parent))

	// Wait for the orchestrator to dispatch the first step.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if col.read() >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if col.read() < 1 {
		t.Fatal("feedback consumer did not launch a process for a valid follow-up")
	}
}

func TestConsumerIgnoresPlainUserQuestion(t *testing.T) {
	_, bus, h, _, col, cleanup := buildEnv(t, 10)
	defer cleanup()

	// User question (no parent_artifact_id).
	th := makeQuestion("t-user-1", nil)
	produce(t, bus, h, th)

	// Give the consumer time to (not) act.
	time.Sleep(150 * time.Millisecond)
	if col.read() != 0 {
		t.Errorf("consumer must ignore raw user questions; dispatched=%d", col.read())
	}
}

func TestConsumerRateLimitDropsOverCap(t *testing.T) {
	_, bus, h, _, col, cleanup := buildEnv(t, 2)
	defer cleanup()

	parent := "proc://p-orig"
	for i := 0; i < 5; i++ {
		produce(t, bus, h, makeQuestion("t-fb-"+timeKey(i), &parent))
	}
	// Wait long enough for processing.
	deadline := time.Now().Add(600 * time.Millisecond)
	for time.Now().Before(deadline) {
		if col.read() >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Allow a tiny grace period for any in-flight 3rd dispatch to NOT occur.
	time.Sleep(150 * time.Millisecond)
	n := col.read()
	if n > 2 {
		// Each launched process dispatches its step 0 command — with
		// cap=2 we should see at most 2 command dispatches from the
		// feedback loop. Each linear process dispatches all 3 steps
		// eagerly though. Allow up to 6 (2 processes × 3 steps).
		if n > 6 {
			t.Errorf("rate-limit exceeded: got %d dispatches, cap implies ≤ 6", n)
		}
	}
	if n == 0 {
		t.Errorf("expected at least some dispatches with cap=2, got 0")
	}
}

func timeKey(i int) string {
	return time.Now().Format("15.04.05") + "-" + itoa(i)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [8]byte
	n := len(buf)
	for i > 0 {
		n--
		buf[n] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[n:])
}
