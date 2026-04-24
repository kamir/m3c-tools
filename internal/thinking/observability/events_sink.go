// events_sink.go — the process.events → stdout + metrics projector.
//
// This file registers a Bus subscription on m3c.<ctx>.process.events
// and filters for the subset of events operators care about
// (anything failing, paused, skipped, or auto-reflect lifecycle).
// Matching events become:
//
//   1. a severity-tagged structured JSON line on stdout (so
//      docker/journalctl/Cloud Run logging can route them), and
//   2. an increment on the corresponding Prometheus counter.
//
// The sink is strictly read-only with respect to the cognitive
// pipeline — it never produces to any topic, never mutates store
// state. If it crashes the pipeline continues running; the worst
// case is lost visibility for the duration of the outage.
package observability

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
	tkafka "github.com/kamir/m3c-tools/internal/thinking/kafka"
	"github.com/kamir/m3c-tools/internal/thinking/schema"
)

// Severity levels carried on the JSON line. Kept as a small set so
// downstream log routers can key off a single `severity` field.
const (
	SeverityError = "error"
	SeverityWarn  = "warn"
	SeverityInfo  = "info"
)

// SinkConfig wires a new EventsSink.
type SinkConfig struct {
	// Hash is the engine's ctx hash (used to derive the topic name).
	Hash mctx.Hash
	// Bus is the event source (in-memory or franz-backed).
	Bus tkafka.Bus
	// Logger is the structured-JSON destination. Nil → stdout via
	// the default logger.
	Logger *log.Logger
	// Metrics is the optional counter surface. Nil → counters not
	// updated (logs still flow).
	Metrics Metrics

	// Out, if set, overrides the JSON-line destination. Used by tests
	// to capture lines without relying on Logger formatting. When nil,
	// lines are written via Logger.
	Out io.Writer

	// Now is overridable for tests. Production uses time.Now().UTC().
	Now func() time.Time
}

// EventsSink is the running consumer.
type EventsSink struct {
	cfg SinkConfig

	mu      sync.Mutex
	stop    func()
	stopped bool
}

// NewEventsSink constructs a sink without subscribing. Call Start to
// attach the subscription.
func NewEventsSink(cfg SinkConfig) (*EventsSink, error) {
	if cfg.Bus == nil {
		return nil, fmt.Errorf("observability: events sink bus required")
	}
	if cfg.Logger == nil {
		cfg.Logger = log.New(os.Stdout, "", log.LstdFlags|log.Lmsgprefix)
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	return &EventsSink{cfg: cfg}, nil
}

// Start subscribes to the engine's process.events topic. Safe to
// call once; subsequent calls are no-ops.
func (s *EventsSink) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stop != nil {
		return nil
	}
	topic := tkafka.TopicName(s.cfg.Hash, tkafka.TopicProcessEvents)
	stop, err := s.cfg.Bus.Subscribe(topic, func(hctx context.Context, m tkafka.Message) error {
		s.handle(m)
		return nil
	})
	if err != nil {
		return fmt.Errorf("observability: subscribe %s: %w", topic, err)
	}
	s.stop = stop
	return nil
}

// Stop unsubscribes. Safe to call multiple times.
func (s *EventsSink) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return
	}
	s.stopped = true
	if s.stop != nil {
		s.stop()
	}
}

// handle decodes one event and drives both sinks (log + metrics).
// Any error in decoding is logged once and swallowed — the sink MUST
// NOT crash the engine on a malformed event.
func (s *EventsSink) handle(m tkafka.Message) {
	var ev schema.ProcessEvent
	if err := json.Unmarshal(m.Value, &ev); err != nil {
		// Keep the line structured so log aggregators can still parse
		// the surrounding context.
		s.emitLine(map[string]interface{}{
			"ts":         s.cfg.Now().Format(time.RFC3339Nano),
			"ctx_hash":   s.cfg.Hash.Hex(),
			"severity":   SeverityWarn,
			"event_type": "ObservabilityDecodeError",
			"detail":     map[string]interface{}{"error": err.Error()},
		})
		return
	}

	if !s.matches(string(ev.Event)) {
		return
	}

	severity := severityFor(string(ev.Event))
	line := map[string]interface{}{
		"ts":         ev.Timestamp.Format(time.RFC3339Nano),
		"ctx_hash":   s.cfg.Hash.Hex(),
		"severity":   severity,
		"event_type": string(ev.Event),
		"process_id": ev.ProcessID,
	}
	if ev.Timestamp.IsZero() {
		line["ts"] = s.cfg.Now().Format(time.RFC3339Nano)
	}
	if len(ev.Detail) > 0 {
		line["detail"] = ev.Detail
	}
	s.emitLine(line)

	s.incrementCounters(ev)
}

// matches returns true when the event type is in the operational set:
// anything ending in Failed, Skipped, Paused, or prefixed AutoReflect.
func (s *EventsSink) matches(name string) bool {
	if strings.HasPrefix(name, "AutoReflect") {
		return true
	}
	if strings.HasSuffix(name, "Failed") {
		return true
	}
	if strings.HasSuffix(name, "Skipped") {
		return true
	}
	if strings.HasSuffix(name, "Paused") {
		return true
	}
	// Explicit opt-in for the schema-validation path which doesn't
	// suffix with Failed but is still an operational error.
	if name == "SchemaValidationError" {
		return true
	}
	return false
}

// severityFor maps an event name to its JSON-line severity field.
func severityFor(name string) string {
	switch name {
	case "StepFailed",
		"ProcessFailed",
		"ArtifactPersistenceFailed",
		"SchemaValidationError":
		return SeverityError
	case "AutoReflectBudgetPaused":
		return SeverityWarn
	case "AutoReflectSkipped":
		return SeverityInfo
	}
	// Default: anything else matching the filter (e.g.
	// AutoReflectTriggered) surfaces as info so operators still see
	// the lifecycle but it doesn't colour as an alert.
	return SeverityInfo
}

// incrementCounters bumps the matching Prometheus counter for this
// event. Called after emitLine so a counter update never blocks the
// log line. The Metrics implementation is nil-safe.
func (s *EventsSink) incrementCounters(ev schema.ProcessEvent) {
	if s.cfg.Metrics == nil {
		return
	}
	switch string(ev.Event) {
	case "StepFailed":
		layer := ""
		if ev.StepLayer != nil {
			layer = string(*ev.StepLayer)
		}
		strategy, _ := detailStr(ev.Detail, "strategy")
		reason, _ := detailStr(ev.Detail, "reason")
		s.cfg.Metrics.RecordStepFailure(layer, strategy, reason)
	case "ProcessFailed":
		mode, _ := detailStr(ev.Detail, "mode")
		s.cfg.Metrics.RecordProcessFailure(mode)
	case "AutoReflectTriggered":
		reason, _ := detailStr(ev.Detail, "reason")
		s.cfg.Metrics.RecordAutoReflectFire(reason)
	case "AutoReflectSkipped":
		// autoreflect.go encodes the skip cause in detail.reason
		// ("rate_limit" | "dedup" | "budget" | "no_eligible_ts").
		reason, _ := detailStr(ev.Detail, "reason")
		s.cfg.Metrics.RecordAutoReflectSkip(reason)
	case "AutoReflectBudgetPaused":
		s.cfg.Metrics.RecordBudgetPause()
	case "ArtifactPersistenceFailed":
		s.cfg.Metrics.RecordER1SinkFailure()
	}
}

// emitLine serialises the map as a single JSON line. When cfg.Out is
// set (tests), writes directly there; otherwise routes through Logger.
func (s *EventsSink) emitLine(line map[string]interface{}) {
	body, err := json.Marshal(line)
	if err != nil {
		// Should never happen for map[string]interface{} with simple
		// primitives; fall back to a best-effort string.
		body = []byte(fmt.Sprintf(`{"ts":%q,"ctx_hash":%q,"severity":"warn","event_type":"ObservabilityMarshalError"}`,
			s.cfg.Now().Format(time.RFC3339Nano), s.cfg.Hash.Hex()))
	}
	if s.cfg.Out != nil {
		_, _ = s.cfg.Out.Write(append(body, '\n'))
		return
	}
	s.cfg.Logger.Printf("%s", body)
}

// detailStr returns the string value at detail[key] and whether it was
// present as a non-empty string.
func detailStr(detail map[string]interface{}, key string) (string, bool) {
	if detail == nil {
		return "", false
	}
	v, ok := detail[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", false
	}
	return s, true
}
