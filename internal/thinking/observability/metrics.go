// Package observability implements the P0 operational surface for
// the Thinking Engine (SPEC-0167, PLAN-0168 §P0): a Prometheus pull
// registry for metrics and a process.events consumer that projects
// operational events to structured JSON stdout logs. Neither sink
// modifies cognitive-pipeline semantics; both are strict observers.
//
// Import-rule invariant: this package does not import any LLM SDK.
// Metrics and log lines record what happened — they never make the
// pipeline happen.
package observability

import (
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Config wires a new Metrics registry. CtxHash and EngineVersion are
// attached as static labels to every metric. BusMetrics is optional;
// when non-nil, a background goroutine polls ConsumerLag every 10s for
// each topic in Topics and updates the m3c_thinking_bus_consumer_lag
// gauge.
type Config struct {
	CtxHash       string
	EngineVersion string

	// BusMetrics is an optional consumer-lag source. The in-memory
	// bus returns 0 for every topic; franz-go's implementation queries
	// the admin client. nil disables the lag gauge entirely.
	BusMetrics BusMetrics

	// Topics to poll for consumer lag. Zero-valued → no polling.
	Topics []string

	// LagPollInterval controls how often BusMetrics.ConsumerLag is
	// called per topic. Zero → DefaultLagPollInterval.
	LagPollInterval time.Duration
}

// BusMetrics is the minimum contract Metrics needs from the Kafka
// driver to surface consumer lag. The in-memory driver returns
// (0, nil) for every call; franz-go's driver uses its admin client.
type BusMetrics interface {
	// ConsumerLag returns the aggregate lag across all partitions of
	// the given topic for the engine's consumer group, or an error if
	// the broker refuses the query.
	ConsumerLag(topic string) (int64, error)
}

// DefaultLagPollInterval is how often Bus.ConsumerLag is polled per
// topic when Config.LagPollInterval is zero.
const DefaultLagPollInterval = 10 * time.Second

// Metrics is the interface the rest of the engine uses to record
// operational events. A nil *Registry satisfies the interface via
// the no-op methods below, so call sites can stay unconditional:
//
//	deps.Metrics.RecordLLMCall(...)   // safe even if Metrics is nil
//
// but in practice the engine hands out either a *Registry or a
// NoopMetrics to avoid nil checks at every hook.
type Metrics interface {
	RecordLLMCall(model, layer, strategy string, tokensIn, tokensOut int, latency time.Duration)
	RecordStepFailure(layer, strategy, reason string)
	RecordProcessFailure(mode string)
	RecordAutoReflectFire(reason string)
	RecordAutoReflectSkip(reason string)
	RecordBudgetPause()
	RecordArtifactCreated(format string)
	RecordER1SinkFailure()
	RecordHMACRotation()
}

// Registry is the live Prometheus-backed Metrics implementation. It
// owns a dedicated *prometheus.Registry (not the global default) so
// tests and fleet-run engines can't accidentally share counter state.
type Registry struct {
	reg *prometheus.Registry

	stepFailures         *prometheus.CounterVec
	processFailures      *prometheus.CounterVec
	autoreflectFires     *prometheus.CounterVec
	autoreflectSkipped   *prometheus.CounterVec
	budgetPauses         prometheus.Counter
	llmTokens            *prometheus.CounterVec
	artifactsCreated     *prometheus.CounterVec
	er1SinkFailures      prometheus.Counter
	hmacRotations        prometheus.Counter
	llmLatencySeconds    *prometheus.HistogramVec
	busConsumerLag       *prometheus.GaugeVec

	stopMu sync.Mutex
	stop   chan struct{}
	done   chan struct{}

	cfg Config
}

// NewMetrics constructs a Registry with all documented counters +
// histogram + gauge registered. Static labels {ctx_hash,
// engine_version} are applied as constant labels on every metric via
// promauto-style manual registration.
func NewMetrics(cfg Config) *Registry {
	constLabels := prometheus.Labels{
		"ctx_hash":       cfg.CtxHash,
		"engine_version": cfg.EngineVersion,
	}
	reg := prometheus.NewRegistry()

	m := &Registry{
		reg: reg,
		cfg: cfg,
	}

	m.stepFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        "m3c_thinking_step_failures_total",
		Help:        "Count of StepFailed events emitted by the engine, labelled by layer/strategy and failure reason.",
		ConstLabels: constLabels,
	}, []string{"layer", "strategy", "reason"})

	m.processFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        "m3c_thinking_process_failures_total",
		Help:        "Count of ProcessFailed events emitted by the engine, labelled by process mode.",
		ConstLabels: constLabels,
	}, []string{"mode"})

	m.autoreflectFires = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        "m3c_thinking_autoreflect_fires_total",
		Help:        "Count of auto-reflect dispatches, labelled by trigger reason (window|heartbeat).",
		ConstLabels: constLabels,
	}, []string{"reason"})

	m.autoreflectSkipped = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        "m3c_thinking_autoreflect_skipped_total",
		Help:        "Count of auto-reflect skips, labelled by reason (rate_limit|dedup|budget|no_eligible_ts).",
		ConstLabels: constLabels,
	}, []string{"reason"})

	m.budgetPauses = prometheus.NewCounter(prometheus.CounterOpts{
		Name:        "m3c_thinking_budget_pauses_total",
		Help:        "Count of times the D4 budget crossed the auto-reflect pause threshold.",
		ConstLabels: constLabels,
	})

	m.llmTokens = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        "m3c_thinking_llm_tokens_total",
		Help:        "LLM tokens consumed, labelled by model and direction (in|out).",
		ConstLabels: constLabels,
	}, []string{"model", "direction"})

	m.artifactsCreated = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        "m3c_thinking_artifacts_created_total",
		Help:        "Count of artifacts successfully projected to ER1, labelled by format.",
		ConstLabels: constLabels,
	}, []string{"format"})

	m.er1SinkFailures = prometheus.NewCounter(prometheus.CounterOpts{
		Name:        "m3c_thinking_er1_sink_failures_total",
		Help:        "Count of ER1 artifact-projection failures after all retries.",
		ConstLabels: constLabels,
	})

	// hmacRotations is reserved for P2 (HMAC key rotation without
	// restart). We declare it now at 0 so operator dashboards can
	// chart it from day one; the counter stays flat until the
	// rotation feature lands.
	m.hmacRotations = prometheus.NewCounter(prometheus.CounterOpts{
		Name:        "m3c_thinking_hmac_rotations_total",
		Help:        "Count of HMAC secret rotations (reserved for P2).",
		ConstLabels: constLabels,
	})

	m.llmLatencySeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:        "m3c_thinking_llm_latency_seconds",
		Help:        "LLM call latency in seconds, labelled by model and layer.",
		ConstLabels: constLabels,
		Buckets:     []float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30},
	}, []string{"model", "layer"})

	m.busConsumerLag = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name:        "m3c_thinking_bus_consumer_lag",
		Help:        "Aggregate consumer-group lag for the engine's own topics, polled from the Kafka admin client.",
		ConstLabels: constLabels,
	}, []string{"topic"})

	reg.MustRegister(
		m.stepFailures,
		m.processFailures,
		m.autoreflectFires,
		m.autoreflectSkipped,
		m.budgetPauses,
		m.llmTokens,
		m.artifactsCreated,
		m.er1SinkFailures,
		m.hmacRotations,
		m.llmLatencySeconds,
		m.busConsumerLag,
	)

	// Seed the counters at 0 so /metrics returns every documented
	// metric even before the first event fires. Without this, a
	// freshly-started engine would omit counters that have not yet
	// been incremented, which breaks dashboards that chart
	// rate(...) from a known-zero baseline.
	m.stepFailures.WithLabelValues("", "", "").Add(0)
	m.processFailures.WithLabelValues("").Add(0)
	m.autoreflectFires.WithLabelValues("").Add(0)
	m.autoreflectSkipped.WithLabelValues("").Add(0)
	m.llmTokens.WithLabelValues("", "in").Add(0)
	m.llmTokens.WithLabelValues("", "out").Add(0)
	m.artifactsCreated.WithLabelValues("").Add(0)
	m.llmLatencySeconds.WithLabelValues("", "").Observe(0) // initialises buckets
	// Counters with no label dimension (budgetPauses, er1SinkFailures,
	// hmacRotations) are always emitted by promhttp even at 0, so they
	// don't need explicit seeding.

	if cfg.BusMetrics != nil && len(cfg.Topics) > 0 {
		m.stop = make(chan struct{})
		m.done = make(chan struct{})
		go m.pollLag()
	}
	return m
}

// Handler returns the promhttp.Handler bound to this Registry's
// private prometheus.Registry. Mount it at /metrics; Prometheus
// scrapes pull from here.
func (m *Registry) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{
		// Keep errors out of the scrape response — Prometheus treats
		// them as a scrape failure. Log them via promhttp's default
		// logger instead.
		ErrorHandling: promhttp.ContinueOnError,
	})
}

// Close stops the background lag-poller (if any). Safe to call
// multiple times.
func (m *Registry) Close() {
	m.stopMu.Lock()
	defer m.stopMu.Unlock()
	if m.stop == nil {
		return
	}
	close(m.stop)
	<-m.done
	m.stop = nil
}

// ----- Metrics interface implementation -----

// RecordLLMCall increments llm_tokens (in+out) and observes latency.
func (m *Registry) RecordLLMCall(model, layer, strategy string, tokensIn, tokensOut int, latency time.Duration) {
	if m == nil {
		return
	}
	if tokensIn > 0 {
		m.llmTokens.WithLabelValues(model, "in").Add(float64(tokensIn))
	}
	if tokensOut > 0 {
		m.llmTokens.WithLabelValues(model, "out").Add(float64(tokensOut))
	}
	m.llmLatencySeconds.WithLabelValues(model, layer).Observe(latency.Seconds())
	_ = strategy // strategy is not a label on llm_tokens (keeps cardinality bounded); retained on the call site for future use.
}

// RecordStepFailure increments step_failures_total.
func (m *Registry) RecordStepFailure(layer, strategy, reason string) {
	if m == nil {
		return
	}
	m.stepFailures.WithLabelValues(layer, strategy, reason).Inc()
}

// RecordProcessFailure increments process_failures_total.
func (m *Registry) RecordProcessFailure(mode string) {
	if m == nil {
		return
	}
	m.processFailures.WithLabelValues(mode).Inc()
}

// RecordAutoReflectFire increments autoreflect_fires_total.
func (m *Registry) RecordAutoReflectFire(reason string) {
	if m == nil {
		return
	}
	m.autoreflectFires.WithLabelValues(reason).Inc()
}

// RecordAutoReflectSkip increments autoreflect_skipped_total.
func (m *Registry) RecordAutoReflectSkip(reason string) {
	if m == nil {
		return
	}
	m.autoreflectSkipped.WithLabelValues(reason).Inc()
}

// RecordBudgetPause increments budget_pauses_total.
func (m *Registry) RecordBudgetPause() {
	if m == nil {
		return
	}
	m.budgetPauses.Inc()
}

// RecordArtifactCreated increments artifacts_created_total.
func (m *Registry) RecordArtifactCreated(format string) {
	if m == nil {
		return
	}
	m.artifactsCreated.WithLabelValues(format).Inc()
}

// RecordER1SinkFailure increments er1_sink_failures_total.
func (m *Registry) RecordER1SinkFailure() {
	if m == nil {
		return
	}
	m.er1SinkFailures.Inc()
}

// RecordHMACRotation increments hmac_rotations_total. Reserved for
// P2; kept here so the counter is visible from day one.
func (m *Registry) RecordHMACRotation() {
	if m == nil {
		return
	}
	m.hmacRotations.Inc()
}

// pollLag is the background loop that reads ConsumerLag for each
// configured topic and updates the gauge. Exits when Close is called.
func (m *Registry) pollLag() {
	defer close(m.done)
	interval := m.cfg.LagPollInterval
	if interval <= 0 {
		interval = DefaultLagPollInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	// Prime immediately so /metrics reflects reality before the first tick.
	m.sampleLag()
	for {
		select {
		case <-m.stop:
			return
		case <-t.C:
			m.sampleLag()
		}
	}
}

func (m *Registry) sampleLag() {
	if m.cfg.BusMetrics == nil {
		return
	}
	for _, topic := range m.cfg.Topics {
		lag, err := m.cfg.BusMetrics.ConsumerLag(topic)
		if err != nil {
			// Treat errors as "unknown" by leaving the last value
			// intact; Prometheus users can detect staleness via
			// scrape timestamps. Alternately we could reset to 0,
			// but that would hide transient broker errors.
			continue
		}
		m.busConsumerLag.WithLabelValues(topic).Set(float64(lag))
	}
}

// ----- NoopMetrics: drop-in when metrics are disabled -----

// NoopMetrics satisfies Metrics without registering anything. Used
// when DISABLE_METRICS=1, and as a safe default in tests that don't
// exercise observability.
type NoopMetrics struct{}

// RecordLLMCall is a no-op.
func (NoopMetrics) RecordLLMCall(string, string, string, int, int, time.Duration) {}

// RecordStepFailure is a no-op.
func (NoopMetrics) RecordStepFailure(string, string, string) {}

// RecordProcessFailure is a no-op.
func (NoopMetrics) RecordProcessFailure(string) {}

// RecordAutoReflectFire is a no-op.
func (NoopMetrics) RecordAutoReflectFire(string) {}

// RecordAutoReflectSkip is a no-op.
func (NoopMetrics) RecordAutoReflectSkip(string) {}

// RecordBudgetPause is a no-op.
func (NoopMetrics) RecordBudgetPause() {}

// RecordArtifactCreated is a no-op.
func (NoopMetrics) RecordArtifactCreated(string) {}

// RecordER1SinkFailure is a no-op.
func (NoopMetrics) RecordER1SinkFailure() {}

// RecordHMACRotation is a no-op.
func (NoopMetrics) RecordHMACRotation() {}
