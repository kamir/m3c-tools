package observability

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// scrape returns the raw /metrics response body as a string.
func scrape(t *testing.T, m *Registry) string {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	m.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("/metrics status = %d, want 200", rr.Code)
	}
	return rr.Body.String()
}

// assertContains fails the test unless body contains every one of
// needles. A hit on the full metric line (name + labels + "0") is a
// stronger signal than a name-only match.
func assertContains(t *testing.T, body string, needles ...string) {
	t.Helper()
	for _, n := range needles {
		if !strings.Contains(body, n) {
			t.Errorf("/metrics body missing %q\n---BODY---\n%s", n, body)
		}
	}
}

// TestMetricsScrapeAtStartupExposesDocumentedSeries checks that a
// freshly-booted registry emits every documented series, with
// counters at 0 and the latency histogram pre-initialised. This is
// the dashboard-baseline guarantee PLAN-0168 §P0 calls out: Prometheus
// scrapes from a known-zero starting point.
func TestMetricsScrapeAtStartupExposesDocumentedSeries(t *testing.T) {
	m := NewMetrics(Config{CtxHash: "abc123def456", EngineVersion: "test-0.0.0"})
	defer m.Close()

	body := scrape(t, m)

	// Counter families (name appears in # TYPE line + seeded sample).
	for _, name := range []string{
		"m3c_thinking_step_failures_total",
		"m3c_thinking_process_failures_total",
		"m3c_thinking_autoreflect_fires_total",
		"m3c_thinking_autoreflect_skipped_total",
		"m3c_thinking_budget_pauses_total",
		"m3c_thinking_llm_tokens_total",
		"m3c_thinking_artifacts_created_total",
		"m3c_thinking_er1_sink_failures_total",
		"m3c_thinking_hmac_rotations_total",
	} {
		assertContains(t, body, "# TYPE "+name+" counter")
	}

	// Histogram family.
	assertContains(t, body, "# TYPE m3c_thinking_llm_latency_seconds histogram")

	// Gauge family (declared even when there's no bus poller).
	assertContains(t, body, "# TYPE m3c_thinking_bus_consumer_lag gauge")

	// Static labels attach to every metric.
	assertContains(t, body, `ctx_hash="abc123def456"`)
	assertContains(t, body, `engine_version="test-0.0.0"`)

	// Counters at 0 on the seed series.
	assertContains(t, body, "m3c_thinking_budget_pauses_total")
	assertContains(t, body, "m3c_thinking_er1_sink_failures_total")
	assertContains(t, body, "m3c_thinking_hmac_rotations_total")
}

// TestStepFailureIncrements verifies the counter wiring.
func TestStepFailureIncrements(t *testing.T) {
	m := NewMetrics(Config{CtxHash: "ctx1", EngineVersion: "v"})
	defer m.Close()

	m.RecordStepFailure("r", "compare", "llm")
	m.RecordStepFailure("r", "compare", "llm")
	m.RecordStepFailure("i", "pattern", "parse")

	body := scrape(t, m)

	assertContains(t, body,
		`m3c_thinking_step_failures_total{ctx_hash="ctx1",engine_version="v",layer="r",reason="llm",strategy="compare"} 2`,
		`m3c_thinking_step_failures_total{ctx_hash="ctx1",engine_version="v",layer="i",reason="parse",strategy="pattern"} 1`,
	)
}

// TestProcessFailureIncrements verifies the counter wiring.
func TestProcessFailureIncrements(t *testing.T) {
	m := NewMetrics(Config{CtxHash: "c", EngineVersion: "v"})
	defer m.Close()
	m.RecordProcessFailure("semi_linear")
	m.RecordProcessFailure("semi_linear")
	m.RecordProcessFailure("loop")

	body := scrape(t, m)
	assertContains(t, body,
		`m3c_thinking_process_failures_total{ctx_hash="c",engine_version="v",mode="semi_linear"} 2`,
		`m3c_thinking_process_failures_total{ctx_hash="c",engine_version="v",mode="loop"} 1`,
	)
}

// TestAutoReflectFireAndSkipIncrement verifies both directions of
// the autoreflect counter pair.
func TestAutoReflectFireAndSkipIncrement(t *testing.T) {
	m := NewMetrics(Config{CtxHash: "c", EngineVersion: "v"})
	defer m.Close()
	m.RecordAutoReflectFire("window")
	m.RecordAutoReflectFire("heartbeat")
	m.RecordAutoReflectSkip("rate_limit")
	m.RecordAutoReflectSkip("dedup")
	m.RecordAutoReflectSkip("budget")

	body := scrape(t, m)
	assertContains(t, body,
		`m3c_thinking_autoreflect_fires_total{ctx_hash="c",engine_version="v",reason="window"} 1`,
		`m3c_thinking_autoreflect_fires_total{ctx_hash="c",engine_version="v",reason="heartbeat"} 1`,
		`m3c_thinking_autoreflect_skipped_total{ctx_hash="c",engine_version="v",reason="rate_limit"} 1`,
		`m3c_thinking_autoreflect_skipped_total{ctx_hash="c",engine_version="v",reason="dedup"} 1`,
		`m3c_thinking_autoreflect_skipped_total{ctx_hash="c",engine_version="v",reason="budget"} 1`,
	)
}

// TestBudgetPauseAndSinkFailureIncrement verifies the two bare-counter
// series with no label dimensions.
func TestBudgetPauseAndSinkFailureIncrement(t *testing.T) {
	m := NewMetrics(Config{CtxHash: "c", EngineVersion: "v"})
	defer m.Close()
	m.RecordBudgetPause()
	m.RecordBudgetPause()
	m.RecordER1SinkFailure()

	body := scrape(t, m)
	assertContains(t, body,
		`m3c_thinking_budget_pauses_total{ctx_hash="c",engine_version="v"} 2`,
		`m3c_thinking_er1_sink_failures_total{ctx_hash="c",engine_version="v"} 1`,
	)
}

// TestArtifactCreatedIncrements verifies the format label.
func TestArtifactCreatedIncrements(t *testing.T) {
	m := NewMetrics(Config{CtxHash: "c", EngineVersion: "v"})
	defer m.Close()
	m.RecordArtifactCreated("summary")
	m.RecordArtifactCreated("summary")
	m.RecordArtifactCreated("report")

	body := scrape(t, m)
	assertContains(t, body,
		`m3c_thinking_artifacts_created_total{ctx_hash="c",engine_version="v",format="summary"} 2`,
		`m3c_thinking_artifacts_created_total{ctx_hash="c",engine_version="v",format="report"} 1`,
	)
}

// TestHMACRotationIncrementsReservedCounter verifies the P2 reserved
// counter ticks so dashboards chart non-zero when the feature lands.
func TestHMACRotationIncrementsReservedCounter(t *testing.T) {
	m := NewMetrics(Config{CtxHash: "c", EngineVersion: "v"})
	defer m.Close()
	m.RecordHMACRotation()
	body := scrape(t, m)
	assertContains(t, body, `m3c_thinking_hmac_rotations_total{ctx_hash="c",engine_version="v"} 1`)
}

// TestLLMCallRecordsTokensAndLatency verifies both counter (tokens)
// and histogram (latency) are updated, and that the 500ms call lands
// inside the 0.5s bucket (and the 1s/2.5s/.../30s higher buckets).
func TestLLMCallRecordsTokensAndLatency(t *testing.T) {
	m := NewMetrics(Config{CtxHash: "c", EngineVersion: "v"})
	defer m.Close()
	m.RecordLLMCall("gpt-4o-mini", "r", "compare", 1200, 340, 500*time.Millisecond)

	body := scrape(t, m)
	assertContains(t, body,
		`m3c_thinking_llm_tokens_total{ctx_hash="c",direction="in",engine_version="v",model="gpt-4o-mini"} 1200`,
		`m3c_thinking_llm_tokens_total{ctx_hash="c",direction="out",engine_version="v",model="gpt-4o-mini"} 340`,
	)

	// 500ms falls inside every bucket at le >= 0.5 .
	assertContains(t, body, `m3c_thinking_llm_latency_seconds_bucket{ctx_hash="c",engine_version="v",layer="r",model="gpt-4o-mini",le="0.5"} 1`)
	assertContains(t, body, `m3c_thinking_llm_latency_seconds_bucket{ctx_hash="c",engine_version="v",layer="r",model="gpt-4o-mini",le="1"} 1`)
	assertContains(t, body, `m3c_thinking_llm_latency_seconds_bucket{ctx_hash="c",engine_version="v",layer="r",model="gpt-4o-mini",le="30"} 1`)
	// And NOT inside the 0.25s bucket (500ms > 250ms).
	assertContains(t, body, `m3c_thinking_llm_latency_seconds_bucket{ctx_hash="c",engine_version="v",layer="r",model="gpt-4o-mini",le="0.25"} 0`)
}

// fakeBusMetrics provides a scripted ConsumerLag implementation for
// the lag-polling test.
type fakeBusMetrics struct {
	lag map[string]int64
	err error
}

func (f *fakeBusMetrics) ConsumerLag(topic string) (int64, error) {
	if f.err != nil {
		return 0, f.err
	}
	return f.lag[topic], nil
}

// TestBusConsumerLagPolls verifies the lag goroutine updates the
// gauge on its first sample.
func TestBusConsumerLagPolls(t *testing.T) {
	bus := &fakeBusMetrics{lag: map[string]int64{
		"m3c.xyz.thoughts.raw": 42,
		"m3c.xyz.process.events": 7,
	}}
	m := NewMetrics(Config{
		CtxHash:         "xyz",
		EngineVersion:   "v",
		BusMetrics:      bus,
		Topics:          []string{"m3c.xyz.thoughts.raw", "m3c.xyz.process.events"},
		LagPollInterval: 10 * time.Millisecond,
	})
	defer m.Close()

	// Wait long enough for the priming sample + at least one tick.
	waitFor(t, 500*time.Millisecond, func() bool {
		body := scrape(t, m)
		return strings.Contains(body, `m3c_thinking_bus_consumer_lag{ctx_hash="xyz",engine_version="v",topic="m3c.xyz.thoughts.raw"} 42`)
	})

	body := scrape(t, m)
	assertContains(t, body,
		`m3c_thinking_bus_consumer_lag{ctx_hash="xyz",engine_version="v",topic="m3c.xyz.thoughts.raw"} 42`,
		`m3c_thinking_bus_consumer_lag{ctx_hash="xyz",engine_version="v",topic="m3c.xyz.process.events"} 7`,
	)
}

// TestNilRegistryIsNoop verifies that nil-receiver calls are safe.
// This matters because deps.Metrics is typed Metrics (interface) but
// sometimes passed as a *Registry, and the typed-nil pattern would
// otherwise panic.
func TestNilRegistryIsNoop(t *testing.T) {
	var m *Registry
	// Must not panic.
	m.RecordLLMCall("m", "r", "s", 1, 1, time.Millisecond)
	m.RecordStepFailure("r", "s", "x")
	m.RecordProcessFailure("semi_linear")
	m.RecordAutoReflectFire("window")
	m.RecordAutoReflectSkip("dedup")
	m.RecordBudgetPause()
	m.RecordArtifactCreated("summary")
	m.RecordER1SinkFailure()
	m.RecordHMACRotation()
}

// TestNoopMetricsSatisfiesInterface documents that NoopMetrics is
// a drop-in when metrics are disabled.
func TestNoopMetricsSatisfiesInterface(t *testing.T) {
	var _ Metrics = NoopMetrics{}
	n := NoopMetrics{}
	n.RecordLLMCall("m", "r", "s", 1, 1, time.Millisecond)
	n.RecordStepFailure("r", "s", "x")
	n.RecordProcessFailure("semi_linear")
	n.RecordAutoReflectFire("window")
	n.RecordAutoReflectSkip("dedup")
	n.RecordBudgetPause()
	n.RecordArtifactCreated("summary")
	n.RecordER1SinkFailure()
	n.RecordHMACRotation()
}

// waitFor retries cond until true or timeout expires.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition never met within %s", timeout)
}
