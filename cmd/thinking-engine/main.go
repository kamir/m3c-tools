// Command thinking-engine boots the per-user m3c Thinking Engine.
//
// Mandatory flag: --user-context-id. Without it, the binary refuses
// to start (SPEC-0167 §Isolation Model). The ctx hash is computed
// once and every subsequent identifier (topic names, HMAC claims,
// log lines) derives from it.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kamir/m3c-tools/internal/thinking/api"
	"github.com/kamir/m3c-tools/internal/thinking/autoreflect"
	"github.com/kamir/m3c-tools/internal/thinking/budget"
	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
	"github.com/kamir/m3c-tools/internal/thinking/er1"
	"github.com/kamir/m3c-tools/internal/thinking/feedback"
	tkafka "github.com/kamir/m3c-tools/internal/thinking/kafka"
	"github.com/kamir/m3c-tools/internal/thinking/llm"
	"github.com/kamir/m3c-tools/internal/thinking/observability"
	"github.com/kamir/m3c-tools/internal/thinking/orchestrator"
	procA "github.com/kamir/m3c-tools/internal/thinking/processors/a"
	procC "github.com/kamir/m3c-tools/internal/thinking/processors/c"
	procI "github.com/kamir/m3c-tools/internal/thinking/processors/i"
	procR "github.com/kamir/m3c-tools/internal/thinking/processors/r"
	"github.com/kamir/m3c-tools/internal/thinking/processors"
	"github.com/kamir/m3c-tools/internal/thinking/prompts"
	"github.com/kamir/m3c-tools/internal/thinking/rebuild"
	"github.com/kamir/m3c-tools/internal/thinking/schema"
	"github.com/kamir/m3c-tools/internal/thinking/sink"
	"github.com/kamir/m3c-tools/internal/thinking/store"
)

// Build-time injectable.
var version = "0.0.0-dev"

func main() {
	var (
		userCtxID   = flag.String("user-context-id", "", "REQUIRED — user_context_id the engine is bound to (SPEC-0167)")
		listen      = flag.String("listen", ":7140", "address to listen on")
		secretEnv   = flag.String("secret-env", "THINKING_ENGINE_SECRET", "env var holding the HMAC secret")
		statePath   = flag.String("state-path", "", "SQLite path (default: ~/.m3c-tools/thinking/<hash>/state.db)")
		kafkaAddr   = flag.String("kafka", "", "Kafka bootstrap address (comma-separated). Empty = in-memory bus. Requires -tags thinking_kafka build to actually connect.")
		er1CredPath = flag.String("er1-credentials", "", "path to ER1 service-account key (Phase 1: unused — HMAC to Flask bridge)")
	)
	flag.Parse()

	if *userCtxID == "" {
		fmt.Fprintln(os.Stderr, "ERROR: --user-context-id is REQUIRED — refuse to start without a concrete user context (SPEC-0167 §Isolation Model)")
		os.Exit(2)
	}

	rawCtx, err := mctx.NewRaw(*userCtxID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(2)
	}
	hash := rawCtx.Hash()

	logger := log.New(os.Stdout, fmt.Sprintf("[thinking-engine ctx=%s] ", hash.Hex()), log.LstdFlags|log.Lmsgprefix)
	logger.Printf("starting version=%s listen=%s", version, *listen)
	logger.Printf("unused-in-week1 kafka=%q er1=%q", *kafkaAddr, *er1CredPath)

	// HMAC secret — required. In dev, export THINKING_ENGINE_SECRET=anything.
	secret := []byte(os.Getenv(*secretEnv))
	if len(secret) == 0 {
		// Dev fallback: derive from ctx hash so local curl-with-no-env still works.
		// This is NOT suitable for production; Phase 2 will require a real secret.
		secret = []byte("dev-" + hash.Hex())
		logger.Printf("WARNING: %s not set, using dev fallback secret", *secretEnv)
	}

	// State DB.
	dbPath := *statePath
	if dbPath == "" {
		home, _ := os.UserHomeDir()
		dir := filepath.Join(home, ".m3c-tools", "thinking", hash.Hex())
		_ = os.MkdirAll(dir, 0o755)
		dbPath = filepath.Join(dir, "state.db")
	}
	logger.Printf("sqlite state: %s", dbPath)
	st, err := store.Open(dbPath)
	if err != nil {
		logger.Fatalf("store: %v", err)
	}
	defer st.Close()

	// Kafka bus — in-memory when no brokers given OR when built without
	// `-tags thinking_kafka`; real franz-go driver when both conditions
	// are met. Wrapped in a schema validator so every produce and every
	// consume goes through the SPEC-0167 gate.
	var brokers []string
	if *kafkaAddr != "" {
		brokers = strings.Split(*kafkaAddr, ",")
	}
	innerBus, err := tkafka.NewBus(hash, brokers)
	if err != nil {
		logger.Fatalf("bus: %v", err)
	}
	if len(brokers) == 0 {
		logger.Printf("bus: in-memory (no -kafka given)")
	} else {
		logger.Printf("bus: connected brokers=%v", brokers)
	}
	bus, err := tkafka.NewValidatingBus(innerBus, nil)
	if err != nil {
		logger.Fatalf("validating bus: %v", err)
	}
	defer func() { _ = bus.Close() }()

	// ER1 HTTP client. ER1_BASE_URL (default http://localhost:5000) is
	// the aims-core Flask bridge; HMAC secret matches
	// `flask/modules/thinking_bridge/auth.py`.
	er1Client, err := er1.NewWithConfig(rawCtx, er1.Config{
		HMACSecret: secret,
	})
	if err != nil {
		logger.Fatalf("er1: %v", err)
	}

	// Orchestrator. Start() subscribes it to its own process.events
	// topic so semi_linear + loop modes can advance step-by-step
	// (SPEC-0167 §Stream 3a).
	orc := orchestrator.New(hash, bus, st)

	// Prompt registry — prefer HTTP if configured, fall back to the
	// in-memory stub so local dev still works without a Flask bridge.
	var promptReg prompts.Registry
	if baseURL := os.Getenv("THINKING_PROMPT_REGISTRY_URL"); baseURL != "" {
		reg, err := prompts.NewHTTPRegistry(prompts.HTTPConfig{
			BaseURL: baseURL,
			Store:   st,
			Logger:  logger,
		})
		if err != nil {
			logger.Fatalf("prompt registry: %v", err)
		}
		promptReg = reg
		logger.Printf("prompts: HTTP registry at %s", baseURL)
	} else {
		promptReg = prompts.NewMemoryRegistry()
		logger.Printf("prompts: in-memory stub registry (set THINKING_PROMPT_REGISTRY_URL to use Flask)")
	}

	// LLM adapter — OpenAI if OPENAI_API_KEY is set; otherwise
	// processors that need LLM will error cleanly.
	var llmAdapter llm.Adapter
	if adapter, err := llm.NewOpenAI(); err == nil {
		llmAdapter = adapter
		logger.Printf("llm: openai adapter initialised")
	} else {
		logger.Printf("llm: not configured (%v) — R/I handlers will fail until configured", err)
	}

	// Budget factory: one controller per process, reusing the shared
	// store for the daily USD counter.
	budgetFactory := func(processID string, spec schema.ProcessSpec) *budget.Controller {
		return budget.New(processID, spec.EffectiveMaxTokens(), 0, st, budget.StubEstimator{})
	}
	_ = budgetFactory // referenced below via deps

	// Consumer-side read cache for listing endpoints (Week 2).
	cache, err := store.NewCache(store.CacheConfig{
		Store:  st,
		Bus:    bus,
		Hash:   hash,
		Logger: logger,
	})
	if err != nil {
		logger.Fatalf("cache: %v", err)
	}
	if err := cache.Start(); err != nil {
		logger.Fatalf("cache start: %v", err)
	}
	defer cache.Stop()

	// Observability (PLAN-0168 §P0). Two independent surfaces, both
	// opt-out via env so tests can suppress them:
	//   DISABLE_METRICS=1      → skip Prometheus registry + /metrics
	//   DISABLE_EVENTS_SINK=1  → skip process.events → stdout logger
	// The Metrics surface is also passed into processors, autoreflect,
	// and sink so their hooks populate counters at the source — the
	// events sink is an independent second path.
	var metricsReg observability.Metrics
	var metricsCloser func()
	var metricsHandler http.Handler
	if os.Getenv("DISABLE_METRICS") != "1" {
		m := observability.NewMetrics(observability.Config{
			CtxHash:       hash.Hex(),
			EngineVersion: version,
			BusMetrics:    bus, // ValidatingBus forwards to inner driver
			Topics: []string{
				tkafka.TopicName(hash, tkafka.TopicThoughtsRaw),
				tkafka.TopicName(hash, tkafka.TopicProcessCommands),
				tkafka.TopicName(hash, tkafka.TopicProcessEvents),
				tkafka.TopicName(hash, tkafka.TopicArtifactsCreated),
			},
		})
		metricsReg = m
		metricsCloser = m.Close
		metricsHandler = m.Handler()
		logger.Printf("metrics: Prometheus registry active")
	} else {
		metricsReg = observability.NoopMetrics{}
		logger.Printf("metrics: disabled (DISABLE_METRICS=1)")
	}

	deps := processors.Deps{
		Hash:    hash,
		Bus:     bus,
		Orc:     orc,
		Prompts: promptReg,
		Log:     logger,
		LLM:     llmAdapter,
		Budgets: budgetFactory,
		Metrics: metricsReg,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	procs := []processors.Processor{
		procR.New(deps),
		procI.New(deps),
		procA.New(deps),
		procC.New(deps),
	}
	for _, p := range procs {
		if err := p.Start(ctx); err != nil {
			logger.Fatalf("start processor: %v", err)
		}
	}

	// Orchestrator's own events subscription (semi_linear + loop — Stream 3a).
	if err := orc.Start(ctx); err != nil {
		logger.Fatalf("start orchestrator: %v", err)
	}

	// Feedback consumer — closes the contradiction → new process loop
	// (SPEC-0167 §Stream 3a). Rate-limited at 10/hour.
	fbConsumer, err := feedback.New(feedback.Config{
		Hash:         hash,
		Bus:          bus,
		Orchestrator: orc,
		Store:        st,
		Logger:       logger,
	})
	if err != nil {
		logger.Fatalf("feedback consumer: %v", err)
	}
	if err := fbConsumer.Start(ctx); err != nil {
		logger.Fatalf("start feedback consumer: %v", err)
	}
	defer fbConsumer.Stop()

	// Auto-reflect consumer — opt-in via ENABLE_AUTO_REFLECT=1. Fires a
	// default semi_linear T→R→I→A ProcessSpec on window-count OR
	// heartbeat triggers (SPEC-0167 Week 3 Phase 2 scaffolding). Gated
	// by its own 10/hour rate limit, dedup ledger, and the D4 daily
	// budget via budget.Ledger. Unset ENABLE_AUTO_REFLECT → zero side
	// effects.
	var autoRef *autoreflect.Consumer
	if autoReflectEnabled(os.Getenv) {
		ledger := budget.NewLedger(st, 0) // 0 → DefaultDailyUSD
		autoRef, err = autoreflect.New(autoreflect.Config{
			Hash:             hash,
			Bus:              bus,
			Orchestrator:     orc,
			Store:            st,
			Ledger:           ledger,
			Logger:           logger,
			WindowN:          intFromEnv("AUTO_REFLECT_WINDOW_N", autoreflect.DefaultWindowN),
			HeartbeatMin:     intFromEnv("AUTO_REFLECT_HEARTBEAT_MIN", autoreflect.DefaultHeartbeatMin),
			RateLimitPerHour: intFromEnv("AUTO_REFLECT_RATE_LIMIT_PER_HOUR", autoreflect.DefaultRateLimitPerHour),
			SkipPlaceholder:  boolFromEnv("AUTO_REFLECT_SKIP_PLACEHOLDER", true),
			Patterns:         listFromEnv("AUTO_REFLECT_PLACEHOLDER_PATTERNS", []string{autoreflect.DefaultPlaceholderPattern}),
			HardTokenCap:     intFromEnv("AUTO_REFLECT_HARD_TOKEN_CAP", autoreflect.DefaultHardTokenCap),
			Metrics:          metricsReg,
		})
		if err != nil {
			logger.Fatalf("auto-reflect: %v", err)
		}
		if err := autoRef.Start(ctx); err != nil {
			logger.Fatalf("start auto-reflect: %v", err)
		}
		logger.Printf("auto-reflect: enabled (ENABLE_AUTO_REFLECT=1)")
		defer autoRef.Stop()
	} else {
		logger.Printf("auto-reflect: disabled (ENABLE_AUTO_REFLECT not set)")
	}

	// Rebuild service for POST /v1/rebuild (Stream 3b).
	rebuildSvc := &rebuild.Service{
		Hash: hash, OwnerID: rawCtx.Value(),
		Bus: bus, ER1: er1Client, Orc: orc, Cache: cache, Logger: logger,
	}

	// ER1 sinker (D2 async artifact persistence — Stream 3b). Opt-in via
	// ENABLE_ER1_SINK=1. Default ON in deployments; tests leave it OFF.
	var sinker *sink.Sinker
	if sink.Enabled(os.Getenv) {
		sinker = sink.New(sink.Config{
			Hash: hash, OwnerID: rawCtx.Value(),
			Bus: bus, ER1: er1Client, Logger: logger,
			Metrics: metricsReg,
		})
		if err := sinker.Start(ctx); err != nil {
			logger.Fatalf("sink: %v", err)
		}
		logger.Printf("sink: ER1 projection active")
	} else {
		logger.Printf("sink: disabled (ENABLE_ER1_SINK not set)")
	}

	// Events sink (PLAN-0168 §P0). Subscribes to process.events and
	// projects operational events to stdout (structured JSON) +
	// Prometheus counters. Opt-out via DISABLE_EVENTS_SINK=1.
	var eventsSink *observability.EventsSink
	if os.Getenv("DISABLE_EVENTS_SINK") != "1" {
		es, err := observability.NewEventsSink(observability.SinkConfig{
			Hash:    hash,
			Bus:     bus,
			Logger:  logger,
			Metrics: metricsReg,
		})
		if err != nil {
			logger.Fatalf("events sink: %v", err)
		}
		if err := es.Start(ctx); err != nil {
			logger.Fatalf("events sink: %v", err)
		}
		defer es.Stop()
		eventsSink = es
		logger.Printf("events sink: subscribed to process.events (errors → stdout)")
	} else {
		logger.Printf("events sink: disabled (DISABLE_EVENTS_SINK=1)")
	}
	_ = eventsSink // retained for future wiring

	// HTTP server.
	srv := api.New(api.Config{
		OwnerRaw:       rawCtx,
		Hash:           hash,
		Secret:         secret,
		Bus:            bus,
		Orc:            orc,
		Store:          st,
		BuildInfo:      version,
		Cache:          cache,
		Rebuild:        rebuildSvc,
		MetricsHandler: metricsHandler, // nil when DISABLE_METRICS=1
	})
	httpSrv := &http.Server{
		Addr:              *listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		logger.Printf("http listening on %s", *listen)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("http: %v", err)
		}
	}()

	// Graceful shutdown.
	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, syscall.SIGINT, syscall.SIGTERM)
	<-stopCh
	logger.Printf("shutdown requested, draining...")

	for _, p := range procs {
		p.Stop()
	}
	orc.Stop()
	if sinker != nil {
		sinker.Stop()
	}
	if metricsCloser != nil {
		metricsCloser()
	}
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	if err := httpSrv.Shutdown(shutCtx); err != nil {
		logger.Printf("http shutdown: %v", err)
	}
	cancel()
	logger.Printf("bye")
}

// autoReflectEnabled reports whether the auto-reflect consumer
// should run. Mirrors sink.Enabled. Accepts "1", "true", "TRUE" as on.
func autoReflectEnabled(getenv func(string) string) bool {
	if getenv == nil {
		return false
	}
	v := getenv("ENABLE_AUTO_REFLECT")
	return v == "1" || v == "true" || v == "TRUE"
}

// intFromEnv returns the integer value of the named env var, or def
// if unset or unparseable.
func intFromEnv(name string, def int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

// boolFromEnv returns the bool value of the named env var, or def
// if unset. Accepts "1", "true", "TRUE", "yes", "YES" as true; the
// symmetric strings "0", "false", "FALSE", "no", "NO" as false.
func boolFromEnv(name string, def bool) bool {
	v := os.Getenv(name)
	switch v {
	case "":
		return def
	case "1", "true", "TRUE", "yes", "YES":
		return true
	case "0", "false", "FALSE", "no", "NO":
		return false
	}
	return def
}

// listFromEnv returns a comma-separated list from an env var, or def
// if unset. Empty entries are dropped; whitespace around entries is
// preserved (regex patterns may legitimately start/end with spaces).
func listFromEnv(name string, def []string) []string {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return def
	}
	return out
}
