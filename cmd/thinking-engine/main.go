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
	"syscall"
	"time"

	"github.com/kamir/m3c-tools/internal/thinking/api"
	"github.com/kamir/m3c-tools/internal/thinking/budget"
	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
	"github.com/kamir/m3c-tools/internal/thinking/er1"
	tkafka "github.com/kamir/m3c-tools/internal/thinking/kafka"
	"github.com/kamir/m3c-tools/internal/thinking/llm"
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
		kafkaAddr   = flag.String("kafka", "", "Kafka bootstrap address (ignored Week 1 — in-memory bus)")
		er1CredPath = flag.String("er1-credentials", "", "path to ER1 service-account key (ignored Week 1 — stub client)")
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

	// Kafka bus — in-memory default, wrapped in a schema validator so
	// every produce + every consume goes through the SPEC-0167 gate.
	innerBus := tkafka.NewMemBus(hash)
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

	// Orchestrator.
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

	deps := processors.Deps{
		Hash:    hash,
		Bus:     bus,
		Orc:     orc,
		Prompts: promptReg,
		Log:     logger,
		LLM:     llmAdapter,
		Budgets: budgetFactory,
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

	// Rebuild service for POST /v1/rebuild.
	rebuildSvc := &rebuild.Service{
		Hash: hash, OwnerID: rawCtx.Value(),
		Bus: bus, ER1: er1Client, Orc: orc, Cache: cache, Logger: logger,
	}

	// ER1 sinker (D2). Opt-in via ENABLE_ER1_SINK=1. Default ON in
	// deployments; tests leave it OFF.
	var sinker *sink.Sinker
	if sink.Enabled(os.Getenv) {
		sinker = sink.New(sink.Config{
			Hash: hash, OwnerID: rawCtx.Value(),
			Bus: bus, ER1: er1Client, Logger: logger,
		})
		if err := sinker.Start(ctx); err != nil {
			logger.Fatalf("sink: %v", err)
		}
		logger.Printf("sink: ER1 projection active")
	} else {
		logger.Printf("sink: disabled (ENABLE_ER1_SINK not set)")
	}

	// HTTP server.
	srv := api.New(api.Config{
		OwnerRaw:  rawCtx,
		Hash:      hash,
		Secret:    secret,
		Bus:       bus,
		Orc:       orc,
		Store:     st,
		BuildInfo: version,
		Cache:     cache,
		Rebuild:   rebuildSvc,
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
	if sinker != nil {
		sinker.Stop()
	}
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	if err := httpSrv.Shutdown(shutCtx); err != nil {
		logger.Printf("http shutdown: %v", err)
	}
	cancel()
	logger.Printf("bye")
}
