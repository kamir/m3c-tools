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
	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
	"github.com/kamir/m3c-tools/internal/thinking/er1"
	tkafka "github.com/kamir/m3c-tools/internal/thinking/kafka"
	"github.com/kamir/m3c-tools/internal/thinking/orchestrator"
	procA "github.com/kamir/m3c-tools/internal/thinking/processors/a"
	procC "github.com/kamir/m3c-tools/internal/thinking/processors/c"
	procI "github.com/kamir/m3c-tools/internal/thinking/processors/i"
	procR "github.com/kamir/m3c-tools/internal/thinking/processors/r"
	"github.com/kamir/m3c-tools/internal/thinking/processors"
	"github.com/kamir/m3c-tools/internal/thinking/prompts"
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

	// Kafka bus — in-memory for Week 1.
	bus := tkafka.NewMemBus(hash)
	defer func() { _ = bus.Close() }()

	// ER1 stub client.
	_ = er1.New(rawCtx) // constructed here only to prove ctx-guard wiring

	// Orchestrator + processors.
	orc := orchestrator.New(hash, bus, st)
	promptReg := prompts.NewMemoryRegistry()
	deps := processors.Deps{
		Hash:    hash,
		Bus:     bus,
		Orc:     orc,
		Prompts: promptReg,
		Log:     logger,
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

	// HTTP server.
	srv := api.New(api.Config{
		OwnerRaw:  rawCtx,
		Hash:      hash,
		Secret:    secret,
		Bus:       bus,
		Orc:       orc,
		Store:     st,
		BuildInfo: version,
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
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	if err := httpSrv.Shutdown(shutCtx); err != nil {
		logger.Printf("http shutdown: %v", err)
	}
	cancel()
	logger.Printf("bye")
}
