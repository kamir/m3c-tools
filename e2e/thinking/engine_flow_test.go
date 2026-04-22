// engine_flow_test.go — end-to-end smoke test for the Thinking
// Engine control API.
//
// Stubbed for Phase 1 Week 1: uses the in-memory Kafka bus (no
// broker). Skips under `go test -short` as the task spec requires;
// `make thinking-test` (unit-only) passes -short to exclude this.

package thinking_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kamir/m3c-tools/internal/thinking/api"
	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
	tkafka "github.com/kamir/m3c-tools/internal/thinking/kafka"
	"github.com/kamir/m3c-tools/internal/thinking/orchestrator"
	procA "github.com/kamir/m3c-tools/internal/thinking/processors/a"
	procI "github.com/kamir/m3c-tools/internal/thinking/processors/i"
	procR "github.com/kamir/m3c-tools/internal/thinking/processors/r"
	"github.com/kamir/m3c-tools/internal/thinking/processors"
	"github.com/kamir/m3c-tools/internal/thinking/prompts"
	"github.com/kamir/m3c-tools/internal/thinking/schema"
	"github.com/kamir/m3c-tools/internal/thinking/store"
)

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}

func newLogger(t *testing.T) *log.Logger {
	return log.New(testWriter{t: t}, "[test] ", log.LstdFlags)
}

func TestLinearProcessEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("thinking e2e: skipped in -short mode")
	}

	raw, _ := mctx.NewRaw("e2e-user")
	hash := raw.Hash()

	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	bus := tkafka.NewMemBus(hash)
	orc := orchestrator.New(hash, bus, st)
	reg := prompts.NewMemoryRegistry()
	deps := processors.Deps{
		Hash: hash, Bus: bus, Orc: orc, Prompts: reg, Log: newLogger(t),
	}

	ctx := t.Context()
	for _, p := range []processors.Processor{procR.New(deps), procI.New(deps), procA.New(deps)} {
		if err := p.Start(ctx); err != nil {
			t.Fatal(err)
		}
	}

	srv := api.New(api.Config{
		OwnerRaw:  raw,
		Hash:      hash,
		Secret:    []byte("t-secret"),
		Bus:       bus,
		Orc:       orc,
		Store:     st,
		BuildInfo: "test",
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	tok := api.SignToken([]byte("t-secret"), api.Claims{
		CtxID: "e2e-user", Expiry: time.Now().Add(time.Minute), Nonce: "t",
	})

	spec := schema.ProcessSpec{
		SchemaVer: schema.CurrentSchemaVer,
		ProcessID: uuid.NewString(),
		Intent:    "smoke test",
		Mode:      schema.ModeLinear,
		Depth:     1,
		Steps: []schema.Step{
			{Layer: schema.LayerR, Strategy: "compare"},
			{Layer: schema.LayerI, Strategy: "pattern"},
			{Layer: schema.LayerA, Strategy: "report"},
		},
	}
	body, _ := json.Marshal(spec)

	req, _ := http.NewRequest("POST", ts.URL+"/v1/process", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusAccepted {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /v1/process status=%d body=%s", resp.StatusCode, b)
	}
	resp.Body.Close()

	deadline := time.Now().Add(3 * time.Second)
	var last map[string]interface{}
	for time.Now().Before(deadline) {
		statusReq, _ := http.NewRequest("GET", ts.URL+"/v1/process/"+spec.ProcessID, nil)
		statusReq.Header.Set("Authorization", "Bearer "+tok)
		sr, err := http.DefaultClient.Do(statusReq)
		if err != nil {
			t.Fatal(err)
		}
		_ = json.NewDecoder(sr.Body).Decode(&last)
		sr.Body.Close()
		if last["state"] == "completed" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if last["state"] != "completed" {
		t.Fatalf("process did not complete: %+v", last)
	}
}

func TestHealthNoAuth(t *testing.T) {
	if testing.Short() {
		t.Skip("thinking e2e: skipped in -short mode")
	}
	raw, _ := mctx.NewRaw("e2e-user")
	hash := raw.Hash()
	st, _ := store.Open(":memory:")
	defer st.Close()
	bus := tkafka.NewMemBus(hash)
	orc := orchestrator.New(hash, bus, st)
	srv := api.New(api.Config{
		OwnerRaw: raw, Hash: hash, Secret: []byte("x"),
		Bus: bus, Orc: orc, Store: st, BuildInfo: "test",
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d", resp.StatusCode)
	}
	var h map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&h)
	if h["ctx"] != hash.Hex() {
		t.Errorf("health ctx = %v, want %s", h["ctx"], hash.Hex())
	}
}
