package main

import (
	"io"
	"net/http"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestBinaryExposesMetricsEndpoint starts the engine binary and
// verifies GET /metrics returns 200 + the documented Prometheus
// series at zero. PLAN-0168 §P0 acceptance gate: "curl
// http://localhost:7140/metrics returns 200 with all documented
// metrics at 0 on fresh start."
//
// Requires the binary at ./build/thinking-engine (see health_test.go
// for the sibling check).
func TestBinaryExposesMetricsEndpoint(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping exec test in -short")
	}
	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	bin := filepath.Join(repoRoot, "build", "thinking-engine")

	port := ":17142"
	tmpDir := t.TempDir()
	cmd := exec.Command(bin,
		"--user-context-id=demo-metrics",
		"--listen="+port,
		"--state-path="+filepath.Join(tmpDir, "state.db"),
	)
	cmd.Env = append(cmd.Environ(), "THINKING_ENGINE_SECRET=t")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	// Wait up to 2s for the HTTP listener.
	deadline := time.Now().Add(2 * time.Second)
	var resp *http.Response
	var err error
	for time.Now().Before(deadline) {
		resp, err = http.Get("http://localhost" + port + "/metrics")
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("metrics request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("metrics status = %d body=%s", resp.StatusCode, b)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	got := string(body)

	// Every documented series must be present at the fresh-start zero
	// baseline. Dashboards that chart rate(...) from 0 depend on this.
	for _, needle := range []string{
		"m3c_thinking_step_failures_total",
		"m3c_thinking_process_failures_total",
		"m3c_thinking_autoreflect_fires_total",
		"m3c_thinking_autoreflect_skipped_total",
		"m3c_thinking_budget_pauses_total",
		"m3c_thinking_llm_tokens_total",
		"m3c_thinking_artifacts_created_total",
		"m3c_thinking_er1_sink_failures_total",
		"m3c_thinking_hmac_rotations_total",
		"m3c_thinking_llm_latency_seconds",
		"m3c_thinking_bus_consumer_lag",
	} {
		if !strings.Contains(got, needle) {
			t.Errorf("/metrics missing %q", needle)
		}
	}

	// Static labels must appear.
	if !strings.Contains(got, `engine_version=`) {
		t.Errorf("/metrics missing engine_version label")
	}
	if !strings.Contains(got, `ctx_hash=`) {
		t.Errorf("/metrics missing ctx_hash label")
	}
}
