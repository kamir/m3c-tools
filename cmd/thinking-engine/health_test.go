package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// TestBinaryServesHealth starts the engine binary, queries /v1/health,
// verifies the ctx hash, then kills the process.
func TestBinaryServesHealth(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping exec test in -short")
	}
	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	bin := filepath.Join(repoRoot, "build", "thinking-engine")

	// Use an unlikely port so we don't collide with a real engine run.
	port := ":17141"
	tmpDir := t.TempDir()
	cmd := exec.Command(bin,
		"--user-context-id=demo-health",
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

	// Give it up to 2s to come up.
	deadline := time.Now().Add(2 * time.Second)
	var resp *http.Response
	var err error
	for time.Now().Before(deadline) {
		resp, err = http.Get("http://localhost" + port + "/v1/health")
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("health request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("health status = %d body=%s", resp.StatusCode, b)
	}
	var h map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&h); err != nil {
		t.Fatal(err)
	}
	if h["ctx"] == "" || h["ctx"] == nil {
		t.Errorf("health missing ctx: %+v", h)
	}
	if h["status"] != "ok" {
		t.Errorf("status = %v, want ok", h["status"])
	}
}
