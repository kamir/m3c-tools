package main

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestBinaryRefusesWithoutCtxID verifies the binary exits non-zero
// and prints a recognizable error when --user-context-id is missing.
// Requires `make thinking-build` (or an equivalent build) to have
// produced ./build/thinking-engine at repo root.
func TestBinaryRefusesWithoutCtxID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping exec test in -short")
	}
	// Locate repo root from this file's directory.
	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	bin := filepath.Join(repoRoot, "build", "thinking-engine")
	cmd := exec.Command(bin)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit, got success; output=%s", out)
	}
	if !strings.Contains(string(out), "user-context-id") {
		t.Errorf("output missing flag reference: %s", out)
	}
}
