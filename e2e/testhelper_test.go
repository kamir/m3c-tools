// Package e2e provides end-to-end test infrastructure for the m3c-tools CLI.
//
// This file contains shared helpers, fixtures, and setup/teardown utilities
// for running CLI commands in a subprocess and asserting outputs.
package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// Binary builder — builds once per test run, reused across all tests
// ---------------------------------------------------------------------------

var (
	builtBinary     string
	builtBinaryOnce sync.Once
	builtBinaryErr  error
)

// BinaryPath returns the path to a freshly built m3c-tools binary.
// The binary is built exactly once per test run and cached for all tests.
// It fails the test immediately if the build fails.
func BinaryPath(t *testing.T) string {
	t.Helper()
	builtBinaryOnce.Do(func() {
		root := RepoRoot(t)
		builtBinary = filepath.Join(root, "build", "m3c-tools-e2e-test")
		cmd := exec.Command("go", "build", "-o", builtBinary, "./cmd/m3c-tools")
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			builtBinaryErr = fmt.Errorf("build failed: %v\n%s", err, out)
		}
	})
	if builtBinaryErr != nil {
		t.Fatalf("BinaryPath: %v", builtBinaryErr)
	}
	return builtBinary
}

// ---------------------------------------------------------------------------
// CLI runner — execute subcommands and capture output
// ---------------------------------------------------------------------------

// CLIResult holds the output and exit information from a CLI invocation.
type CLIResult struct {
	Stdout   string
	Stderr   string
	Combined string // stdout + stderr interleaved (as CombinedOutput)
	ExitCode int
	Err      error
}

// RunCLI executes the m3c-tools binary with the given arguments and returns
// the captured output. It builds the binary on first call.
// The command inherits the current environment plus any extra env vars.
func RunCLI(t *testing.T, args ...string) *CLIResult {
	t.Helper()
	return RunCLIWithEnv(t, nil, args...)
}

// RunCLIWithEnv executes the m3c-tools binary with extra environment variables.
// env entries should be in "KEY=VALUE" format. nil env means inherit only.
func RunCLIWithEnv(t *testing.T, env []string, args ...string) *CLIResult {
	t.Helper()
	bin := BinaryPath(t)
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), env...)

	out, err := cmd.CombinedOutput()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}
	combined := string(out)
	return &CLIResult{
		Stdout:   combined, // CombinedOutput merges both
		Stderr:   combined,
		Combined: combined,
		ExitCode: exitCode,
		Err:      err,
	}
}

// RunCLIWithDir executes the m3c-tools binary in a specific working directory.
func RunCLIWithDir(t *testing.T, dir string, args ...string) *CLIResult {
	t.Helper()
	bin := BinaryPath(t)
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=1")

	out, err := cmd.CombinedOutput()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}
	combined := string(out)
	return &CLIResult{
		Stdout:   combined,
		Stderr:   combined,
		Combined: combined,
		ExitCode: exitCode,
		Err:      err,
	}
}

// ---------------------------------------------------------------------------
// Assertion helpers on CLIResult
// ---------------------------------------------------------------------------

// AssertSuccess fails the test if the command exited with a non-zero code.
func (r *CLIResult) AssertSuccess(t *testing.T) {
	t.Helper()
	if r.ExitCode != 0 {
		t.Fatalf("Expected exit code 0, got %d\nOutput:\n%s", r.ExitCode, r.Combined)
	}
}

// AssertExitCode fails the test if the exit code doesn't match expected.
func (r *CLIResult) AssertExitCode(t *testing.T, expected int) {
	t.Helper()
	if r.ExitCode != expected {
		t.Fatalf("Expected exit code %d, got %d\nOutput:\n%s", expected, r.ExitCode, r.Combined)
	}
}

// AssertContains fails the test if the combined output does not contain substr.
func (r *CLIResult) AssertContains(t *testing.T, substr string) {
	t.Helper()
	if !strings.Contains(r.Combined, substr) {
		t.Errorf("Expected output to contain %q, got:\n%s", substr, r.Combined)
	}
}

// AssertNotContains fails the test if the combined output contains substr.
func (r *CLIResult) AssertNotContains(t *testing.T, substr string) {
	t.Helper()
	if strings.Contains(r.Combined, substr) {
		t.Errorf("Expected output NOT to contain %q, got:\n%s", substr, r.Combined)
	}
}

// AssertOutputContainsAll fails if any of the given substrings are missing.
func (r *CLIResult) AssertOutputContainsAll(t *testing.T, substrs ...string) {
	t.Helper()
	for _, s := range substrs {
		if !strings.Contains(r.Combined, s) {
			t.Errorf("Expected output to contain %q, got:\n%s", s, r.Combined)
		}
	}
}

// AssertOutputEmpty fails if the combined output is not empty (ignoring whitespace).
func (r *CLIResult) AssertOutputEmpty(t *testing.T) {
	t.Helper()
	if strings.TrimSpace(r.Combined) != "" {
		t.Errorf("Expected empty output, got:\n%s", r.Combined)
	}
}

// ---------------------------------------------------------------------------
// Repo root helper
// ---------------------------------------------------------------------------

var (
	repoRootPath string
	repoRootOnce sync.Once
)

// RepoRoot finds and returns the repository root directory (where Makefile lives).
// Result is cached for the process lifetime.
func RepoRoot(t *testing.T) string {
	t.Helper()
	repoRootOnce.Do(func() {
		wd, err := os.Getwd()
		if err != nil {
			return
		}
		dir := wd
		for {
			if _, err := os.Stat(filepath.Join(dir, "Makefile")); err == nil {
				repoRootPath = dir
				return
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				return
			}
			dir = parent
		}
	})
	if repoRootPath == "" {
		t.Fatal("Cannot find repo root (Makefile not found in parent directories)")
	}
	return repoRootPath
}

// ---------------------------------------------------------------------------
// Temp directory and fixture helpers
// ---------------------------------------------------------------------------

// TempDataDir creates a temporary directory mimicking ~/.m3c-tools/ and returns
// its path. The directory is automatically cleaned up when the test finishes.
func TempDataDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return dir
}

// WriteFixture creates a temporary file with the given content in a test-owned
// directory. Returns the absolute path to the file.
func WriteFixture(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("WriteFixture mkdir: %v", err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFixture write: %v", err)
	}
	return p
}

// WriteFixtureBytes creates a temporary file with binary content.
func WriteFixtureBytes(t *testing.T, name string, data []byte) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("WriteFixtureBytes mkdir: %v", err)
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatalf("WriteFixtureBytes write: %v", err)
	}
	return p
}

// FixtureDir creates a temporary directory populated with multiple files.
// files is a map of relative-path → content.
func FixtureDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("FixtureDir mkdir %s: %v", name, err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatalf("FixtureDir write %s: %v", name, err)
		}
	}
	return dir
}

// ---------------------------------------------------------------------------
// Environment helpers
// ---------------------------------------------------------------------------

// WithEnv temporarily sets an environment variable for the duration of the
// test and restores it on cleanup. Returns the set value for chaining.
func WithEnv(t *testing.T, key, value string) string {
	t.Helper()
	old, existed := os.LookupEnv(key)
	os.Setenv(key, value)
	t.Cleanup(func() {
		if existed {
			os.Setenv(key, old)
		} else {
			os.Unsetenv(key)
		}
	})
	return value
}

// ---------------------------------------------------------------------------
// Skip helpers
// ---------------------------------------------------------------------------

// SkipIfNoNetwork skips the test when M3C_SKIP_NETWORK is set.
func SkipIfNoNetwork(t *testing.T) {
	t.Helper()
	if os.Getenv("M3C_SKIP_NETWORK") != "" {
		t.Skip("Skipping: M3C_SKIP_NETWORK is set")
	}
}

// SkipIfNoER1 skips the test when ER1 is not configured or not reachable.
func SkipIfNoER1(t *testing.T) {
	t.Helper()
	if os.Getenv("ER1_API_URL") == "" {
		t.Skip("Skipping: ER1_API_URL not set")
	}
}

// SkipIfNoMicrophone skips the test when M3C_SKIP_AUDIO is set.
func SkipIfNoMicrophone(t *testing.T) {
	t.Helper()
	if os.Getenv("M3C_SKIP_AUDIO") != "" {
		t.Skip("Skipping: M3C_SKIP_AUDIO is set")
	}
}
