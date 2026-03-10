package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCLIHelp verifies the e2e test infrastructure by running the CLI
// with "help" and asserting the output using all helper functions.
func TestCLIHelp(t *testing.T) {
	result := RunCLI(t, "help")
	result.AssertSuccess(t)
	result.AssertContains(t, "m3c-tools")
	result.AssertContains(t, "Commands:")
	result.AssertNotContains(t, "FATAL")
	result.AssertOutputContainsAll(t, "transcript", "upload", "record", "devices")
}

// TestCLIUnknownCommand verifies that unknown commands return a non-zero exit code.
func TestCLIUnknownCommand(t *testing.T) {
	result := RunCLI(t, "nonexistent-command-xyz")
	result.AssertExitCode(t, 1)
	result.AssertContains(t, "Unknown command")
}

// TestCLINoArgs verifies that running with no args shows usage and exits non-zero.
func TestCLINoArgs(t *testing.T) {
	result := RunCLI(t)
	result.AssertExitCode(t, 1)
	result.AssertContains(t, "Commands:")
}

// TestRepoRoot verifies the repo root finder works correctly.
func TestRepoRoot(t *testing.T) {
	root := RepoRoot(t)
	if root == "" {
		t.Fatal("RepoRoot returned empty string")
	}
	// Should contain Makefile
	if _, err := os.Stat(filepath.Join(root, "Makefile")); err != nil {
		t.Errorf("RepoRoot %s does not contain Makefile: %v", root, err)
	}
	// Should contain go.mod
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Errorf("RepoRoot %s does not contain go.mod: %v", root, err)
	}
}

// TestWriteFixture verifies the fixture helper creates files correctly.
func TestWriteFixture(t *testing.T) {
	path := WriteFixture(t, "test.txt", "hello world")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "hello world" {
		t.Errorf("Expected 'hello world', got %q", string(data))
	}
}

// TestWriteFixtureBytes verifies binary fixture creation.
func TestWriteFixtureBytes(t *testing.T) {
	content := []byte{0x00, 0xFF, 0x42}
	path := WriteFixtureBytes(t, "binary.bin", content)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(data) != 3 || data[2] != 0x42 {
		t.Errorf("Unexpected content: %v", data)
	}
}

// TestFixtureDir verifies directory fixture creation with multiple files.
func TestFixtureDir(t *testing.T) {
	dir := FixtureDir(t, map[string]string{
		"a.txt":        "file a",
		"sub/b.txt":    "file b",
		"sub/c/d.json": `{"key": "value"}`,
	})

	// Check all files exist
	for _, rel := range []string{"a.txt", "sub/b.txt", "sub/c/d.json"} {
		p := filepath.Join(dir, rel)
		if _, err := os.Stat(p); err != nil {
			t.Errorf("Expected file %s: %v", rel, err)
		}
	}

	// Verify content
	data, _ := os.ReadFile(filepath.Join(dir, "sub/b.txt"))
	if string(data) != "file b" {
		t.Errorf("Expected 'file b', got %q", string(data))
	}
}

// TestTempDataDir verifies temp data dir creation.
func TestTempDataDir(t *testing.T) {
	dir := TempDataDir(t)
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("TempDataDir: %v", err)
	}
	if !info.IsDir() {
		t.Error("TempDataDir did not return a directory")
	}
}

// TestWithEnv verifies environment variable setting and restoration.
func TestWithEnv(t *testing.T) {
	key := "M3C_TEST_HELPER_ENV_VAR_XYZ"
	os.Unsetenv(key)

	t.Run("sets and restores", func(t *testing.T) {
		WithEnv(t, key, "test_value")
		if v := os.Getenv(key); v != "test_value" {
			t.Errorf("Expected 'test_value', got %q", v)
		}
	})

	// After subtest cleanup, var should be unset
	if _, exists := os.LookupEnv(key); exists {
		t.Error("Environment variable was not cleaned up after test")
	}
}

// TestCLIResultAssertions verifies that assertion helpers work correctly
// by checking behavior with known outputs.
func TestCLIResultAssertions(t *testing.T) {
	// Create a synthetic result
	r := &CLIResult{
		Stdout:   "hello world\nfoo bar\n",
		Stderr:   "hello world\nfoo bar\n",
		Combined: "hello world\nfoo bar\n",
		ExitCode: 0,
		Err:      nil,
	}

	// These should not fail
	r.AssertSuccess(t)
	r.AssertExitCode(t, 0)
	r.AssertContains(t, "hello")
	r.AssertContains(t, "foo bar")
	r.AssertNotContains(t, "baz")
	r.AssertOutputContainsAll(t, "hello", "foo")

	// Verify Contains works with multi-line
	if !strings.Contains(r.Combined, "world") {
		t.Error("Multi-line contains check failed")
	}
}

// TestRunCLIWithEnv verifies env vars are passed to subprocess.
func TestRunCLIWithEnv(t *testing.T) {
	// Use help command — env vars shouldn't break anything
	result := RunCLIWithEnv(t, []string{"M3C_TEST_CUSTOM_VAR=1"}, "help")
	result.AssertSuccess(t)
	result.AssertContains(t, "m3c-tools")
}
