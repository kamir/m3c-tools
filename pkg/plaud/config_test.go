package plaud

import (
	"os"
	"path/filepath"
	"testing"
)

// --- SEC-M8: secure Plaud token resolution ---

func TestResolveAuthToken_PrefersTokenFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tok")
	if err := os.WriteFile(path, []byte("  file-token-12345\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// Env and argv both set — token-file must win and must NOT be flagged leaked.
	t.Setenv(PlaudTokenEnvVar, "env-token")
	tok, leaked, err := ResolveAuthToken(path, "argv-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "file-token-12345" {
		t.Errorf("token = %q, want trimmed file-token-12345", tok)
	}
	if leaked {
		t.Error("token-file source must not be flagged as argv-leaked")
	}
}

func TestResolveAuthToken_EnvBeatsArgv(t *testing.T) {
	t.Setenv(PlaudTokenEnvVar, "env-token-xyz")
	tok, leaked, err := ResolveAuthToken("", "argv-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "env-token-xyz" {
		t.Errorf("token = %q, want env-token-xyz", tok)
	}
	if leaked {
		t.Error("env source must not be flagged as argv-leaked")
	}
}

func TestResolveAuthToken_ArgvIsFlaggedLeaked(t *testing.T) {
	os.Unsetenv(PlaudTokenEnvVar)
	tok, leaked, err := ResolveAuthToken("", "bare-argv-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "bare-argv-token" {
		t.Errorf("token = %q, want bare-argv-token", tok)
	}
	if !leaked {
		t.Error("bare-argv token MUST be flagged as leaked so the caller warns")
	}
}

func TestResolveAuthToken_NoSourceErrors(t *testing.T) {
	os.Unsetenv(PlaudTokenEnvVar)
	if _, _, err := ResolveAuthToken("", ""); err == nil {
		t.Error("expected error when no token source is provided")
	}
}

func TestResolveAuthToken_EmptyTokenFileErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty")
	if err := os.WriteFile(path, []byte("   \n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ResolveAuthToken(path, ""); err == nil {
		t.Error("expected error for empty --token-file")
	}
}

func TestResolveAuthToken_MissingTokenFileErrors(t *testing.T) {
	if _, _, err := ResolveAuthToken("/no/such/token/file", ""); err == nil {
		t.Error("expected error for unreadable --token-file")
	}
}

// --- SEC-L9: Plaud DocID validation ---

func TestValidateDocID(t *testing.T) {
	valid := []string{
		"abcd1234",
		"AbC_def-123456",
		"0123456789abcdef0123456789abcdef",
	}
	for _, id := range valid {
		if err := ValidateDocID(id); err != nil {
			t.Errorf("ValidateDocID(%q) unexpected error: %v", id, err)
		}
	}

	invalid := []string{
		"",                 // empty
		"short",            // < 8 chars
		"../../etc/passwd", // path traversal
		"abc/def/ghi",      // slash
		"abc1234?x=1",      // query injection
		"abc1234#frag",     // fragment
		"abc 1234 5678",    // whitespace
		"abc.detail.1234",  // dot
		"id%2e%2e",         // percent-encoded
	}
	for _, id := range invalid {
		if err := ValidateDocID(id); err == nil {
			t.Errorf("ValidateDocID(%q) should have rejected it", id)
		}
	}
}
