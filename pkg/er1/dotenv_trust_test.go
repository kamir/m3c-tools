package er1

import (
	"os"
	"path/filepath"
	"testing"
)

// hostileDotenv writes a .env of the kind a foreign checkout could carry and
// returns its path. The keys are the ones that actually move credentials:
// M3C_PLM_BASE_URL becomes the PLM base, and the PLM client sends the ER1 API
// key plus the device token to it.
func hostileDotenv(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	body := "M3C_PLM_BASE_URL=https://attacker.example\n" +
		"ER1_API_URL=https://attacker.example/upload_2\n" +
		"M3C_ER1_SESSION_FILE=/tmp/stolen-session.json\n" +
		"ER1_CONTENT_TYPE=harmless-label\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// clearProbeVars empties every variable the fixture sets, so the assertions
// see this test's own effect and not the developer's ambient environment.
func clearProbeVars(t *testing.T) {
	t.Helper()
	for _, k := range []string{"M3C_PLM_BASE_URL", "ER1_API_URL", "M3C_ER1_SESSION_FILE", "ER1_CONTENT_TYPE"} {
		t.Setenv(k, "")
	}
}

// AUDIT-0001 finding 2.7: without the opt-in, a working-directory .env must
// not reach the process environment at all.
func TestLoadDotenvUntrustedIgnoredWithoutOptIn(t *testing.T) {
	clearProbeVars(t)
	t.Setenv(EnvDotenvOptIn, "")
	if err := LoadDotenvUntrusted(hostileDotenv(t)); err != nil {
		t.Fatalf("LoadDotenvUntrusted: %v", err)
	}
	for _, k := range []string{"M3C_PLM_BASE_URL", "ER1_API_URL", "M3C_ER1_SESSION_FILE", "ER1_CONTENT_TYPE"} {
		if got := os.Getenv(k); got != "" {
			t.Errorf("%s leaked from an un-opted-in working-directory .env: %q", k, got)
		}
	}
}

// The opt-in restores the documented development workflow, so the fix is one
// variable away from the old behaviour instead of a dead end.
func TestLoadDotenvUntrustedAppliedWithOptIn(t *testing.T) {
	clearProbeVars(t)
	t.Setenv(EnvDotenvOptIn, "1")
	if err := LoadDotenvUntrusted(hostileDotenv(t)); err != nil {
		t.Fatalf("LoadDotenvUntrusted: %v", err)
	}
	if got := os.Getenv("M3C_PLM_BASE_URL"); got != "https://attacker.example" {
		t.Errorf("opt-in did not apply the file: M3C_PLM_BASE_URL=%q", got)
	}
}

// An explicit off is honoured too, and a missing file still reports its
// os.Stat error to callers that care.
func TestLoadDotenvUntrustedExplicitOff(t *testing.T) {
	clearProbeVars(t)
	t.Setenv(EnvDotenvOptIn, "0")
	if err := LoadDotenvUntrusted(hostileDotenv(t)); err != nil {
		t.Fatalf("LoadDotenvUntrusted: %v", err)
	}
	if got := os.Getenv("ER1_API_URL"); got != "" {
		t.Errorf("M3C_DOTENV=0 still applied ER1_API_URL=%q", got)
	}
	if err := LoadDotenvUntrusted(filepath.Join(t.TempDir(), ".env")); err == nil {
		t.Error("a missing .env should still surface its stat error")
	}
}

// A file the caller CHOSE (the home preferences, a profile) keeps the old
// semantics: every key applies, no opt-in involved.
func TestLoadDotenvChosenPathUnchanged(t *testing.T) {
	clearProbeVars(t)
	t.Setenv(EnvDotenvOptIn, "")
	if err := LoadDotenv(hostileDotenv(t)); err != nil {
		t.Fatalf("LoadDotenv: %v", err)
	}
	if got := os.Getenv("ER1_API_URL"); got != "https://attacker.example/upload_2" {
		t.Errorf("a chosen .env must still apply every key, got ER1_API_URL=%q", got)
	}
}

// The classifier drives the stderr trail for an opted-in file. It must cover
// the redirect, credential and path shapes, and leave plain labels alone.
func TestSensitiveDotenvKey(t *testing.T) {
	sensitive := []string{
		"ER1_API_URL", "M3C_PLM_BASE_URL", "PLAUD_API_URL", "ER1_API_KEY",
		"ER1_DEVICE_TOKEN", "M3C_PLAUD_TOKEN", "YT_PROXY_URL", "YT_PROXY_AUTH",
		"M3C_ER1_SESSION_FILE", "PLAUD_TOKEN_FILE", "YT_MEMORY_DIR",
		"IMPORT_TRACKER_FILE", "PATH", "SOME_NEW_SECRET", "DB_PASSWORD",
	}
	for _, k := range sensitive {
		if !sensitiveDotenvKey(k) {
			t.Errorf("%s should be classified security-relevant", k)
		}
	}
	benign := []string{
		"ER1_CONTENT_TYPE", "ER1_UPLOAD_TIMEOUT", "ER1_MAX_RETRIES",
		"M3C_WHISPER_MODEL", "M3C_WHISPER_LANGUAGE", "PLAUD_DEFAULT_TAGS",
		"M3C_REVERSE_BLOCK_ENABLED",
	}
	for _, k := range benign {
		if sensitiveDotenvKey(k) {
			t.Errorf("%s should NOT be classified security-relevant", k)
		}
	}
}
