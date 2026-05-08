package er1

import (
	"bytes"
	"log"
	"os"
	"testing"
)

// SPEC-0143: Tests for dual-auth (device token + API key) behavior in LoadConfig and HealthCheck.

func TestLoadConfig_NoWarningWithDeviceToken(t *testing.T) {
	t.Setenv("ER1_DEVICE_TOKEN", "test-token")
	t.Setenv("ER1_API_KEY", "")
	os.Unsetenv("ER1_API_KEY")

	// Capture log output to verify no warning is emitted.
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	cfg := LoadConfig()
	if cfg == nil {
		t.Fatal("LoadConfig returned nil")
	}

	output := buf.String()
	if bytes.Contains([]byte(output), []byte("WARNING")) {
		t.Errorf("LoadConfig should NOT warn when device token is set, but logged: %s", output)
	}
}

func TestLoadConfig_WarnsWhenNoAuth(t *testing.T) {
	t.Setenv("ER1_DEVICE_TOKEN", "")
	os.Unsetenv("ER1_DEVICE_TOKEN")
	t.Setenv("ER1_API_KEY", "")
	os.Unsetenv("ER1_API_KEY")
	// LoadConfig also suppresses the warning when ~/.m3c-tools/device-token.enc
	// exists on disk (the user has signed in). On a developer machine that file
	// usually exists, so the test must isolate $HOME to a clean temp dir to
	// reliably observe the warning.
	t.Setenv("HOME", t.TempDir())

	// Capture log output to verify warning is emitted.
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	cfg := LoadConfig()
	if cfg == nil {
		t.Fatal("LoadConfig returned nil")
	}

	output := buf.String()
	if !bytes.Contains([]byte(output), []byte("WARNING")) {
		t.Errorf("LoadConfig should warn when no auth is configured, but logged: %q", output)
	}
	if !bytes.Contains([]byte(output), []byte("No authentication configured")) {
		t.Errorf("Warning should mention 'No authentication configured', got: %q", output)
	}
}

func TestHealthCheck_AcceptsDeviceTokenAuth(t *testing.T) {
	t.Setenv("ER1_DEVICE_TOKEN", "test-token")
	cfg := &Config{APIKey: "", APIURL: "https://127.0.0.1:9999/upload_2"}

	// HealthCheck should NOT return the "no authentication configured" error
	// when a device token is set, even when APIKey is empty.
	err := cfg.HealthCheck()
	if err != nil && err.Error() == "no authentication configured (no device token, no API key)" {
		t.Error("HealthCheck should accept device token as valid auth, but rejected it")
	}
	// The error may be "unreachable" (no server running) -- that's expected and OK.
	// The important thing is that the auth gate did not block.
}

// BUG-0137: a placeholder API key targeting prod must be wiped at LoadConfig
// time so the request is never sent (no silent server-side 401).
func TestLoadConfig_PlaceholderKeyOnProdIsCleared(t *testing.T) {
	t.Setenv("ER1_DEVICE_TOKEN", "")
	os.Unsetenv("ER1_DEVICE_TOKEN")
	t.Setenv("ER1_API_KEY", "minimal-key")
	t.Setenv("ER1_API_URL", "https://onboarding.guide/upload_2")
	t.Setenv("HOME", t.TempDir()) // suppress device-token.enc presence noise

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	cfg := LoadConfig()
	if cfg == nil {
		t.Fatal("LoadConfig returned nil")
	}
	if cfg.APIKey != "" {
		t.Errorf("placeholder key against prod must be cleared; got APIKey = %q", cfg.APIKey)
	}
	if !bytes.Contains(buf.Bytes(), []byte("FATAL")) {
		t.Errorf("expected FATAL log line for placeholder key, got: %q", buf.String())
	}
	if !bytes.Contains(buf.Bytes(), []byte("minimal-key")) {
		t.Errorf("FATAL log line must name the offending placeholder, got: %q", buf.String())
	}
}

// BUG-0137: the dev-credential against localhost is a legitimate pairing
// (the local Docker container accepts it). LoadConfig must not clear it.
func TestLoadConfig_DevCredentialOnLocalhostIsKept(t *testing.T) {
	t.Setenv("ER1_DEVICE_TOKEN", "")
	os.Unsetenv("ER1_DEVICE_TOKEN")
	t.Setenv("ER1_API_KEY", "democredential-er1-api-key")
	t.Setenv("ER1_API_URL", "https://127.0.0.1:8081/upload_2")

	cfg := LoadConfig()
	if cfg == nil {
		t.Fatal("LoadConfig returned nil")
	}
	if cfg.APIKey != "democredential-er1-api-key" {
		t.Errorf("dev credential against localhost must be kept; got APIKey = %q", cfg.APIKey)
	}
}
