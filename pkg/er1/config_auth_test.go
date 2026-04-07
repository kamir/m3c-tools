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
