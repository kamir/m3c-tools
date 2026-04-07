package e2e

import (
	"os"
	"testing"
)

// TestDoctorBasicOutput verifies the doctor command runs and produces the expected sections.
func TestDoctorBasicOutput(t *testing.T) {
	r := RunCLI(t, "doctor")
	// Doctor may fail (no valid credentials in CI) but must produce structured output.
	r.AssertContains(t, "m3c-tools doctor")
	r.AssertContains(t, "Profile")
	r.AssertContains(t, "Authentication")
	r.AssertContains(t, "Config Consistency")
	r.AssertContains(t, "Connectivity")
	r.AssertContains(t, "Result:")
}

// TestDoctorShowsAuthMethod verifies the doctor command reports the active auth method.
func TestDoctorShowsAuthMethod(t *testing.T) {
	r := RunCLI(t, "doctor")
	r.AssertContains(t, "Auth method:")
}

// TestDoctorNoAuthShowsFail verifies that doctor correctly reports missing auth
// when neither device token nor API key is set.
// Uses a clean HOME to avoid the active profile injecting an API key.
func TestDoctorNoAuthShowsFail(t *testing.T) {
	tmpHome := t.TempDir()
	r := RunCLIWithEnv(t, []string{
		"HOME=" + tmpHome,
		"ER1_API_KEY=",
		"ER1_DEVICE_TOKEN=",
		"ER1_API_URL=https://onboarding.guide/upload_2",
	}, "doctor")
	r.AssertContains(t, "NO AUTH")
}

// TestCheckER1ReportsAuthMethod verifies check-er1 uses the correct auth label.
func TestCheckER1ReportsAuthMethod(t *testing.T) {
	SkipIfNoER1(t)
	r := RunCLI(t, "check-er1")
	// Should say "Auth check" not "API key check".
	r.AssertContains(t, "Auth check:")
	r.AssertNotContains(t, "API key check:")
}

// TestDeviceTokenAuthNoAPIKey verifies that with a device token set and no API key,
// the system does NOT warn about missing API key and uses Bearer auth.
func TestDeviceTokenAuthNoAPIKey(t *testing.T) {
	r := RunCLIWithEnv(t, []string{
		"ER1_API_KEY=",
		"ER1_DEVICE_TOKEN=fake-token-for-testing",
		"ER1_API_URL=https://onboarding.guide/upload_2",
	}, "doctor")
	// Should NOT contain the old API key warning.
	r.AssertNotContains(t, "ER1_API_KEY is not set")
	// Should show Bearer token as auth method.
	r.AssertContains(t, "Bearer token")
	// API key should show as not needed.
	r.AssertContains(t, "not needed")
}

// TestDeviceTokenPreferredOverAPIKey verifies token takes priority when both are set.
func TestDeviceTokenPreferredOverAPIKey(t *testing.T) {
	r := RunCLIWithEnv(t, []string{
		"ER1_API_KEY=some-legacy-key",
		"ER1_DEVICE_TOKEN=fake-token-for-testing",
		"ER1_API_URL=https://onboarding.guide/upload_2",
	}, "doctor")
	r.AssertContains(t, "Bearer token")
	r.AssertContains(t, "not needed")
}

// TestDoctorAgainstLocalDocker runs doctor against a local Docker dev server.
// Requires: docker ER1 running at 127.0.0.1:8081 with dev profile.
func TestDoctorAgainstLocalDocker(t *testing.T) {
	if os.Getenv("M3C_E2E_LOCAL_DOCKER") == "" {
		t.Skip("Skipping: set M3C_E2E_LOCAL_DOCKER=1 to run against local Docker")
	}

	r := RunCLIWithEnv(t, []string{
		"ER1_API_URL=https://127.0.0.1:8081/upload_2",
		"ER1_VERIFY_SSL=false",
	}, "doctor")
	r.AssertContains(t, "ER1 /health")
	// Local docker should be reachable.
	r.AssertContains(t, "HTTP 200")
}

// TestCheckER1AgainstLocalDocker runs check-er1 against a local Docker dev server.
// Requires: docker ER1 running at 127.0.0.1:8081 with dev profile.
func TestCheckER1AgainstLocalDocker(t *testing.T) {
	if os.Getenv("M3C_E2E_LOCAL_DOCKER") == "" {
		t.Skip("Skipping: set M3C_E2E_LOCAL_DOCKER=1 to run against local Docker")
	}

	r := RunCLIWithEnv(t, []string{
		"ER1_API_URL=https://127.0.0.1:8081/upload_2",
		"ER1_API_KEY=democredential-er1-api-key",
		"ER1_VERIFY_SSL=false",
	}, "check-er1")
	r.AssertContains(t, "REACHABLE")
	r.AssertContains(t, "Auth check:")
}

// TestUploadWithDeviceTokenOnly verifies that upload works with only a device token.
// Requires: ER1 server running and a valid device token.
func TestUploadWithDeviceTokenOnly(t *testing.T) {
	if os.Getenv("M3C_E2E_LOCAL_DOCKER") == "" {
		t.Skip("Skipping: set M3C_E2E_LOCAL_DOCKER=1 to run against local Docker")
	}
	token := os.Getenv("ER1_DEVICE_TOKEN")
	if token == "" {
		t.Skip("Skipping: ER1_DEVICE_TOKEN not set — pair device first")
	}

	// Upload with device token, no API key.
	r := RunCLIWithEnv(t, []string{
		"ER1_API_KEY=",
		"ER1_DEVICE_TOKEN=" + token,
		"ER1_API_URL=https://127.0.0.1:8081/upload_2",
		"ER1_VERIFY_SSL=false",
	}, "upload", "--transcript-text", "E2E test: device token auth only")
	// Should not fail with "API key not set" error.
	r.AssertNotContains(t, "ER1_API_KEY is not set")
}
