package er1

import (
	"os"
	"testing"
)

func TestLoadConfig_Defaults(t *testing.T) {
	// Clear env to test defaults
	for _, k := range []string{"ER1_API_URL", "ER1_API_KEY", "ER1_CONTEXT_ID", "ER1_CONTENT_TYPE"} {
		os.Unsetenv(k)
	}
	cfg := LoadConfig()
	if cfg.APIURL == "" {
		t.Error("APIURL should have a default")
	}
	if cfg.ContextID == "" {
		t.Error("ContextID should have a default")
	}
}

func TestLoadConfig_FromEnv(t *testing.T) {
	os.Setenv("ER1_API_URL", "https://test.example.com/upload_2")
	os.Setenv("ER1_API_KEY", "test-key-123")
	os.Setenv("ER1_CONTEXT_ID", "user-456___mft")
	defer func() {
		os.Unsetenv("ER1_API_URL")
		os.Unsetenv("ER1_API_KEY")
		os.Unsetenv("ER1_CONTEXT_ID")
	}()

	cfg := LoadConfig()
	if cfg.APIURL != "https://test.example.com/upload_2" {
		t.Errorf("APIURL = %q, want test URL", cfg.APIURL)
	}
	if cfg.APIKey != "test-key-123" {
		t.Errorf("APIKey = %q, want test-key-123", cfg.APIKey)
	}
	if cfg.ContextID != "user-456___mft" {
		t.Errorf("ContextID = %q, want user-456___mft", cfg.ContextID)
	}
}

func TestAuthHeaders_WithKey(t *testing.T) {
	cfg := &Config{APIKey: "my-key", ContextID: "ctx-123"}
	h := cfg.AuthHeaders()
	if h["X-API-KEY"] != "my-key" {
		t.Errorf("X-API-KEY = %q, want my-key", h["X-API-KEY"])
	}
	if h["X-Context-ID"] != "ctx-123" {
		t.Errorf("X-Context-ID = %q, want ctx-123", h["X-Context-ID"])
	}
}

func TestAuthHeaders_Empty(t *testing.T) {
	cfg := &Config{}
	h := cfg.AuthHeaders()
	if _, ok := h["X-API-KEY"]; ok {
		t.Error("X-API-KEY should not be set when APIKey is empty")
	}
}

// SPEC-0143: Device token tests

func TestAuthHeaders_PrefersDeviceToken(t *testing.T) {
	t.Setenv("ER1_DEVICE_TOKEN", "test-bearer-token")
	cfg := &Config{APIKey: "some-api-key", ContextID: "ctx"}
	h := cfg.AuthHeaders()
	if h["Authorization"] != "Bearer test-bearer-token" {
		t.Errorf("Authorization = %q, want Bearer token", h["Authorization"])
	}
	if _, ok := h["X-API-KEY"]; ok {
		t.Error("X-API-KEY should not be set when device token is active")
	}
}

func TestHealthCheck_AcceptsDeviceToken(t *testing.T) {
	t.Setenv("ER1_DEVICE_TOKEN", "test-token")
	cfg := &Config{APIKey: "", APIURL: "https://127.0.0.1:9999/upload_2"}
	// HealthCheck should NOT return "no authentication configured" when token exists.
	err := cfg.HealthCheck()
	if err != nil && err.Error() == "no authentication configured (no device token, no API key)" {
		t.Error("HealthCheck should accept device token as valid auth")
	}
	// It may fail with "unreachable" (no server) — that's OK, the auth gate passed.
}

func TestHealthCheck_RejectsNoAuth(t *testing.T) {
	t.Setenv("ER1_DEVICE_TOKEN", "")
	os.Unsetenv("ER1_DEVICE_TOKEN")
	cfg := &Config{APIKey: ""}
	err := cfg.HealthCheck()
	if err == nil {
		t.Error("HealthCheck should fail when no auth is configured")
	}
	if err.Error() != "no authentication configured (no device token, no API key)" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSummary_ShowsTokenAuth(t *testing.T) {
	t.Setenv("ER1_DEVICE_TOKEN", "test-token")
	cfg := &Config{APIURL: "https://example.com/upload_2", ContextID: "ctx"}
	s := cfg.Summary()
	if !contains(s, "device-token") {
		t.Errorf("Summary should show device-token auth, got: %s", s)
	}
}

func TestSummary_ShowsAPIKeyAuth(t *testing.T) {
	t.Setenv("ER1_DEVICE_TOKEN", "")
	os.Unsetenv("ER1_DEVICE_TOKEN")
	cfg := &Config{APIURL: "https://example.com/upload_2", APIKey: "abc123", ContextID: "ctx"}
	s := cfg.Summary()
	if !contains(s, "api-key") {
		t.Errorf("Summary should show api-key auth, got: %s", s)
	}
}

func TestSummary_ShowsNoAuth(t *testing.T) {
	t.Setenv("ER1_DEVICE_TOKEN", "")
	os.Unsetenv("ER1_DEVICE_TOKEN")
	cfg := &Config{APIURL: "https://example.com/upload_2", ContextID: "ctx"}
	s := cfg.Summary()
	if !contains(s, "(none)") {
		t.Errorf("Summary should show (none) auth, got: %s", s)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
