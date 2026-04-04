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
