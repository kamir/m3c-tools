package auth

import (
	"net/http"
	"os"
	"testing"
)

func TestApplyAuth_PrefersDeviceToken(t *testing.T) {
	t.Setenv("ER1_DEVICE_TOKEN", "test-bearer-token")
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	ApplyAuth(req, "some-api-key")

	if got := req.Header.Get("Authorization"); got != "Bearer test-bearer-token" {
		t.Errorf("Authorization = %q, want Bearer test-bearer-token", got)
	}
	if got := req.Header.Get("X-API-KEY"); got != "" {
		t.Errorf("X-API-KEY = %q, want empty (token takes priority)", got)
	}
}

func TestApplyAuth_FallsBackToAPIKey(t *testing.T) {
	t.Setenv("ER1_DEVICE_TOKEN", "")
	os.Unsetenv("ER1_DEVICE_TOKEN")
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	ApplyAuth(req, "my-api-key")

	if got := req.Header.Get("X-API-KEY"); got != "my-api-key" {
		t.Errorf("X-API-KEY = %q, want my-api-key", got)
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("Authorization = %q, want empty (no token)", got)
	}
}

func TestApplyAuth_NoAuth(t *testing.T) {
	t.Setenv("ER1_DEVICE_TOKEN", "")
	os.Unsetenv("ER1_DEVICE_TOKEN")
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	ApplyAuth(req, "")

	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("Authorization = %q, want empty", got)
	}
	if got := req.Header.Get("X-API-KEY"); got != "" {
		t.Errorf("X-API-KEY = %q, want empty", got)
	}
}

func TestHasAuth_TokenOnly(t *testing.T) {
	t.Setenv("ER1_DEVICE_TOKEN", "some-token")
	if !HasAuth("") {
		t.Error("HasAuth should return true when device token is set")
	}
}

func TestHasAuth_APIKeyOnly(t *testing.T) {
	t.Setenv("ER1_DEVICE_TOKEN", "")
	os.Unsetenv("ER1_DEVICE_TOKEN")
	if !HasAuth("some-key") {
		t.Error("HasAuth should return true when API key is provided")
	}
}

func TestHasAuth_Neither(t *testing.T) {
	t.Setenv("ER1_DEVICE_TOKEN", "")
	os.Unsetenv("ER1_DEVICE_TOKEN")
	if HasAuth("") {
		t.Error("HasAuth should return false when neither token nor key exists")
	}
}

func TestAuthMethod_Token(t *testing.T) {
	t.Setenv("ER1_DEVICE_TOKEN", "tok")
	if got := AuthMethod(); got != "device token" {
		t.Errorf("AuthMethod() = %q, want 'device token'", got)
	}
}

func TestAuthMethod_APIKey(t *testing.T) {
	t.Setenv("ER1_DEVICE_TOKEN", "")
	os.Unsetenv("ER1_DEVICE_TOKEN")
	t.Setenv("ER1_API_KEY", "key")
	if got := AuthMethod(); got != "API key" {
		t.Errorf("AuthMethod() = %q, want 'API key'", got)
	}
}

func TestAuthMethod_None(t *testing.T) {
	t.Setenv("ER1_DEVICE_TOKEN", "")
	os.Unsetenv("ER1_DEVICE_TOKEN")
	t.Setenv("ER1_API_KEY", "")
	os.Unsetenv("ER1_API_KEY")
	if got := AuthMethod(); got != "none" {
		t.Errorf("AuthMethod() = %q, want 'none'", got)
	}
}
