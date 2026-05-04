package timetracking

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestPLMClient_SendsAPIKeyAndBearerWhenBothAvailable pins the post-2026-05-02
// contract for BUG-0124: PLM accepts both Bearer and X-API-KEY (server-side
// fix landed in modules/plm/api.py), so the client sends both when both are
// available. The server checks Bearer first, falls back to API key.
//
// History: the v2.7.0 contract was "X-API-KEY only, never Authorization"
// because PLM rejected Bearer with HTTP 401. Once the server learned Bearer,
// the client started sending both — Bearer for users who only have
// `m3c-tools login` (no API key in profile), API key as a fallback.
func TestPLMClient_SendsAPIKeyAndBearerWhenBothAvailable(t *testing.T) {
	t.Setenv("ER1_DEVICE_TOKEN", "device-token-abcdef")

	var seenAPIKey, seenAuth, seenCtx string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAPIKey = r.Header.Get("X-API-KEY")
		seenAuth = r.Header.Get("Authorization")
		seenCtx = r.Header.Get("X-Context-ID")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"projects":[],"total":0}`))
	}))
	defer srv.Close()

	c := NewPLMClient(PLMConfig{
		BaseURL:   srv.URL,
		APIKey:    "real-api-key-1234567890abcdef",
		ContextID: "107677460544181387647",
		VerifySSL: false,
	})

	if err := c.HealthCheck(); err != nil {
		t.Fatalf("HealthCheck: %v", err)
	}

	if seenAPIKey != "real-api-key-1234567890abcdef" {
		t.Errorf("X-API-KEY = %q, want the configured key", seenAPIKey)
	}
	if seenAuth != "Bearer device-token-abcdef" {
		t.Errorf("Authorization = %q, want %q", seenAuth, "Bearer device-token-abcdef")
	}
	if seenCtx != "107677460544181387647" {
		t.Errorf("X-Context-ID = %q", seenCtx)
	}
}

// TestPLMClient_BearerOnlyWorksWithoutAPIKey covers the original motivation
// for the May 2 follow-up: a user signed in via `m3c-tools login` carries a
// device token but no API key in the profile. PLM must still be reachable —
// otherwise the menubar Projects submenu silently empties out.
func TestPLMClient_BearerOnlyWorksWithoutAPIKey(t *testing.T) {
	t.Setenv("ER1_DEVICE_TOKEN", "device-token-only")

	var seenAPIKey, seenAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAPIKey = r.Header.Get("X-API-KEY")
		seenAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"projects":[],"total":0}`))
	}))
	defer srv.Close()

	c := NewPLMClient(PLMConfig{
		BaseURL:   srv.URL,
		ContextID: "107677460544181387647",
		VerifySSL: false,
	})

	if err := c.HealthCheck(); err != nil {
		t.Fatalf("HealthCheck: %v", err)
	}

	if seenAPIKey != "" {
		t.Errorf("X-API-KEY should be empty when no key configured; got %q", seenAPIKey)
	}
	if seenAuth != "Bearer device-token-only" {
		t.Errorf("Authorization = %q, want %q", seenAuth, "Bearer device-token-only")
	}
}

// TestPLMClient_APIKeyOnlyWhenNoDeviceToken — symmetric to the Bearer-only
// case. CI machines and headless installs typically have an API key in the
// profile but no device token; the client must work without Bearer.
func TestPLMClient_APIKeyOnlyWhenNoDeviceToken(t *testing.T) {
	t.Setenv("ER1_DEVICE_TOKEN", "")

	var seenAPIKey, seenAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAPIKey = r.Header.Get("X-API-KEY")
		seenAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"projects":[],"total":0}`))
	}))
	defer srv.Close()

	c := NewPLMClient(PLMConfig{
		BaseURL:   srv.URL,
		APIKey:    "real-api-key-1234567890abcdef",
		ContextID: "107677460544181387647",
		VerifySSL: false,
	})

	if err := c.HealthCheck(); err != nil {
		t.Fatalf("HealthCheck: %v", err)
	}

	if seenAPIKey != "real-api-key-1234567890abcdef" {
		t.Errorf("X-API-KEY = %q, want the configured key", seenAPIKey)
	}
	if seenAuth != "" {
		t.Errorf("Authorization should be empty without device token; got %q", seenAuth)
	}
}
