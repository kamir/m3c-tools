package timetracking

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestPLMClient_UsesAPIKeyEvenWithDeviceToken pins down BUG-0124: the PLM
// endpoint on onboarding.guide does not accept Bearer auth, so the PLM
// client must send X-API-KEY directly even when ER1_DEVICE_TOKEN is set.
// Before the fix, the shared auth.ApplyAuth helper preferred Bearer and
// PLM silently 401'd, killing the menubar's "Projects" submenu.
func TestPLMClient_UsesAPIKeyEvenWithDeviceToken(t *testing.T) {
	t.Setenv("ER1_DEVICE_TOKEN", "stale-bearer-token-that-the-server-will-reject")

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
		t.Errorf("X-API-KEY header = %q, want the configured key", seenAPIKey)
	}
	if seenAuth != "" {
		t.Errorf("Authorization header should NOT be sent (PLM rejects Bearer); got %q", seenAuth)
	}
	if seenCtx != "107677460544181387647" {
		t.Errorf("X-Context-ID = %q", seenCtx)
	}
}
