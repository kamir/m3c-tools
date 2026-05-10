package skillgate

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestHTTPInvocationPoster_SendsXAPIKey verifies the gateway client harmonizes
// with the rest of the skill-registry API surface by sending the API key as
// `X-API-KEY: <key>` and NOT as `Authorization: Bearer <key>`. This is AC-11
// of runtime-envelope-e2e-test.sh (SPEC-0202 §17).
func TestHTTPInvocationPoster_SendsXAPIKey(t *testing.T) {
	const apiKey = "test-api-key-deadbeef"

	var (
		gotXAPIKey   string
		gotAuthz     string
		gotCT        string
		gotUA        string
		gotEventType string
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotXAPIKey = r.Header.Get("X-API-KEY")
		gotAuthz = r.Header.Get("Authorization")
		gotCT = r.Header.Get("Content-Type")
		gotUA = r.Header.Get("User-Agent")
		body, _ := io.ReadAll(r.Body)
		var ev map[string]any
		_ = json.Unmarshal(body, &ev)
		if t, ok := ev["type"].(string); ok {
			gotEventType = t
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	poster := NewHTTPInvocationPoster(srv.URL, apiKey)
	ev := InvocationEvent{
		Type:      "gate.allowed",
		TokenID:   "ct:01HZTESTTESTTESTTESTTESTTE",
		SkillName: "didactic-session",
		Tenant:    "kup-berlin",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	if err := poster.PostInvocation(ev); err != nil {
		t.Fatalf("PostInvocation: unexpected error: %v", err)
	}

	if gotXAPIKey != apiKey {
		t.Errorf("expected X-API-KEY=%q, got %q", apiKey, gotXAPIKey)
	}
	if gotAuthz != "" {
		t.Errorf("expected NO Authorization header (registry uses X-API-KEY), got %q", gotAuthz)
	}
	if gotCT != "application/json" {
		t.Errorf("expected Content-Type=application/json, got %q", gotCT)
	}
	if gotUA == "" {
		t.Errorf("expected non-empty User-Agent")
	}
	if gotEventType != "gate.allowed" {
		t.Errorf("expected event type=gate.allowed, got %q", gotEventType)
	}
}

// TestHTTPInvocationPoster_NoAPIKeySetsNoHeader confirms that if APIKey is
// empty the client emits NEITHER an X-API-KEY nor an Authorization header
// (the receiver is expected to refuse anonymous calls itself; the client
// MUST NOT silently send the empty string).
func TestHTTPInvocationPoster_NoAPIKeySetsNoHeader(t *testing.T) {
	var gotXAPIKey, gotAuthz string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotXAPIKey = r.Header.Get("X-API-KEY")
		gotAuthz = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	poster := NewHTTPInvocationPoster(srv.URL, "")
	if err := poster.PostInvocation(InvocationEvent{Type: "gate.allowed"}); err != nil {
		t.Fatalf("PostInvocation: unexpected error: %v", err)
	}

	if gotXAPIKey != "" {
		t.Errorf("expected NO X-API-KEY when APIKey unset, got %q", gotXAPIKey)
	}
	if gotAuthz != "" {
		t.Errorf("expected NO Authorization header, got %q", gotAuthz)
	}
}

// TestHTTPInvocationPoster_Non2xxReturnsError ensures non-2xx upstream
// responses surface as errors so callers (Gate.audit) can log them, even
// though Gate.audit itself discards the error per SPEC-0202 §9.
func TestHTTPInvocationPoster_Non2xxReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	poster := NewHTTPInvocationPoster(srv.URL, "key")
	err := poster.PostInvocation(InvocationEvent{Type: "gate.refused"})
	if err == nil {
		t.Fatal("expected error on 500 response, got nil")
	}
}
