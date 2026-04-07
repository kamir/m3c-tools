package plaud

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestDeriveAccountID_Deterministic(t *testing.T) {
	token := "test-plaud-token-abc123"
	id1 := DeriveAccountID(token)
	id2 := DeriveAccountID(token)
	if id1 != id2 {
		t.Errorf("DeriveAccountID not deterministic: %q != %q", id1, id2)
	}
	if id1 == "" {
		t.Error("DeriveAccountID returned empty string")
	}
	if len(id1) != len("plaud-")+16 {
		t.Errorf("DeriveAccountID unexpected length: got %d, want %d", len(id1), len("plaud-")+16)
	}
}

func TestDeriveAccountID_DifferentTokens(t *testing.T) {
	id1 := DeriveAccountID("token-alpha")
	id2 := DeriveAccountID("token-beta")
	if id1 == id2 {
		t.Errorf("DeriveAccountID returned same ID for different tokens: %q", id1)
	}
}

func TestDeriveAccountID_HasPrefix(t *testing.T) {
	id := DeriveAccountID("some-token")
	if id[:6] != "plaud-" {
		t.Errorf("DeriveAccountID missing prefix: got %q", id)
	}
}

func TestDeriveBaseURL(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"https://127.0.0.1:8081/upload_2", "https://127.0.0.1:8081"},
		{"https://example.com/upload", "https://example.com"},
		{"https://example.com/api/upload_2", "https://example.com/api"},
		{"https://example.com", "https://example.com"},
	}
	for _, tt := range tests {
		got := deriveBaseURL(tt.input)
		if got != tt.want {
			t.Errorf("deriveBaseURL(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestNewSyncAPIClient_BaseURL(t *testing.T) {
	client := NewSyncAPIClient("https://127.0.0.1:8081/upload_2", "key", "user", true)
	if client.BaseURL() != "https://127.0.0.1:8081" {
		t.Errorf("BaseURL = %q, want %q", client.BaseURL(), "https://127.0.0.1:8081")
	}
}

func TestCheckRecordings_Success(t *testing.T) {
	expected := SyncCheckResult{
		Synced: map[string]SyncedInfo{
			"rec-001": {ER1DocID: "doc-abc", SyncedAt: "2026-04-01T10:00:00Z", SyncedFrom: "macbook"},
		},
		Unsynced: []string{"rec-002", "rec-003"},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/plaud-sync/check" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.Error(w, "not found", 404)
			return
		}
		if r.Header.Get("X-API-KEY") != "test-key" {
			t.Error("missing X-API-KEY header")
		}
		if r.Header.Get("X-User-ID") != "test-user" {
			t.Error("missing X-User-ID header")
		}
		q := r.URL.Query()
		if q.Get("plaud_account_id") != "plaud-abc" {
			t.Errorf("wrong plaud_account_id: %q", q.Get("plaud_account_id"))
		}
		ids := q.Get("recording_ids")
		if ids != "rec-001,rec-002,rec-003" {
			t.Errorf("wrong recording_ids: %q", ids)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(expected)
	}))
	defer srv.Close()

	client := &SyncAPIClient{
		baseURL:    srv.URL,
		apiKey:     "test-key",
		userID:     "test-user",
		deviceName: "test-device",
		client:     srv.Client(),
	}

	result, err := client.CheckRecordings("plaud-abc", []string{"rec-001", "rec-002", "rec-003"})
	if err != nil {
		t.Fatalf("CheckRecordings returned error: %v", err)
	}
	if result == nil {
		t.Fatal("CheckRecordings returned nil result")
	}
	if len(result.Synced) != 1 {
		t.Errorf("expected 1 synced, got %d", len(result.Synced))
	}
	if info, ok := result.Synced["rec-001"]; !ok {
		t.Error("rec-001 not in synced map")
	} else if info.ER1DocID != "doc-abc" {
		t.Errorf("wrong ER1DocID: %q", info.ER1DocID)
	}
	if len(result.Unsynced) != 2 {
		t.Errorf("expected 2 unsynced, got %d", len(result.Unsynced))
	}
}

func TestCheckRecordings_EmptyList(t *testing.T) {
	client := NewSyncAPIClient("https://127.0.0.1:8081/upload_2", "key", "user", true)
	result, err := client.CheckRecordings("plaud-abc", []string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result for empty list")
	}
	if len(result.Synced) != 0 || len(result.Unsynced) != 0 {
		t.Error("expected empty synced/unsynced for empty input")
	}
}

func TestCheckRecordings_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", 500)
	}))
	defer srv.Close()

	client := &SyncAPIClient{
		baseURL:    srv.URL,
		apiKey:     "key",
		userID:     "user",
		deviceName: "dev",
		client:     srv.Client(),
	}

	result, err := client.CheckRecordings("plaud-abc", []string{"rec-001"})
	// Graceful degradation: should return nil, nil (not an error)
	if err != nil {
		t.Errorf("expected nil error on server error, got: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil result on server error, got: %+v", result)
	}
}

func TestCheckRecordings_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	client := &SyncAPIClient{
		baseURL:    srv.URL,
		apiKey:     "bad-key",
		userID:     "user",
		deviceName: "dev",
		client:     srv.Client(),
	}

	result, err := client.CheckRecordings("plaud-abc", []string{"rec-001"})
	if err != nil {
		t.Errorf("expected nil error on auth failure, got: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil result on auth failure, got: %+v", result)
	}
}

func TestRegisterMapping_Success(t *testing.T) {
	var received SyncMapping
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/plaud-sync/map" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.Error(w, "not found", 404)
			return
		}
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("X-API-KEY") != "test-key" {
			t.Error("missing X-API-KEY")
		}
		if r.Header.Get("X-Device-ID") == "" {
			t.Error("missing X-Device-ID")
		}
		json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	client := &SyncAPIClient{
		baseURL:    srv.URL,
		apiKey:     "test-key",
		userID:     "test-user",
		deviceName: "test-device",
		client:     srv.Client(),
	}

	mapping := SyncMapping{
		PlaudAccountID:   "plaud-abc",
		PlaudRecordingID: "rec-001",
		ER1DocID:         "doc-xyz",
		ER1ContextID:     "ctx-123",
		RecordingTitle:   "Test Recording",
		RecordingDuration: 120,
		AudioFormat:      "ogg",
		AudioSizeBytes:   1024,
		TranscriptLength: 500,
	}

	err := client.RegisterMapping(mapping)
	if err != nil {
		t.Fatalf("RegisterMapping returned error: %v", err)
	}
	if received.PlaudRecordingID != "rec-001" {
		t.Errorf("server received wrong recording ID: %q", received.PlaudRecordingID)
	}
	if received.ER1DocID != "doc-xyz" {
		t.Errorf("server received wrong doc ID: %q", received.ER1DocID)
	}
}

func TestRegisterMapping_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", 500)
	}))
	defer srv.Close()

	client := &SyncAPIClient{
		baseURL:    srv.URL,
		apiKey:     "key",
		userID:     "user",
		deviceName: "dev",
		client:     srv.Client(),
	}

	err := client.RegisterMapping(SyncMapping{PlaudRecordingID: "rec-001"})
	// RegisterMapping DOES return an error on failure (unlike CheckRecordings)
	if err == nil {
		t.Error("expected error on server error, got nil")
	}
}

func TestCheckRecordings_NetworkError(t *testing.T) {
	// Point at a closed server to simulate network error
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srvURL := srv.URL
	srv.Close() // close immediately

	client := &SyncAPIClient{
		baseURL:    srvURL,
		apiKey:     "key",
		userID:     "user",
		deviceName: "dev",
		client:     &http.Client{},
	}

	result, err := client.CheckRecordings("plaud-abc", []string{"rec-001"})
	// Graceful degradation on network error
	if err != nil {
		t.Errorf("expected nil error on network failure, got: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil result on network failure, got: %+v", result)
	}
}

func TestCheckRecordings_AuthUsesBearer(t *testing.T) {
	// When ER1_DEVICE_TOKEN is set, ApplyAuth should use Bearer instead of X-API-KEY.
	t.Setenv("ER1_DEVICE_TOKEN", "test-device-token-xyz")
	defer os.Unsetenv("ER1_DEVICE_TOKEN")

	var gotAuthHeader string
	var gotAPIKeyHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthHeader = r.Header.Get("Authorization")
		gotAPIKeyHeader = r.Header.Get("X-API-KEY")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(SyncCheckResult{
			Synced:   map[string]SyncedInfo{},
			Unsynced: []string{"rec-001"},
		})
	}))
	defer srv.Close()

	client := &SyncAPIClient{
		baseURL:    srv.URL,
		apiKey:     "fallback-api-key",
		userID:     "test-user",
		deviceName: "test-device",
		client:     srv.Client(),
	}

	result, err := client.CheckRecordings("plaud-abc", []string{"rec-001"})
	if err != nil {
		t.Fatalf("CheckRecordings returned error: %v", err)
	}
	if result == nil {
		t.Fatal("CheckRecordings returned nil result")
	}

	// Bearer token should take priority over API key.
	if gotAuthHeader != "Bearer test-device-token-xyz" {
		t.Errorf("Authorization header = %q, want 'Bearer test-device-token-xyz'", gotAuthHeader)
	}
	// X-API-KEY should NOT be set when device token is available.
	if gotAPIKeyHeader != "" {
		t.Errorf("X-API-KEY header = %q, want empty (Bearer takes priority)", gotAPIKeyHeader)
	}
}

func TestRegisterMapping_AuthUsesBearer(t *testing.T) {
	// Verify RegisterMapping also uses Bearer auth when device token is set.
	t.Setenv("ER1_DEVICE_TOKEN", "mapping-bearer-token")
	defer os.Unsetenv("ER1_DEVICE_TOKEN")

	var gotAuthHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	client := &SyncAPIClient{
		baseURL:    srv.URL,
		apiKey:     "fallback-key",
		userID:     "user",
		deviceName: "dev",
		client:     srv.Client(),
	}

	err := client.RegisterMapping(SyncMapping{
		PlaudAccountID:   "plaud-abc",
		PlaudRecordingID: "rec-001",
		ER1DocID:         "doc-001",
	})
	if err != nil {
		t.Fatalf("RegisterMapping returned error: %v", err)
	}
	if gotAuthHeader != "Bearer mapping-bearer-token" {
		t.Errorf("Authorization = %q, want 'Bearer mapping-bearer-token'", gotAuthHeader)
	}
}

func TestRegisterMapping_NetworkError(t *testing.T) {
	// Point at an invalid URL to simulate network error.
	client := &SyncAPIClient{
		baseURL:    "http://127.0.0.1:1", // port 1 is almost certainly closed
		apiKey:     "key",
		userID:     "user",
		deviceName: "dev",
		client:     &http.Client{},
	}

	err := client.RegisterMapping(SyncMapping{PlaudRecordingID: "rec-001"})
	// RegisterMapping should return an error on network failure (not panic).
	if err == nil {
		t.Error("expected error on network failure, got nil")
	}
	if !strings.Contains(err.Error(), "unreachable") {
		t.Errorf("error should mention 'unreachable', got: %v", err)
	}
}

func TestCheckRecordings_VerifiesQueryParams(t *testing.T) {
	// Verify that the correct endpoint and query parameters are used.
	var gotPath string
	var gotAccountID string
	var gotRecordingIDs string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAccountID = r.URL.Query().Get("plaud_account_id")
		gotRecordingIDs = r.URL.Query().Get("recording_ids")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(SyncCheckResult{
			Synced:   map[string]SyncedInfo{},
			Unsynced: []string{"a", "b"},
		})
	}))
	defer srv.Close()

	client := &SyncAPIClient{
		baseURL:    srv.URL,
		apiKey:     "key",
		userID:     "user",
		deviceName: "dev",
		client:     srv.Client(),
	}

	_, err := client.CheckRecordings("plaud-test-account", []string{"a", "b"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotPath != "/api/plaud-sync/check" {
		t.Errorf("path = %q, want /api/plaud-sync/check", gotPath)
	}
	if gotAccountID != "plaud-test-account" {
		t.Errorf("plaud_account_id = %q, want 'plaud-test-account'", gotAccountID)
	}
	if gotRecordingIDs != "a,b" {
		t.Errorf("recording_ids = %q, want 'a,b'", gotRecordingIDs)
	}
}

func TestRegisterMapping_VerifiesPOSTBody(t *testing.T) {
	// Verify RegisterMapping sends correct JSON fields in the POST body.
	var received SyncMapping
	var gotMethod string
	var gotContentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotContentType = r.Header.Get("Content-Type")
		json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	client := &SyncAPIClient{
		baseURL:    srv.URL,
		apiKey:     "key",
		userID:     "user",
		deviceName: "dev",
		client:     srv.Client(),
	}

	mapping := SyncMapping{
		PlaudAccountID:    "plaud-xyz",
		PlaudRecordingID:  "rec-999",
		ER1DocID:          "doc-456",
		ER1ContextID:      "ctx-789",
		RecordingTitle:    "Important Meeting",
		RecordingDuration: 3600,
		AudioFormat:       "ogg",
		AudioSizeBytes:    2048000,
		TranscriptLength:  15000,
	}

	err := client.RegisterMapping(mapping)
	if err != nil {
		t.Fatalf("RegisterMapping returned error: %v", err)
	}

	if gotMethod != "POST" {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotContentType)
	}
	if received.PlaudAccountID != "plaud-xyz" {
		t.Errorf("PlaudAccountID = %q, want 'plaud-xyz'", received.PlaudAccountID)
	}
	if received.PlaudRecordingID != "rec-999" {
		t.Errorf("PlaudRecordingID = %q, want 'rec-999'", received.PlaudRecordingID)
	}
	if received.ER1DocID != "doc-456" {
		t.Errorf("ER1DocID = %q, want 'doc-456'", received.ER1DocID)
	}
	if received.ER1ContextID != "ctx-789" {
		t.Errorf("ER1ContextID = %q, want 'ctx-789'", received.ER1ContextID)
	}
	if received.RecordingTitle != "Important Meeting" {
		t.Errorf("RecordingTitle = %q, want 'Important Meeting'", received.RecordingTitle)
	}
	if received.RecordingDuration != 3600 {
		t.Errorf("RecordingDuration = %d, want 3600", received.RecordingDuration)
	}
	if received.AudioFormat != "ogg" {
		t.Errorf("AudioFormat = %q, want 'ogg'", received.AudioFormat)
	}
	if received.AudioSizeBytes != 2048000 {
		t.Errorf("AudioSizeBytes = %d, want 2048000", received.AudioSizeBytes)
	}
	if received.TranscriptLength != 15000 {
		t.Errorf("TranscriptLength = %d, want 15000", received.TranscriptLength)
	}
}
