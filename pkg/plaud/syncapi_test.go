package plaud

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
		http.Error(w, "unauthorized", 401)
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
