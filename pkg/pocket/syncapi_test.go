package pocket

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// SPEC-0176 §3.4: mirror pkg/plaud/syncapi_test.go for the Pocket
// equivalent. Pins the wire contract with /api/pocket-sync/{check,map}.

func TestDeriveAccountID_Deterministic(t *testing.T) {
	key := "pk_test_pocket_token_abc123"
	id1 := DeriveAccountID(key)
	id2 := DeriveAccountID(key)
	if id1 != id2 {
		t.Errorf("DeriveAccountID not deterministic: %q != %q", id1, id2)
	}
	if id1 == "" {
		t.Error("DeriveAccountID returned empty string")
	}
	if len(id1) != len("pocket-")+16 {
		t.Errorf("DeriveAccountID unexpected length: got %d, want %d", len(id1), len("pocket-")+16)
	}
}

func TestDeriveAccountID_DifferentTokens(t *testing.T) {
	id1 := DeriveAccountID("pk_alpha")
	id2 := DeriveAccountID("pk_beta")
	if id1 == id2 {
		t.Errorf("DeriveAccountID returned same ID for different keys: %q", id1)
	}
}

func TestDeriveAccountID_HasPrefix(t *testing.T) {
	id := DeriveAccountID("pk_some_key")
	if id[:7] != "pocket-" {
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
		{"https://onboarding.guide/upload_2", "https://onboarding.guide"},
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
			"9bbc770f-f269-4054-a1d2-4d7770fb4089": {ER1DocID: "doc-abc", SyncedAt: "2026-04-27T18:48:38+00:00", SyncedFrom: "macbook"},
		},
		Unsynced: []string{"ac4e7b92-40ca-46c0-bafe-e70111c3dbd0", "19fdf806-40a4-4519-95aa-b5d81acf3acf"},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/pocket-sync/check" {
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
		if q.Get("pocket_account_id") != "pocket-abc" {
			t.Errorf("wrong pocket_account_id: %q", q.Get("pocket_account_id"))
		}
		ids := q.Get("recording_ids")
		want := "9bbc770f-f269-4054-a1d2-4d7770fb4089,ac4e7b92-40ca-46c0-bafe-e70111c3dbd0,19fdf806-40a4-4519-95aa-b5d81acf3acf"
		if ids != want {
			t.Errorf("wrong recording_ids: %q want %q", ids, want)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(expected)
	}))
	defer srv.Close()

	client := &SyncAPIClient{
		baseURL:    srv.URL,
		apiKey:     "test-key",
		userID:     "test-user",
		deviceName: "test-device",
		client:     srv.Client(),
	}

	result, err := client.CheckRecordings("pocket-abc", []string{
		"9bbc770f-f269-4054-a1d2-4d7770fb4089",
		"ac4e7b92-40ca-46c0-bafe-e70111c3dbd0",
		"19fdf806-40a4-4519-95aa-b5d81acf3acf",
	})
	if err != nil {
		t.Fatalf("CheckRecordings returned error: %v", err)
	}
	if result == nil {
		t.Fatal("CheckRecordings returned nil result")
	}
	if len(result.Synced) != 1 {
		t.Errorf("expected 1 synced, got %d", len(result.Synced))
	}
	if info, ok := result.Synced["9bbc770f-f269-4054-a1d2-4d7770fb4089"]; !ok {
		t.Error("expected UUID not in synced map")
	} else if info.ER1DocID != "doc-abc" {
		t.Errorf("wrong ER1DocID: %q", info.ER1DocID)
	}
	if len(result.Unsynced) != 2 {
		t.Errorf("expected 2 unsynced, got %d", len(result.Unsynced))
	}
}

func TestCheckRecordings_EmptyList(t *testing.T) {
	client := NewSyncAPIClient("https://127.0.0.1:8081/upload_2", "key", "user", true)
	result, err := client.CheckRecordings("pocket-abc", []string{})
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

	result, err := client.CheckRecordings("pocket-abc", []string{"rec-001"})
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

	result, err := client.CheckRecordings("pocket-abc", []string{"rec-001"})
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
		if r.URL.Path != "/api/pocket-sync/map" {
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
		_ = json.NewDecoder(r.Body).Decode(&received)
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
		PocketAccountID:   "pocket-abc",
		PocketRecordingID: "9bbc770f-f269-4054-a1d2-4d7770fb4089",
		ER1DocID:          "doc-xyz",
		ER1ContextID:      "ctx-123",
		RecordingTitle:    "Test Recording",
		RecordingDuration: 120,
		TranscriptLength:  500,
	}

	err := client.RegisterMapping(mapping)
	if err != nil {
		t.Fatalf("RegisterMapping returned error: %v", err)
	}
	if received.PocketRecordingID != "9bbc770f-f269-4054-a1d2-4d7770fb4089" {
		t.Errorf("server received wrong recording ID: %q", received.PocketRecordingID)
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

	err := client.RegisterMapping(SyncMapping{PocketRecordingID: "rec-001"})
	if err == nil {
		t.Error("expected error on server error, got nil")
	}
}

func TestCheckRecordings_NetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srvURL := srv.URL
	srv.Close()

	client := &SyncAPIClient{
		baseURL:    srvURL,
		apiKey:     "key",
		userID:     "user",
		deviceName: "dev",
		client:     &http.Client{},
	}

	result, err := client.CheckRecordings("pocket-abc", []string{"rec-001"})
	if err != nil {
		t.Errorf("expected nil error on network failure, got: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil result on network failure, got: %+v", result)
	}
}

func TestCheckRecordings_AuthUsesBearer(t *testing.T) {
	t.Setenv("ER1_DEVICE_TOKEN", "test-device-token-xyz")
	defer os.Unsetenv("ER1_DEVICE_TOKEN")

	var gotAuthHeader string
	var gotAPIKeyHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthHeader = r.Header.Get("Authorization")
		gotAPIKeyHeader = r.Header.Get("X-API-KEY")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(SyncCheckResult{
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

	result, err := client.CheckRecordings("pocket-abc", []string{"rec-001"})
	if err != nil {
		t.Fatalf("CheckRecordings returned error: %v", err)
	}
	if result == nil {
		t.Fatal("CheckRecordings returned nil result")
	}

	if gotAuthHeader != "Bearer test-device-token-xyz" {
		t.Errorf("Authorization header = %q, want 'Bearer test-device-token-xyz'", gotAuthHeader)
	}
	if gotAPIKeyHeader != "" {
		t.Errorf("X-API-KEY header = %q, want empty (Bearer takes priority)", gotAPIKeyHeader)
	}
}

func TestRegisterMapping_AuthUsesBearer(t *testing.T) {
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
		PocketAccountID:   "pocket-abc",
		PocketRecordingID: "rec-001",
		ER1DocID:          "doc-001",
	})
	if err != nil {
		t.Fatalf("RegisterMapping returned error: %v", err)
	}
	if gotAuthHeader != "Bearer mapping-bearer-token" {
		t.Errorf("Authorization = %q, want 'Bearer mapping-bearer-token'", gotAuthHeader)
	}
}

func TestRegisterMapping_NetworkError(t *testing.T) {
	client := &SyncAPIClient{
		baseURL:    "http://127.0.0.1:1",
		apiKey:     "key",
		userID:     "user",
		deviceName: "dev",
		client:     &http.Client{},
	}

	err := client.RegisterMapping(SyncMapping{PocketRecordingID: "rec-001"})
	if err == nil {
		t.Error("expected error on network failure, got nil")
	}
	if !strings.Contains(err.Error(), "unreachable") {
		t.Errorf("error should mention 'unreachable', got: %v", err)
	}
}

func TestCheckRecordings_VerifiesQueryParams(t *testing.T) {
	var gotPath string
	var gotAccountID string
	var gotRecordingIDs string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAccountID = r.URL.Query().Get("pocket_account_id")
		gotRecordingIDs = r.URL.Query().Get("recording_ids")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(SyncCheckResult{
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

	_, err := client.CheckRecordings("pocket-test-account", []string{"a", "b"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotPath != "/api/pocket-sync/check" {
		t.Errorf("path = %q, want /api/pocket-sync/check", gotPath)
	}
	if gotAccountID != "pocket-test-account" {
		t.Errorf("pocket_account_id = %q, want 'pocket-test-account'", gotAccountID)
	}
	if gotRecordingIDs != "a,b" {
		t.Errorf("recording_ids = %q, want 'a,b'", gotRecordingIDs)
	}
}

func TestRegisterMapping_VerifiesPOSTBody(t *testing.T) {
	var received SyncMapping
	var gotMethod string
	var gotContentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotContentType = r.Header.Get("Content-Type")
		_ = json.NewDecoder(r.Body).Decode(&received)
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
		PocketAccountID:   "pocket-xyz",
		PocketRecordingID: "9bbc770f-f269-4054-a1d2-4d7770fb4089",
		ER1DocID:          "doc-456",
		ER1ContextID:      "ctx-789",
		RecordingTitle:    "Important Meeting",
		RecordingDuration: 3600,
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
	if received.PocketAccountID != "pocket-xyz" {
		t.Errorf("PocketAccountID = %q, want 'pocket-xyz'", received.PocketAccountID)
	}
	if received.PocketRecordingID != "9bbc770f-f269-4054-a1d2-4d7770fb4089" {
		t.Errorf("PocketRecordingID = %q, want UUID", received.PocketRecordingID)
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
	if received.TranscriptLength != 15000 {
		t.Errorf("TranscriptLength = %d, want 15000", received.TranscriptLength)
	}
}
