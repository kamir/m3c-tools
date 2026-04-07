package er1

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPairDevice_SendsCorrectPayload(t *testing.T) {
	var gotBody PairRequest
	var gotMethod, gotPath string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	err := PairDevice(context.Background(), server.URL, "test-key", PairRequest{
		DeviceType:    "m3c-desktop",
		DeviceID:      "test-host",
		DeviceName:    "test-host (m3c-tools)",
		ClientVersion: "1.0.0",
	})
	if err != nil {
		t.Fatalf("PairDevice failed: %v", err)
	}
	if gotMethod != "POST" {
		t.Errorf("Method = %q, want POST", gotMethod)
	}
	if gotPath != "/api/v2/devices/pair" {
		t.Errorf("Path = %q, want /api/v2/devices/pair", gotPath)
	}
	if gotBody.DeviceType != "m3c-desktop" {
		t.Errorf("DeviceType = %q, want m3c-desktop", gotBody.DeviceType)
	}
	if gotBody.DeviceID != "test-host" {
		t.Errorf("DeviceID = %q, want test-host", gotBody.DeviceID)
	}
	if gotBody.DeviceName != "test-host (m3c-tools)" {
		t.Errorf("DeviceName = %q, want test-host (m3c-tools)", gotBody.DeviceName)
	}
	if gotBody.ClientVersion != "1.0.0" {
		t.Errorf("ClientVersion = %q, want 1.0.0", gotBody.ClientVersion)
	}
}

func TestPairDevice_UsesAuth(t *testing.T) {
	t.Setenv("ER1_DEVICE_TOKEN", "test-bearer-token")

	var gotAuthHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	err := PairDevice(context.Background(), server.URL, "", PairRequest{
		DeviceType: "m3c-desktop",
		DeviceID:   "test-host",
	})
	if err != nil {
		t.Fatalf("PairDevice failed: %v", err)
	}
	if gotAuthHeader != "Bearer test-bearer-token" {
		t.Errorf("Authorization = %q, want 'Bearer test-bearer-token'", gotAuthHeader)
	}
}

func TestPairDevice_SetsUserID(t *testing.T) {
	t.Setenv("ER1_CONTEXT_ID", "107677460544181387647___mft")

	var gotUserID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserID = r.Header.Get("X-User-ID")
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	err := PairDevice(context.Background(), server.URL, "test-key", PairRequest{
		DeviceType: "m3c-desktop",
		DeviceID:   "test-host",
	})
	if err != nil {
		t.Fatalf("PairDevice failed: %v", err)
	}
	if gotUserID != "107677460544181387647" {
		t.Errorf("X-User-ID = %q, want 107677460544181387647", gotUserID)
	}
}

func TestDeviceHeartbeat_SendsCorrectPayload(t *testing.T) {
	var gotBody HeartbeatRequest
	var gotMethod, gotPath string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	err := DeviceHeartbeat(context.Background(), server.URL, "test-key", HeartbeatRequest{
		DeviceType:       "plaud",
		DeviceID:         "test-host",
		ItemsSyncedDelta: 5,
		LastItemID:       "doc123",
		ClientVersion:    "1.0.0",
	})
	if err != nil {
		t.Fatalf("DeviceHeartbeat failed: %v", err)
	}
	if gotMethod != "POST" {
		t.Errorf("Method = %q, want POST", gotMethod)
	}
	if gotPath != "/api/v2/devices/heartbeat" {
		t.Errorf("Path = %q, want /api/v2/devices/heartbeat", gotPath)
	}
	if gotBody.ItemsSyncedDelta != 5 {
		t.Errorf("ItemsSyncedDelta = %d, want 5", gotBody.ItemsSyncedDelta)
	}
	if gotBody.LastItemID != "doc123" {
		t.Errorf("LastItemID = %q, want doc123", gotBody.LastItemID)
	}
}

func TestListDevices_ParsesResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("Method = %q, want GET", r.Method)
		}
		if r.URL.Path != "/api/v2/devices" {
			t.Errorf("Path = %q, want /api/v2/devices", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[
			{"device_type":"m3c-desktop","device_name":"MacBook Pro","status":"active","items_synced":42,"last_sync_at":"2026-04-07T10:00:00Z"},
			{"device_type":"plaud","device_name":"Plaud.ai Recorder","status":"active","items_synced":10,"last_sync_at":"2026-04-07T09:30:00Z"}
		]`))
	}))
	defer server.Close()

	devices, err := ListDevices(context.Background(), server.URL, "test-key")
	if err != nil {
		t.Fatalf("ListDevices failed: %v", err)
	}
	if len(devices) != 2 {
		t.Fatalf("len(devices) = %d, want 2", len(devices))
	}
	if devices[0].DeviceType != "m3c-desktop" {
		t.Errorf("devices[0].DeviceType = %q, want m3c-desktop", devices[0].DeviceType)
	}
	if devices[0].ItemsSynced != 42 {
		t.Errorf("devices[0].ItemsSynced = %d, want 42", devices[0].ItemsSynced)
	}
	if devices[1].DeviceName != "Plaud.ai Recorder" {
		t.Errorf("devices[1].DeviceName = %q, want Plaud.ai Recorder", devices[1].DeviceName)
	}
}

func TestPairDevice_Idempotent(t *testing.T) {
	// Server returns 200 OK (already paired) — should not be an error.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	err := PairDevice(context.Background(), server.URL, "test-key", PairRequest{
		DeviceType: "m3c-desktop",
		DeviceID:   "test-host",
	})
	if err != nil {
		t.Errorf("PairDevice should succeed on 200 (idempotent), got: %v", err)
	}
}

func TestPairDevice_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	err := PairDevice(context.Background(), server.URL, "test-key", PairRequest{
		DeviceType: "m3c-desktop",
		DeviceID:   "test-host",
	})
	if err == nil {
		t.Error("PairDevice should return error on 500")
	}
}

func TestDeviceHeartbeat_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	err := DeviceHeartbeat(context.Background(), server.URL, "test-key", HeartbeatRequest{
		DeviceType:       "plaud",
		DeviceID:         "test-host",
		ItemsSyncedDelta: 1,
	})
	if err == nil {
		t.Error("DeviceHeartbeat should return error on 500")
	}
}

func TestListDevices_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal"}`))
	}))
	defer server.Close()

	_, err := ListDevices(context.Background(), server.URL, "test-key")
	if err == nil {
		t.Error("ListDevices should return error on 500")
	}
}

func TestBaseURLFromConfig(t *testing.T) {
	tests := []struct {
		apiURL string
		want   string
	}{
		{"https://onboarding.guide/upload_2", "https://onboarding.guide"},
		{"https://127.0.0.1:8081/upload_2", "https://127.0.0.1:8081"},
		{"https://example.com/prefix/upload_2", "https://example.com/prefix"},
		{"https://example.com", "https://example.com"},
	}
	for _, tt := range tests {
		cfg := &Config{APIURL: tt.apiURL}
		got := BaseURLFromConfig(cfg)
		if got != tt.want {
			t.Errorf("BaseURLFromConfig(%q) = %q, want %q", tt.apiURL, got, tt.want)
		}
	}
}

func TestApplyUserIDHeader_NoContextID(t *testing.T) {
	t.Setenv("ER1_CONTEXT_ID", "")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if uid := r.Header.Get("X-User-ID"); uid != "" {
			t.Errorf("X-User-ID should be empty when ER1_CONTEXT_ID is unset, got %q", uid)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	err := PairDevice(context.Background(), server.URL, "test-key", PairRequest{
		DeviceType: "m3c-desktop",
		DeviceID:   "test-host",
	})
	if err != nil {
		t.Fatalf("PairDevice failed: %v", err)
	}
}
