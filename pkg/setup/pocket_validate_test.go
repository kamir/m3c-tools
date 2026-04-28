package setup

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidatePocketKey_Valid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/public/recordings" {
			http.Error(w, "not found", 404)
			return
		}
		if r.Header.Get("Authorization") != "Bearer pk_good" {
			t.Errorf("missing/wrong Authorization header: %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":[],"pagination":{"total":42}}`))
	}))
	defer srv.Close()

	v := ValidatePocketKey(srv.Client(), srv.URL, "pk_good")
	if !v.IsValid() {
		t.Fatalf("expected valid, got %+v", v)
	}
	if v.RecordingCount != 42 {
		t.Errorf("RecordingCount = %d, want 42", v.RecordingCount)
	}
	if !strings.Contains(v.HumanMessage, "42 recordings") {
		t.Errorf("HumanMessage = %q, want it to mention 42 recordings", v.HumanMessage)
	}
}

func TestValidatePocketKey_OneRecordingPlural(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":[],"pagination":{"total":1}}`))
	}))
	defer srv.Close()
	v := ValidatePocketKey(srv.Client(), srv.URL, "pk_x")
	if !strings.Contains(v.HumanMessage, "1 recording on") {
		t.Errorf("singular form wrong: %q", v.HumanMessage)
	}
}

func TestValidatePocketKey_ZeroRecordings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":[]}`))
	}))
	defer srv.Close()
	v := ValidatePocketKey(srv.Client(), srv.URL, "pk_x")
	if !v.IsValid() {
		t.Fatalf("expected valid, got %+v", v)
	}
	if v.RecordingCount != 0 {
		t.Errorf("RecordingCount = %d, want 0", v.RecordingCount)
	}
	if !strings.Contains(v.HumanMessage, "0 recordings") {
		t.Errorf("HumanMessage = %q", v.HumanMessage)
	}
}

func TestValidatePocketKey_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", 401)
	}))
	defer srv.Close()
	v := ValidatePocketKey(srv.Client(), srv.URL, "pk_bad")
	if v.State != "unauthorized" {
		t.Errorf("state = %q, want unauthorized", v.State)
	}
	if !strings.Contains(v.HumanMessage, "rejected") {
		t.Errorf("HumanMessage should say 'rejected', got %q", v.HumanMessage)
	}
	if !strings.Contains(v.HumanMessage, "app.heypocket.com") {
		t.Error("HumanMessage should point to the key-management URL")
	}
}

func TestValidatePocketKey_Forbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", 403)
	}))
	defer srv.Close()
	v := ValidatePocketKey(srv.Client(), srv.URL, "pk_x")
	if v.State != "unauthorized" {
		t.Errorf("403 should map to unauthorized, got %q", v.State)
	}
}

func TestValidatePocketKey_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", 500)
	}))
	defer srv.Close()
	v := ValidatePocketKey(srv.Client(), srv.URL, "pk_x")
	if v.State != "unreachable" {
		t.Errorf("500 should map to unreachable, got %q", v.State)
	}
}

func TestValidatePocketKey_NetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()
	v := ValidatePocketKey(&http.Client{}, url, "pk_x")
	if v.State != "unreachable" {
		t.Errorf("closed server should map to unreachable, got %q", v.State)
	}
	if !strings.Contains(v.HumanMessage, "Couldn't reach Pocket") {
		t.Errorf("HumanMessage = %q", v.HumanMessage)
	}
}

func TestValidatePocketKey_EmptyKey(t *testing.T) {
	v := ValidatePocketKey(nil, "", "")
	if v.State != "unauthorized" {
		t.Errorf("empty key should map to unauthorized, got %q", v.State)
	}
	if !strings.Contains(v.HumanMessage, "Empty API key") {
		t.Errorf("HumanMessage = %q", v.HumanMessage)
	}
}

func TestValidatePocketKey_KeyIsTrimmed(t *testing.T) {
	var receivedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":[],"pagination":{"total":3}}`))
	}))
	defer srv.Close()

	v := ValidatePocketKey(srv.Client(), srv.URL, "  pk_padded  \n")
	if !v.IsValid() {
		t.Fatalf("expected valid, got %+v", v)
	}
	if receivedAuth != "Bearer pk_padded" {
		t.Errorf("Authorization = %q, want trimmed 'Bearer pk_padded'", receivedAuth)
	}
}

func TestValidatePocketKey_DefaultURLWhenEmpty(t *testing.T) {
	// Non-functional test — just verifies that an empty baseURL doesn't crash.
	// Hits the real default URL, which will fail with network/DNS in CI but
	// must classify as "unreachable" not panic.
	v := ValidatePocketKey(&http.Client{Timeout: 1}, "", "pk_x")
	if v.State != "unreachable" && v.State != "valid" && v.State != "unauthorized" {
		t.Errorf("unexpected state %q", v.State)
	}
}

func TestValidatePocketKey_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`<<not json>>`))
	}))
	defer srv.Close()
	v := ValidatePocketKey(srv.Client(), srv.URL, "pk_x")
	if v.State != "unreachable" {
		t.Errorf("malformed body should map to unreachable, got %q", v.State)
	}
}

func TestValidatePocketKey_SuccessFalseEnvelope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":false,"error":"key revoked"}`))
	}))
	defer srv.Close()
	v := ValidatePocketKey(srv.Client(), srv.URL, "pk_x")
	if v.State != "unauthorized" {
		t.Errorf("success=false envelope should map to unauthorized, got %q", v.State)
	}
}
