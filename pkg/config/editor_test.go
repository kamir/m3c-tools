package config

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestServer(t *testing.T) *EditorServer {
	t.Helper()
	dir := t.TempDir()
	pm := &ProfileManager{BaseDir: dir}
	// Seed with a couple of profiles.
	if err := pm.CreateProfile("dev", "Local dev", map[string]string{
		"ER1_API_URL":    "https://localhost:8081/upload_2",
		"ER1_API_KEY":    "secret-key-1234567890",
		"ER1_CONTEXT_ID": "user123",
		"ER1_VERIFY_SSL": "false",
	}); err != nil {
		t.Fatal(err)
	}
	if err := pm.CreateProfile("cloud", "Cloud", map[string]string{
		"ER1_API_URL": "https://cloud.example.com/upload_2",
		"ER1_API_KEY": "cloud-key-abc",
	}); err != nil {
		t.Fatal(err)
	}
	if err := pm.writeActiveProfile("dev"); err != nil {
		t.Fatal(err)
	}

	srv := NewEditorServer(":0")
	srv.manager = pm
	srv.NoBrowser = true
	return srv
}

func TestGetHealth(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/health", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("GET /api/health = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "m3c-settings-editor") {
		t.Errorf("unexpected health body: %s", w.Body.String())
	}
}

func TestGetUI(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("GET / = %d, want 200", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	if !strings.Contains(w.Body.String(), "M3C Tools") {
		t.Error("HTML should contain 'M3C Tools'")
	}
}

func TestEditorListProfiles(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/profiles", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("GET /api/profiles = %d, want 200", w.Code)
	}

	var resp profileListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(resp.Profiles) != 2 {
		t.Fatalf("got %d profiles, want 2", len(resp.Profiles))
	}
	if resp.Active != "dev" {
		t.Errorf("active = %q, want %q", resp.Active, "dev")
	}

	names := map[string]bool{}
	for _, p := range resp.Profiles {
		names[p.Name] = true
	}
	if !names["dev"] || !names["cloud"] {
		t.Errorf("expected dev and cloud profiles, got %v", names)
	}
}

func TestEditorGetProfile(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/profiles/dev", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("GET /api/profiles/dev = %d, want 200", w.Code)
	}

	var resp profileDetailResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if resp.Name != "dev" {
		t.Errorf("name = %q, want %q", resp.Name, "dev")
	}
	if !resp.IsActive {
		t.Error("dev should be active")
	}
	if resp.Vars["ER1_API_URL"] != "https://localhost:8081/upload_2" {
		t.Errorf("ER1_API_URL = %q", resp.Vars["ER1_API_URL"])
	}
}

func TestGetProfileNotFound(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/profiles/nonexistent", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != 404 {
		t.Fatalf("GET /api/profiles/nonexistent = %d, want 404", w.Code)
	}
}

func TestEditorUpdateProfile(t *testing.T) {
	srv := newTestServer(t)
	body := `{"vars":{"ER1_API_URL":"https://new.example.com/upload_2","ER1_API_KEY":"newkey"}}`
	req := httptest.NewRequest("PUT", "/api/profiles/dev", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("PUT /api/profiles/dev = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	// Verify the update persisted.
	p, err := srv.manager.GetProfile("dev")
	if err != nil {
		t.Fatalf("GetProfile after update: %v", err)
	}
	if p.Vars["ER1_API_URL"] != "https://new.example.com/upload_2" {
		t.Errorf("ER1_API_URL = %q after update", p.Vars["ER1_API_URL"])
	}
	if p.Vars["ER1_API_KEY"] != "newkey" {
		t.Errorf("ER1_API_KEY = %q after update", p.Vars["ER1_API_KEY"])
	}
}

func TestEditorCreateProfile(t *testing.T) {
	srv := newTestServer(t)
	body := `{"name":"staging","description":"Staging env","vars":{"ER1_API_URL":"https://staging.example.com"}}`
	req := httptest.NewRequest("POST", "/api/profiles", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != 201 {
		t.Fatalf("POST /api/profiles = %d, want 201; body: %s", w.Code, w.Body.String())
	}

	// Verify it exists.
	p, err := srv.manager.GetProfile("staging")
	if err != nil {
		t.Fatalf("GetProfile staging: %v", err)
	}
	if p.Vars["ER1_API_URL"] != "https://staging.example.com" {
		t.Errorf("ER1_API_URL = %q", p.Vars["ER1_API_URL"])
	}
}

func TestEditorCreateProfileEmptyName(t *testing.T) {
	srv := newTestServer(t)
	body := `{"name":"","description":"No name"}`
	req := httptest.NewRequest("POST", "/api/profiles", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != 400 {
		t.Fatalf("POST /api/profiles (empty name) = %d, want 400", w.Code)
	}
}

func TestEditorDeleteProfile(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest("DELETE", "/api/profiles/cloud", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("DELETE /api/profiles/cloud = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	// Verify it is gone.
	_, err := srv.manager.GetProfile("cloud")
	if err == nil {
		t.Error("cloud profile should have been deleted")
	}
}

func TestEditorDeleteActiveProfile(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest("DELETE", "/api/profiles/dev", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	// Should fail because dev is the active profile.
	if w.Code != 409 {
		t.Fatalf("DELETE /api/profiles/dev = %d, want 409; body: %s", w.Code, w.Body.String())
	}
}

func TestEditorActivateProfile(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest("POST", "/api/profiles/cloud/activate", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("POST /api/profiles/cloud/activate = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	// Active profile should now be cloud.
	active := srv.manager.ActiveProfileName()
	if active != "cloud" {
		t.Errorf("active = %q, want %q", active, "cloud")
	}
}

func TestNotFoundRoute(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest("GET", "/nonexistent", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != 404 {
		t.Fatalf("GET /nonexistent = %d, want 404", w.Code)
	}
}
