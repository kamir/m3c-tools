package config

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/setup"
)

//go:embed editor.html
var editorHTML []byte

// EditorServer serves the web-based profile settings UI.
type EditorServer struct {
	Addr      string // listen address, default ":9116"
	NoBrowser bool   // skip opening browser on start
	manager   *ProfileManager
}

// NewEditorServer creates an EditorServer with sensible defaults.
func NewEditorServer(addr string) *EditorServer {
	if addr == "" {
		addr = ":9116"
	}
	return &EditorServer{
		Addr:    addr,
		manager: NewProfileManager(),
	}
}

// Start initialises routes and starts the HTTP server. It opens the
// browser automatically unless NoBrowser is set. Blocks until shutdown.
func (s *EditorServer) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleUI)
	mux.HandleFunc("/api/profiles", s.handleProfiles)
	mux.HandleFunc("/api/profiles/", s.handleProfileByName)
	mux.HandleFunc("/api/validate/pocket-key", s.handleValidatePocketKey) // SPEC-0175 §3.3
	mux.HandleFunc("/api/health", s.handleHealth)

	host := s.Addr
	if strings.HasPrefix(host, ":") {
		host = "localhost" + host
	}
	url := "http://" + host

	fmt.Fprintf(os.Stderr, "m3c-tools settings editor listening on %s\n", url)

	if !s.NoBrowser {
		go func() {
			time.Sleep(200 * time.Millisecond)
			openEditorBrowser(url)
		}()
	}

	return http.ListenAndServe(s.Addr, mux)
}

// Handler returns the HTTP handler without starting a server, for testing.
func (s *EditorServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleUI)
	mux.HandleFunc("/api/profiles", s.handleProfiles)
	mux.HandleFunc("/api/profiles/", s.handleProfileByName)
	mux.HandleFunc("/api/validate/pocket-key", s.handleValidatePocketKey)
	mux.HandleFunc("/api/health", s.handleHealth)
	return mux
}

// handleValidatePocketKey delegates to setup.ValidatePocketKey and returns
// the structured verdict as JSON. SPEC-0175 §3.3: the UI renders the
// verdict as a green/red/yellow marker.
//
// Request:  {"key": "pk_...", "base_url": ""}
// Response: {"state": "valid|unauthorized|unreachable", "recording_count": N,
//            "human_message": "...", "detail": "..."}
func (s *EditorServer) handleValidatePocketKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Key     string `json:"key"`
		BaseURL string `json:"base_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	verdict := setup.ValidatePocketKey(nil, req.BaseURL, req.Key)
	resp := map[string]any{
		"state":           verdict.State,
		"recording_count": verdict.RecordingCount,
		"human_message":   verdict.HumanMessage,
		"detail":          verdict.Detail,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleUI serves the embedded HTML page.
func (s *EditorServer) handleUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(editorHTML)
}

// ── Profile list / create ──

type profileListResponse struct {
	Profiles []profileSummary `json:"profiles"`
	Active   string           `json:"active"`
}

type profileSummary struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	ER1URL      string `json:"er1_url"`
	IsActive    bool   `json:"is_active"`
}

type createProfileRequest struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Vars        map[string]string `json:"vars"`
}

func (s *EditorServer) handleProfiles(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listProfiles(w, r)
	case http.MethodPost:
		s.createProfile(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *EditorServer) listProfiles(w http.ResponseWriter, _ *http.Request) {
	profiles, err := s.manager.ListProfiles()
	if err != nil {
		jsonError(w, fmt.Sprintf("listing profiles: %v", err), http.StatusInternalServerError)
		return
	}

	active := s.manager.ActiveProfileName()
	resp := profileListResponse{
		Profiles: make([]profileSummary, len(profiles)),
		Active:   active,
	}
	for i, p := range profiles {
		resp.Profiles[i] = profileSummary{
			Name:        p.Name,
			Description: p.Description,
			ER1URL:      p.Vars["ER1_API_URL"],
			IsActive:    p.Name == active,
		}
	}

	jsonOK(w, resp)
}

func (s *EditorServer) createProfile(w http.ResponseWriter, r *http.Request) {
	var req createProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		jsonError(w, "name is required", http.StatusBadRequest)
		return
	}
	if req.Vars == nil {
		req.Vars = map[string]string{}
	}

	if err := s.manager.CreateProfile(req.Name, req.Description, req.Vars); err != nil {
		jsonError(w, fmt.Sprintf("creating profile: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	jsonOK(w, map[string]string{"status": "created", "name": req.Name})
}

// ── Single profile routes ──

type profileDetailResponse struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Vars        map[string]string `json:"vars"`
	IsActive    bool              `json:"is_active"`
}

type updateProfileRequest struct {
	Vars map[string]string `json:"vars"`
}

func (s *EditorServer) handleProfileByName(w http.ResponseWriter, r *http.Request) {
	// Route pattern: /api/profiles/{name}[/action]
	path := strings.TrimPrefix(r.URL.Path, "/api/profiles/")
	parts := strings.SplitN(path, "/", 2)
	name := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	if name == "" {
		http.Error(w, "profile name required", http.StatusBadRequest)
		return
	}

	switch {
	case action == "activate" && r.Method == http.MethodPost:
		s.activateProfile(w, name)
	case action == "test" && r.Method == http.MethodPost:
		s.testProfile(w, name)
	case action == "" && r.Method == http.MethodGet:
		s.getProfile(w, name)
	case action == "" && r.Method == http.MethodPut:
		s.updateProfile(w, r, name)
	case action == "" && r.Method == http.MethodDelete:
		s.deleteProfile(w, name)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *EditorServer) getProfile(w http.ResponseWriter, name string) {
	p, err := s.manager.GetProfile(name)
	if err != nil {
		jsonError(w, fmt.Sprintf("profile %q not found", name), http.StatusNotFound)
		return
	}

	active := s.manager.ActiveProfileName()

	// Mask the API key in the response for display, but also include the
	// real key so the editor can populate the password field.
	vars := make(map[string]string, len(p.Vars))
	for k, v := range p.Vars {
		vars[k] = v
	}

	jsonOK(w, profileDetailResponse{
		Name:        p.Name,
		Description: p.Description,
		Vars:        vars,
		IsActive:    p.Name == active,
	})
}

func (s *EditorServer) updateProfile(w http.ResponseWriter, r *http.Request, name string) {
	p, err := s.manager.GetProfile(name)
	if err != nil {
		jsonError(w, fmt.Sprintf("profile %q not found", name), http.StatusNotFound)
		return
	}

	var req updateProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	if req.Vars != nil {
		p.Vars = req.Vars
	}

	if err := s.manager.CreateProfile(name, p.Description, p.Vars); err != nil {
		jsonError(w, fmt.Sprintf("saving profile: %v", err), http.StatusInternalServerError)
		return
	}

	jsonOK(w, map[string]string{"status": "updated", "name": name})
}

func (s *EditorServer) deleteProfile(w http.ResponseWriter, name string) {
	if err := s.manager.DeleteProfile(name); err != nil {
		jsonError(w, err.Error(), http.StatusConflict)
		return
	}
	jsonOK(w, map[string]string{"status": "deleted", "name": name})
}

func (s *EditorServer) activateProfile(w http.ResponseWriter, name string) {
	if err := s.manager.SwitchProfile(name); err != nil {
		jsonError(w, fmt.Sprintf("activating profile: %v", err), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]string{"status": "activated", "name": name})
}

func (s *EditorServer) testProfile(w http.ResponseWriter, name string) {
	p, err := s.manager.GetProfile(name)
	if err != nil {
		jsonError(w, fmt.Sprintf("profile %q not found", name), http.StatusNotFound)
		return
	}

	if err := s.manager.TestConnection(p); err != nil {
		jsonOK(w, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}

	jsonOK(w, map[string]interface{}{"ok": true})
}

// handleHealth returns a simple health check response.
func (s *EditorServer) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok","service":"m3c-settings-editor"}`))
}

// ── Helpers ──

func jsonOK(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// openEditorBrowser opens the given URL in the default browser.
func openEditorBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		return
	}
	cmd.Start()
}
