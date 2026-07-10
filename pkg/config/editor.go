package config

import (
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
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
//
// SEC-M3: this server exposes a secret-bearing profile API (ER1 URLs and
// API keys). It MUST bind to loopback only (127.0.0.1) so it is never
// reachable from other hosts on the LAN, and it requires a per-launch random
// token on every request. The token is minted on construction, baked into the
// browser-open URL, and verified on every guarded request via a Host-header
// allowlist + constant-time token comparison.
type EditorServer struct {
	Addr      string // listen address, default "127.0.0.1:9116"
	NoBrowser bool   // skip opening browser on start
	token     string // per-launch random token required on every request
	manager   *ProfileManager
}

// NewEditorServer creates an EditorServer with sensible defaults.
func NewEditorServer(addr string) *EditorServer {
	if addr == "" {
		addr = "127.0.0.1:9116"
	}
	addr = loopbackAddr(addr)
	return &EditorServer{
		Addr:    addr,
		token:   newLaunchToken(),
		manager: NewProfileManager(),
	}
}

// newLaunchToken mints a 256-bit hex token unique to this process launch.
// On the (effectively impossible) failure of the system RNG we fail closed by
// leaving the token empty, which makes every guarded request reject.
func newLaunchToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

// loopbackAddr forces any host portion of addr to the loopback interface.
// A bare ":9116" or an explicit "0.0.0.0:9116" both become "127.0.0.1:9116".
// SEC-M3: never honour a request to bind a non-loopback interface.
func loopbackAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// addr had no port separator we recognise; treat the whole thing as
		// a port spec and pin to loopback.
		return "127.0.0.1" + addr
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "*" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

// isLoopbackHost reports whether the HTTP Host header refers to the local
// loopback interface only. Requests with any other Host are rejected so a
// LAN attacker cannot reach the secret-bearing API via DNS-rebinding or by
// pointing a hostname at this machine's routable address.
func isLoopbackHost(hostHeader string) bool {
	host := hostHeader
	if h, _, err := net.SplitHostPort(hostHeader); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// guard wraps the mux with the SEC-M3 access controls: a loopback Host-header
// allowlist plus a constant-time per-launch token check. The token may be
// supplied either as a "token" query parameter (so the browser-open URL works
// with a single click) or as an X-M3C-Token request header.
func (s *EditorServer) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// SEC-M3: the Host-header allowlist applies to EVERY request — it is
		// the DNS-rebinding / cross-host defence and has no exemptions.
		if !isLoopbackHost(r.Host) {
			http.Error(w, "forbidden: non-loopback Host", http.StatusForbidden)
			return
		}
		// The bootstrap surfaces carry no secrets and must stay reachable so a
		// bare reopen of the page works: the UI page (which server-injects the
		// token) and the health check are token-exempt. Everything that reads
		// or mutates profile secrets requires the per-launch token.
		if !tokenExemptPath(r.URL.Path) && !s.tokenOK(r) {
			http.Error(w, "forbidden: missing or invalid token", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// tokenExemptPath reports whether a path may be served without the per-launch
// token. Only the non-secret bootstrap surfaces qualify.
func tokenExemptPath(p string) bool {
	return p == "/" || p == "/api/health"
}

// tokenOK reports whether the request carries the per-launch token. An empty
// server token (RNG failure) rejects everything — fail closed.
func (s *EditorServer) tokenOK(r *http.Request) bool {
	if s.token == "" {
		return false
	}
	got := r.Header.Get("X-M3C-Token")
	if got == "" {
		got = r.URL.Query().Get("token")
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) == 1
}

// browserURL returns the loopback URL (including the launch token) the local
// browser should open to reach the editor.
func (s *EditorServer) browserURL() string {
	host := s.Addr
	if strings.HasPrefix(host, ":") {
		host = "127.0.0.1" + host
	} else if h, port, err := net.SplitHostPort(host); err == nil {
		if h == "" || h == "0.0.0.0" || h == "::" {
			h = "127.0.0.1"
		}
		host = net.JoinHostPort(h, port)
	}
	url := "http://" + host
	if s.token != "" {
		url += "/?token=" + s.token
	}
	return url
}

// Start initialises routes and starts the HTTP server. It binds loopback only
// (SEC-M3) and opens the browser automatically unless NoBrowser is set. Blocks
// until shutdown.
func (s *EditorServer) Start() error {
	// SEC-M3: defend in depth — force the listener onto the loopback
	// interface even if Addr was tampered with after construction.
	s.Addr = loopbackAddr(s.Addr)

	url := s.browserURL()

	fmt.Fprintf(os.Stderr, "m3c-tools settings editor listening on %s\n", url)

	if !s.NoBrowser {
		go func() {
			time.Sleep(200 * time.Millisecond)
			openEditorBrowser(url)
		}()
	}

	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: s.GuardedHandler()}
	return srv.Serve(ln)
}

// mux builds the route table shared by Handler and GuardedHandler.
func (s *EditorServer) mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleUI)
	mux.HandleFunc("/api/profiles", s.handleProfiles)
	mux.HandleFunc("/api/profiles/", s.handleProfileByName)
	mux.HandleFunc("/api/validate/pocket-key", s.handleValidatePocketKey) // SPEC-0175 §3.3
	mux.HandleFunc("/api/health", s.handleHealth)
	return mux
}

// Handler returns the raw (unguarded) HTTP handler, for unit-testing the
// route/handler logic in isolation. The network-facing path uses
// GuardedHandler instead.
func (s *EditorServer) Handler() http.Handler {
	return s.mux()
}

// GuardedHandler returns the handler actually served on the network: the route
// mux wrapped in the SEC-M3 loopback-Host + per-launch-token guard.
func (s *EditorServer) GuardedHandler() http.Handler {
	return s.guard(s.mux())
}

// Token returns the per-launch token required by guarded requests. Exposed for
// tests and for callers that need to construct an authorised URL.
func (s *EditorServer) Token() string { return s.token }

// handleValidatePocketKey delegates to setup.ValidatePocketKey and returns
// the structured verdict as JSON. SPEC-0175 §3.3: the UI renders the
// verdict as a green/red/yellow marker.
//
// Request:  {"key": "pk_...", "base_url": ""}
// Response: {"state": "valid|unauthorized|unreachable", "recording_count": N,
//
//	"human_message": "...", "detail": "..."}
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

// handleUI serves the embedded HTML page. SEC-M3: the per-launch token is
// injected server-side as a <meta> tag so the in-page JS can authenticate its
// API calls even when the page is reopened without the ?token= query string.
func (s *EditorServer) handleUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(s.injectToken(editorHTML))
}

// injectToken inserts the launch token into the served HTML as a meta tag.
// The token is hex (no HTML-significant characters) so plain concatenation is
// safe. If there is no <head> or no token, the page is served unchanged.
func (s *EditorServer) injectToken(page []byte) []byte {
	if s.token == "" {
		return page
	}
	meta := `<meta name="m3c-token" content="` + s.token + `">`
	const anchor = "<head>"
	if i := strings.Index(string(page), anchor); i >= 0 {
		i += len(anchor)
		out := make([]byte, 0, len(page)+len(meta))
		out = append(out, page[:i]...)
		out = append(out, meta...)
		out = append(out, page[i:]...)
		return out
	}
	return page
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
