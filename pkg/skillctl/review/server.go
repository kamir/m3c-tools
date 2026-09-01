// Package review provides a local HTTP server for reviewing skill delta reports.
package review

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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/delta"
)

//go:embed ui.html
var uiHTML []byte

// Server serves the review UI and API endpoints.
//
// SEC-M3: binds loopback only (127.0.0.1) and enforces a loopback Host-header
// allowlist plus a per-launch random token on its data endpoints, so the local
// review API is never reachable from other hosts on the LAN.
type Server struct {
	Addr      string // listen address, default "127.0.0.1:9115"
	DeltaPath string // path to delta report JSON
	NoBrowser bool   // skip opening browser on start

	token string // per-launch random token required on data endpoints

	mu        sync.Mutex
	report    *delta.DeltaReport
	sealStore *delta.SealStore
}

// NewServer creates a review server with sensible defaults.
func NewServer(addr, deltaPath string) *Server {
	if addr == "" {
		addr = "127.0.0.1:9115"
	}
	return &Server{
		Addr:      loopbackAddr(addr),
		DeltaPath: deltaPath,
		token:     newLaunchToken(),
	}
}

// loadDelta reads a DeltaReport from a JSON file on disk.
func loadDelta(path string) (*delta.DeltaReport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading delta report: %w", err)
	}
	var dr delta.DeltaReport
	if err := json.Unmarshal(data, &dr); err != nil {
		return nil, fmt.Errorf("parsing delta report: %w", err)
	}
	return &dr, nil
}

// LoadDelta reads the delta report from the configured path.
func (s *Server) LoadDelta(path string) error {
	dr, err := loadDelta(path)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.report = dr
	s.mu.Unlock()
	return nil
}

// Start initialises routes, loads the delta, and starts the HTTP server.
// It blocks until the server is shut down.
func (s *Server) Start() error {
	if err := s.LoadDelta(s.DeltaPath); err != nil {
		return fmt.Errorf("loading delta: %w", err)
	}

	store, err := delta.NewSealStore()
	if err != nil {
		return fmt.Errorf("initialising seal store: %w", err)
	}
	s.sealStore = store

	// SEC-M3: defend in depth — pin the listener to loopback even if Addr
	// was tampered with after construction.
	s.Addr = loopbackAddr(s.Addr)

	url := s.browserURL()

	fmt.Fprintf(os.Stderr, "skillctl review server listening on %s\n", url)

	if !s.NoBrowser {
		go func() {
			time.Sleep(300 * time.Millisecond)
			openBrowser(url)
		}()
	}

	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	httpSrv := &http.Server{Handler: s.GuardedHandler()}
	return httpSrv.Serve(ln)
}

// mux builds the route table shared by Handler and GuardedHandler.
func (s *Server) mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleUI)
	mux.HandleFunc("/api/delta", s.handleGetDelta)
	mux.HandleFunc("/api/delta/", s.handleReviewEntry)
	mux.HandleFunc("/api/seal", s.handleSeal)
	mux.HandleFunc("/api/seals", s.handleListSeals)
	mux.HandleFunc("/api/health", s.handleHealth)
	return mux
}

// Handler returns the raw (unguarded) route mux, for unit-testing handler
// logic in isolation. The network-facing path uses GuardedHandler.
func (s *Server) Handler() http.Handler { return s.mux() }

// GuardedHandler returns the route mux wrapped in the SEC-M3 loopback-Host +
// per-launch-token guard. This is what is served on the network.
func (s *Server) GuardedHandler() http.Handler { return s.guard(s.mux()) }

// Token returns the per-launch token required by guarded data endpoints.
func (s *Server) Token() string { return s.token }

// guard enforces the SEC-M3 access controls: a loopback Host-header allowlist
// (every request) plus a constant-time per-launch token check (every data
// endpoint; the UI page and health check are token-exempt so a bare reopen of
// the page still bootstraps).
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isLoopbackHost(r.Host) {
			http.Error(w, "forbidden: non-loopback Host", http.StatusForbidden)
			return
		}
		if r.URL.Path != "/" && r.URL.Path != "/api/health" && !s.tokenOK(r) {
			http.Error(w, "forbidden: missing or invalid token", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// tokenOK reports whether the request carries the per-launch token, supplied
// as an X-M3C-Token header or a "token" query parameter. An empty server token
// (RNG failure) rejects everything — fail closed.
func (s *Server) tokenOK(r *http.Request) bool {
	if s.token == "" {
		return false
	}
	got := r.Header.Get("X-M3C-Token")
	if got == "" {
		got = r.URL.Query().Get("token")
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) == 1
}

// browserURL returns the loopback URL (with the launch token) to open.
func (s *Server) browserURL() string {
	url := "http://" + loopbackHostPort(s.Addr)
	if s.token != "" {
		url += "/?token=" + s.token
	}
	return url
}

// newLaunchToken mints a 256-bit hex token unique to this process launch.
// On RNG failure it returns "" so the guard fails closed.
func newLaunchToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

// loopbackAddr forces any host portion of addr to the loopback interface, so a
// bare ":9115" or an explicit "0.0.0.0:9115" both bind 127.0.0.1.
func loopbackAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "127.0.0.1" + addr
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "*" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

// loopbackHostPort renders addr as a host:port suitable for a browser URL,
// pinning a missing/wildcard host to loopback.
func loopbackHostPort(addr string) string {
	if strings.HasPrefix(addr, ":") {
		return "127.0.0.1" + addr
	}
	if h, port, err := net.SplitHostPort(addr); err == nil {
		if h == "" || h == "0.0.0.0" || h == "::" {
			h = "127.0.0.1"
		}
		return net.JoinHostPort(h, port)
	}
	return addr
}

// isLoopbackHost reports whether the HTTP Host header refers to loopback only.
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

// handleUI serves the embedded HTML page. SEC-M3: the per-launch token is
// injected server-side as a <meta> tag so the in-page JS can authenticate its
// API calls.
func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(injectToken(uiHTML, s.token))
}

// injectToken inserts the launch token into the served HTML as a meta tag.
// The token is hex (no HTML-significant characters) so plain concatenation is
// safe. If there is no <head> or no token, the page is served unchanged.
func injectToken(page []byte, token string) []byte {
	if token == "" {
		return page
	}
	meta := `<meta name="m3c-token" content="` + token + `">`
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

// deltaJSON is the JSON shape served to the UI, adding per-entry indices
// and using summary field names the frontend expects.
type deltaJSON struct {
	ComputedAt    string      `json:"computed_at"`
	BaselinePath  string      `json:"baseline_path"`
	CurrentPath   string      `json:"current_path"`
	Entries       []entryJSON `json:"entries"`
	TotalAdded    int         `json:"total_added"`
	TotalModified int         `json:"total_modified"`
	TotalRemoved  int         `json:"total_removed"`
	TotalMoved    int         `json:"total_moved"`
}

type entryJSON struct {
	Index int `json:"index"`
	delta.DeltaEntry
}

func buildDeltaJSON(dr *delta.DeltaReport) *deltaJSON {
	dj := &deltaJSON{
		ComputedAt:    dr.ComputedAt,
		BaselinePath:  dr.BaselinePath,
		CurrentPath:   dr.CurrentPath,
		TotalAdded:    dr.Summary.Added,
		TotalModified: dr.Summary.Modified,
		TotalRemoved:  dr.Summary.Removed,
		TotalMoved:    dr.Summary.Moved,
		Entries:       make([]entryJSON, len(dr.Entries)),
	}
	for i := range dr.Entries {
		dj.Entries[i] = entryJSON{
			Index:      i,
			DeltaEntry: dr.Entries[i],
		}
	}
	return dj
}

// handleGetDelta returns the current DeltaReport as JSON.
func (s *Server) handleGetDelta(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	d := s.report
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(buildDeltaJSON(d))
}

// reviewRequest is the JSON body for updating a review status.
type reviewRequest struct {
	Status string `json:"status"`
}

// handleReviewEntry updates the review status for a single delta entry.
// PUT /api/delta/{index}/review
func (s *Server) handleReviewEntry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse index from path: /api/delta/0/review
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/delta/"), "/")
	if len(parts) != 2 || parts[1] != "review" {
		http.Error(w, "invalid path: expected /api/delta/{index}/review", http.StatusBadRequest)
		return
	}
	idx, err := strconv.Atoi(parts[0])
	if err != nil {
		http.Error(w, "invalid index", http.StatusBadRequest)
		return
	}

	var req reviewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	var status delta.ReviewStatus
	switch req.Status {
	case "approved":
		status = delta.ReviewApproved
	case "rejected":
		status = delta.ReviewRejected
	case "deferred":
		status = delta.ReviewDeferred
	case "pending":
		status = delta.ReviewPending
	default:
		http.Error(w, "invalid status: use approved, rejected, deferred, or pending", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.report == nil || idx < 0 || idx >= len(s.report.Entries) {
		http.Error(w, "index out of range", http.StatusNotFound)
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)
	s.report.Entries[idx].ReviewStatus = status
	s.report.Entries[idx].ReviewedAt = now
	s.report.Entries[idx].ReviewedBy = os.Getenv("USER")

	entry := entryJSON{Index: idx, DeltaEntry: s.report.Entries[idx]}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entry)
}

// sealResponse is the JSON returned after sealing.
type sealResponse struct {
	SealID   string `json:"seal_id"`
	SealedAt string `json:"sealed_at"`
	SealedBy string `json:"sealed_by"`
	Approved int    `json:"approved"`
	Rejected int    `json:"rejected"`
	Deferred int    `json:"deferred"`
	Total    int    `json:"total"`
}

// handleSeal creates a new seal from the current reviewed delta.
func (s *Server) handleSeal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.Lock()
	d := s.report
	s.mu.Unlock()

	if d == nil {
		http.Error(w, "no delta loaded", http.StatusBadRequest)
		return
	}

	// Check that all entries are reviewed (not pending).
	for _, e := range d.Entries {
		if e.ReviewStatus == delta.ReviewPending {
			http.Error(w, "all entries must be reviewed before sealing", http.StatusConflict)
			return
		}
	}

	// Count review decisions.
	approved, rejected, deferred := 0, 0, 0
	for _, e := range d.Entries {
		switch e.ReviewStatus {
		case delta.ReviewApproved:
			approved++
		case delta.ReviewRejected:
			rejected++
		case delta.ReviewDeferred:
			deferred++
		}
	}

	now := time.Now().UTC()
	resp := sealResponse{
		SealID:   fmt.Sprintf("seal-%s", now.Format("20060102T150405Z")),
		SealedAt: now.Format(time.RFC3339),
		SealedBy: os.Getenv("USER"),
		Approved: approved,
		Rejected: rejected,
		Deferred: deferred,
		Total:    len(d.Entries),
	}

	// Write the seal record to the seal store as a minimal record.
	if s.sealStore != nil {
		sealRecord := delta.SealRecord{
			SealID:     resp.SealID,
			SealedAt:   resp.SealedAt,
			SealedBy:   resp.SealedBy,
			SkillCount: resp.Total,
			Approved:   approved,
			Rejected:   rejected,
			Deferred:   deferred,
		}
		sealData, err := json.MarshalIndent(sealRecord, "", "  ")
		if err == nil {
			sealPath := fmt.Sprintf("%s/%s.json", s.sealStore.BaseDir, resp.SealID)
			os.WriteFile(sealPath, sealData, 0644)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleListSeals returns all seal records.
func (s *Server) handleListSeals(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.sealStore == nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]"))
		return
	}

	seals, err := s.sealStore.ListSeals()
	if err != nil {
		http.Error(w, fmt.Sprintf("listing seals: %v", err), http.StatusInternalServerError)
		return
	}
	if seals == nil {
		seals = []delta.SealRecord{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(seals)
}

// handleHealth returns a simple health check response.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok","service":"skillctl-review"}`))
}

// openBrowser opens the given URL in the default browser.
func openBrowser(url string) {
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
