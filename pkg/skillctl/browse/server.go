package browse

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
	"sync"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/model"
)

//go:embed ui.html
var uiHTML []byte

// Server serves the skill graph browser UI and API.
//
// SEC-M3: binds loopback only (127.0.0.1) and enforces a loopback Host-header
// allowlist plus a per-launch random token on its data endpoints, so the local
// browse API is never reachable from other hosts on the LAN.
type Server struct {
	Addr      string
	NoBrowser bool

	token string // per-launch random token required on data endpoints

	mu    sync.RWMutex
	graph *SkillGraph
	inv   *model.Inventory
	store *GraphStore
	hash  string // current inventory hash for rebuild staleness check
}

// NewServer creates a browse server from a pre-built inventory.
func NewServer(addr string, inv *model.Inventory) *Server {
	if addr == "" {
		addr = "127.0.0.1:9116"
	}
	graph := BuildGraph(inv)
	return &Server{
		Addr:  loopbackAddr(addr),
		token: newLaunchToken(),
		graph: graph,
		inv:   inv,
	}
}

// NewServerWithCache creates a browse server using a pre-loaded graph and
// an open GraphStore. The store is used by the /api/graph/rebuild endpoint
// to persist refreshed graphs.
func NewServerWithCache(addr string, inv *model.Inventory, graph *SkillGraph, store *GraphStore, inventoryHash string) *Server {
	if addr == "" {
		addr = "127.0.0.1:9116"
	}
	return &Server{
		Addr:  loopbackAddr(addr),
		token: newLaunchToken(),
		graph: graph,
		inv:   inv,
		store: store,
		hash:  inventoryHash,
	}
}

// Start registers routes and starts the HTTP server. Binds loopback only
// (SEC-M3). Blocks until shutdown.
func (s *Server) Start() error {
	// SEC-M3: defend in depth — pin the listener to loopback even if Addr
	// was tampered with after construction.
	s.Addr = loopbackAddr(s.Addr)

	url := s.browserURL()

	fmt.Fprintf(os.Stderr, "skillctl browse server listening on %s\n", url)

	if !s.NoBrowser {
		go func() {
			time.Sleep(300 * time.Millisecond)
			openBrowserURL(url)
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
	mux.HandleFunc("/api/graph", s.handleGraph)
	mux.HandleFunc("/api/graph/filter", s.handleFilter)
	mux.HandleFunc("/api/graph/search", s.handleSearch)
	mux.HandleFunc("/api/graph/rebuild", s.handleRebuild)
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
// bare ":9116" or an explicit "0.0.0.0:9116" both bind 127.0.0.1.
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

// loopbackHostPort renders addr as a host:port for a browser URL, pinning a
// missing/wildcard host to loopback.
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

func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(injectToken(uiHTML, s.token))
}

func (s *Server) handleGraph(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.RLock()
	g := s.graph
	s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(g)
}

func (s *Server) handleFilter(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	projects := splitParam(q.Get("project"))
	types := splitParam(q.Get("type"))
	categories := splitParam(q.Get("category"))
	tags := splitParam(q.Get("tag"))

	s.mu.RLock()
	g := s.graph
	s.mu.RUnlock()

	filtered := filterGraph(g, projects, types, categories, tags)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(filtered)
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	if query == "" {
		http.Error(w, "missing q parameter", http.StatusBadRequest)
		return
	}

	s.mu.RLock()
	g := s.graph
	s.mu.RUnlock()

	var matches []Node
	for _, n := range g.Nodes {
		if strings.Contains(strings.ToLower(n.Label), query) ||
			strings.Contains(strings.ToLower(n.Description), query) {
			matches = append(matches, n)
		}
	}
	if matches == nil {
		matches = []Node{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(matches)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok","service":"skillctl-browse"}`))
}

func (s *Server) handleRebuild(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	inv := s.inv
	s.mu.RUnlock()

	if inv == nil {
		http.Error(w, "no inventory loaded", http.StatusInternalServerError)
		return
	}

	graph := BuildGraph(inv)

	s.mu.Lock()
	s.graph = graph
	s.mu.Unlock()

	// Persist to SQLite if a store is available.
	if s.store != nil && s.hash != "" {
		if err := s.store.SaveGraphWithHash(graph, s.hash); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to persist rebuilt graph: %v\n", err)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "rebuilt",
		"node_count": len(graph.Nodes),
		"edge_count": len(graph.Edges),
	})
}

// filterGraph returns a subgraph with only matching skill nodes and their connections.
func filterGraph(g *SkillGraph, projects, types, categories, tags []string) *SkillGraph {
	if len(projects) == 0 && len(types) == 0 && len(categories) == 0 && len(tags) == 0 {
		return g
	}

	// Determine which content nodes pass the filter.
	keepSkills := make(map[string]bool)
	for _, n := range g.Nodes {
		if !n.Kind.IsContentNode() {
			continue
		}
		if len(projects) > 0 && !contains(projects, n.Project) {
			continue
		}
		if len(types) > 0 && !contains(types, n.SkillType) {
			continue
		}
		if len(categories) > 0 && !contains(categories, n.Category) {
			continue
		}
		if len(tags) > 0 && !hasAny(tags, n.Tags) {
			continue
		}
		keepSkills[n.ID] = true
	}

	// Collect all nodes reachable from kept skills via edges.
	keepNodes := make(map[string]bool)
	for id := range keepSkills {
		keepNodes[id] = true
	}
	var edges []Edge
	for _, e := range g.Edges {
		if keepSkills[e.Source] || keepSkills[e.Target] {
			keepNodes[e.Source] = true
			keepNodes[e.Target] = true
			edges = append(edges, e)
		}
	}

	var nodes []Node
	for _, n := range g.Nodes {
		if keepNodes[n.ID] {
			nodes = append(nodes, n)
		}
	}
	if nodes == nil {
		nodes = []Node{}
	}
	if edges == nil {
		edges = []Edge{}
	}

	fg := &SkillGraph{
		Nodes:      nodes,
		Edges:      edges,
		Projects:   g.Projects,
		Categories: g.Categories,
		Tags:       g.Tags,
		SkillTypes: g.SkillTypes,
	}
	for _, n := range nodes {
		fg.Stats.TotalNodes++
		switch n.Kind {
		case NodeSkill:
			fg.Stats.SkillNodes++
		case NodeProject:
			fg.Stats.ProjectNodes++
		case NodeCategory:
			fg.Stats.CategoryNodes++
		case NodeTag:
			fg.Stats.TagNodes++
		}
	}
	fg.Stats.TotalEdges = len(edges)
	return fg
}

func splitParam(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func contains(list []string, val string) bool {
	for _, v := range list {
		if v == val {
			return true
		}
	}
	return false
}

func hasAny(needles []string, haystack []string) bool {
	for _, n := range needles {
		for _, h := range haystack {
			if n == h {
				return true
			}
		}
	}
	return false
}

func openBrowserURL(url string) {
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
