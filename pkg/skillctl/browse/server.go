package browse

import (
	_ "embed"
	"encoding/json"
	"fmt"
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
type Server struct {
	Addr      string
	NoBrowser bool

	mu    sync.RWMutex
	graph *SkillGraph
	inv   *model.Inventory
}

// NewServer creates a browse server from a pre-built inventory.
func NewServer(addr string, inv *model.Inventory) *Server {
	if addr == "" {
		addr = ":9116"
	}
	graph := BuildGraph(inv)
	return &Server{
		Addr:  addr,
		graph: graph,
		inv:   inv,
	}
}

// Start registers routes and starts the HTTP server. Blocks until shutdown.
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleUI)
	mux.HandleFunc("/api/graph", s.handleGraph)
	mux.HandleFunc("/api/graph/filter", s.handleFilter)
	mux.HandleFunc("/api/graph/search", s.handleSearch)
	mux.HandleFunc("/api/health", s.handleHealth)

	host := s.Addr
	if strings.HasPrefix(host, ":") {
		host = "localhost" + host
	}
	url := "http://" + host

	fmt.Fprintf(os.Stderr, "skillctl browse server listening on %s\n", url)

	if !s.NoBrowser {
		go func() {
			time.Sleep(300 * time.Millisecond)
			openBrowserURL(url)
		}()
	}

	return http.ListenAndServe(s.Addr, mux)
}

func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(uiHTML)
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

// filterGraph returns a subgraph with only matching skill nodes and their connections.
func filterGraph(g *SkillGraph, projects, types, categories, tags []string) *SkillGraph {
	if len(projects) == 0 && len(types) == 0 && len(categories) == 0 && len(tags) == 0 {
		return g
	}

	// Determine which skill nodes pass the filter.
	keepSkills := make(map[string]bool)
	for _, n := range g.Nodes {
		if n.Kind != NodeSkill {
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
