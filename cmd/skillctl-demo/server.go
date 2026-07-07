package main

// server.go — the P1 web mirror.
//
// A tiny embed.FS HTTP server on 127.0.0.1 that serves the scenario SVGs +
// competitor infographics (copied from skill-governance/) and a thin run-panel
// page. It live-bridges the driver's event stream over Server-Sent Events, so
// the browser shows the current scenario's SVG, a live terminal pane, and the
// exit-code badge — with no external hosts and no CDN (CSP-safe, offline).

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"time"
)

//go:embed web
var webFS embed.FS

// Server mirrors the bus to browsers.
type Server struct {
	bus      *Bus
	sandbox  *Sandbox
	skillctl string
	mode     string
}

func NewServer(bus *Bus, sb *Sandbox, skillctl, mode string) *Server {
	return &Server{bus: bus, sandbox: sb, skillctl: skillctl, mode: mode}
}

// Start binds 127.0.0.1 on the requested port (scanning upward if busy) and
// serves in a background goroutine. Returns the bound "host:port".
func (s *Server) Start(port int) (string, error) {
	var ln net.Listener
	var err error
	for p := port; p < port+25; p++ {
		ln, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err == nil {
			break
		}
	}
	if ln == nil {
		return "", fmt.Errorf("no free port in %d..%d: %w", port, port+25, err)
	}

	sub, _ := fs.Sub(webFS, "web")
	mux := http.NewServeMux()
	mux.Handle("/assets/", http.FileServer(http.FS(sub)))
	mux.HandleFunc("/events", s.handleEvents)
	mux.HandleFunc("/api/scenarios", s.handleScenarios)
	mux.HandleFunc("/api/state", s.handleState)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		b, err := webFS.ReadFile("web/run-panel.html")
		if err != nil {
			http.Error(w, "run-panel missing", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// Same-origin-only CSP: everything is inlined, so nothing external loads.
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'")
		_, _ = w.Write(b)
	})

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	return ln.Addr().String(), nil
}

// handleEvents streams the bus over SSE: replay history first (so a late browser
// catches up), then live events until the client disconnects.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch, history := s.bus.Subscribe()
	defer s.bus.Unsubscribe(ch)

	writeEvent := func(e Event) bool {
		b, _ := json.Marshal(e)
		if _, err := fmt.Fprintf(w, "data: %s\n\n", b); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}
	for _, e := range history {
		if !writeEvent(e) {
			return
		}
	}
	ctx := r.Context()
	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-ch:
			if !writeEvent(e) {
				return
			}
		case <-keepalive.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (s *Server) handleScenarios(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, Scenarios())
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"skillctl": s.skillctl,
		"home":     s.sandbox.Home,
		"mode":     s.mode,
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
