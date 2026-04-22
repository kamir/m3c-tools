// Package api implements the Thinking Engine control surface per
// SPEC/api/thinking-engine-openapi.yaml. Routes are registered
// manually (no external router dep) so we keep build simple.
//
// HMAC bearer auth wraps everything except /v1/health.
// SSE for /v1/process/:id/events uses WHATWG EventSource format:
//
//	event: <name>\n
//	data: <json>\n
//	\n
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	mctx "github.com/kamir/m3c-tools/internal/thinking/ctx"
	tkafka "github.com/kamir/m3c-tools/internal/thinking/kafka"
	"github.com/kamir/m3c-tools/internal/thinking/orchestrator"
	"github.com/kamir/m3c-tools/internal/thinking/rebuild"
	"github.com/kamir/m3c-tools/internal/thinking/schema"
	"github.com/kamir/m3c-tools/internal/thinking/store"
)

// Config wires the API server.
type Config struct {
	OwnerRaw  mctx.Raw
	Hash      mctx.Hash
	Secret    []byte
	Bus       tkafka.Bus
	Orc       *orchestrator.Orchestrator
	Store     *store.Store
	BuildInfo string

	// Cache serves listings when non-nil. The Week 2 real cache
	// subscribes to T/R/I/A topics and maintains a windowed index;
	// tests can pass nil to fall back to empty-list behaviour.
	Cache *store.Cache

	// Rebuild wires the /v1/rebuild admin endpoint. Optional; when
	// nil the handler returns 501.
	Rebuild *rebuild.Service
}

// Server is the HTTP surface.
type Server struct {
	cfg     Config
	mux     *http.ServeMux
	handler http.Handler

	sseMu   sync.Mutex
	sseSubs map[string][]chan schema.ProcessEvent // processID → subscribers
}

// New builds the server. Call Handler() to mount it.
func New(cfg Config) *Server {
	s := &Server{
		cfg:     cfg,
		mux:     http.NewServeMux(),
		sseSubs: map[string][]chan schema.ProcessEvent{},
	}
	s.registerRoutes()

	// Subscribe to the engine's own event topic so we can fan out
	// to SSE subscribers.
	evtTopic := tkafka.TopicName(cfg.Hash, tkafka.TopicProcessEvents)
	_, err := cfg.Bus.Subscribe(evtTopic, func(ctx context.Context, m tkafka.Message) error {
		var ev schema.ProcessEvent
		if err := json.Unmarshal(m.Value, &ev); err != nil {
			return err
		}
		s.fanoutSSE(ev)
		return nil
	})
	if err != nil {
		// Not fatal for Week 1 — SSE will simply be empty.
		_ = err
	}

	bypass := map[string]bool{"/v1/health": true}
	auth := AuthMiddleware(cfg.Secret, cfg.OwnerRaw, bypass)
	s.handler = auth(s.mux)
	return s
}

// Handler returns the authenticated root handler.
func (s *Server) Handler() http.Handler { return s.handler }

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("/v1/health", s.health)
	s.mux.HandleFunc("/v1/process", s.createProcess)
	s.mux.HandleFunc("/v1/process/", s.processDispatch)
	s.mux.HandleFunc("/v1/thoughts", s.listThoughts)
	s.mux.HandleFunc("/v1/reflections", s.listReflections)
	s.mux.HandleFunc("/v1/insights", s.listInsights)
	s.mux.HandleFunc("/v1/artifacts", s.listArtifacts)
	s.mux.HandleFunc("/v1/trace/", s.trace)
	s.mux.HandleFunc("/v1/compile", s.compile)
	s.mux.HandleFunc("/v1/rebuild", s.rebuild)
	s.mux.HandleFunc("/v1/replay", s.replay) // 501
}

// ----- handlers -----

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "ok",
		"ctx":    s.cfg.Hash.Hex(),
		"kafka":  "up", // in-memory bus is always up in Week 1
		"er1":    "up",
		"build":  s.cfg.BuildInfo,
	})
}

func (s *Server) createProcess(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var spec schema.ProcessSpec
	if err := json.Unmarshal(body, &spec); err != nil {
		http.Error(w, "bad ProcessSpec: "+err.Error(), http.StatusBadRequest)
		return
	}
	if spec.SchemaVer == 0 {
		spec.SchemaVer = schema.CurrentSchemaVer
	}
	if err := s.cfg.Orc.Submit(r.Context(), spec); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"process_id": spec.ProcessID,
		"status":     "accepted",
	})
}

// processDispatch matches:
//   GET  /v1/process/{id}
//   GET  /v1/process/{id}/events
//   POST /v1/process/{id}/cancel
func (s *Server) processDispatch(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/process/")
	path = strings.Trim(path, "/")
	if path == "" {
		http.NotFound(w, r)
		return
	}
	parts := strings.SplitN(path, "/", 2)
	id := parts[0]
	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.getProcess(w, r, id)
		return
	}
	switch parts[1] {
	case "events":
		s.sseEvents(w, r, id)
	case "cancel":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := s.cfg.Orc.Cancel(r.Context(), id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) getProcess(w http.ResponseWriter, r *http.Request, id string) {
	row, err := s.cfg.Store.GetProcess(id)
	if err != nil {
		http.Error(w, "process not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"process_id":   row.ProcessID,
		"state":        string(row.State),
		"current_step": row.CurrentStep,
		"artifact_ids": row.ArtifactIDs,
	})
}

func (s *Server) sseEvents(w http.ResponseWriter, r *http.Request, id string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan schema.ProcessEvent, 32)
	s.addSSE(id, ch)
	defer s.removeSSE(id, ch)

	// initial hello comment keeps the connection open on slow starts.
	fmt.Fprintf(w, ": connected ctx=%s\n\n", s.cfg.Hash.Hex())
	flusher.Flush()

	keep := time.NewTicker(15 * time.Second)
	defer keep.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-keep.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		case ev := <-ch:
			b, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: %s\n", ev.Event)
			fmt.Fprintf(w, "data: %s\n\n", string(b))
			flusher.Flush()
		}
	}
}

func (s *Server) trace(w http.ResponseWriter, r *http.Request) {
	artifactID := strings.TrimPrefix(r.URL.Path, "/v1/trace/")
	artifactID = strings.Trim(artifactID, "/")
	if artifactID == "" {
		http.NotFound(w, r)
		return
	}
	if s.cfg.Cache == nil {
		http.Error(w, "trace unavailable — cache not wired", http.StatusServiceUnavailable)
		return
	}
	tree, ok := buildTrace(s.cfg.Cache, artifactID)
	if !ok {
		http.Error(w, "artifact not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, tree)
}

func (s *Server) compile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"compilation_id": "stub-c-0001",
	})
}

func (s *Server) rebuild(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.cfg.Rebuild == nil {
		http.Error(w, "rebuild service not configured", http.StatusNotImplemented)
		return
	}
	if !rebuild.TryBegin(s.cfg.Rebuild) {
		http.Error(w, "rebuild already in progress", http.StatusTooManyRequests)
		return
	}
	defer rebuild.End(s.cfg.Rebuild)

	res, err := s.cfg.Rebuild.Run(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusAccepted, res)
}

func (s *Server) replay(w http.ResponseWriter, r *http.Request) {
	// Phase 2 — see SPEC-0167 D5.
	http.Error(w, "replay not implemented in Phase 1", http.StatusNotImplemented)
}

// ----- listing endpoints (Week 2) -----

func (s *Server) listThoughts(w http.ResponseWriter, r *http.Request) {
	s.listLayer(w, r, "T", "")
}

func (s *Server) listReflections(w http.ResponseWriter, r *http.Request) {
	// thought_id filter maps to the R.thought_ids parent index.
	parent := r.URL.Query().Get("thought_id")
	s.listLayer(w, r, "R", parent)
}

func (s *Server) listInsights(w http.ResponseWriter, r *http.Request) {
	// reflection_id or thought_id filter maps to I.input_ids.
	parent := r.URL.Query().Get("reflection_id")
	if parent == "" {
		parent = r.URL.Query().Get("thought_id")
	}
	s.listLayer(w, r, "I", parent)
}

func (s *Server) listArtifacts(w http.ResponseWriter, r *http.Request) {
	// insight_id filter maps to A.insight_ids.
	parent := r.URL.Query().Get("insight_id")
	s.listLayer(w, r, "A", parent)
}

func (s *Server) listLayer(w http.ResponseWriter, r *http.Request, layer, parentID string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.cfg.Cache == nil {
		writeJSON(w, http.StatusOK, []interface{}{})
		return
	}
	var since time.Time
	if s := r.URL.Query().Get("since"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			since = t
		}
	}
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		// best-effort parse; invalid values fall back to default
		var n int
		_, err := fmt.Sscanf(l, "%d", &n)
		if err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	rows := s.cfg.Cache.List(layer, since, parentID, limit)
	// Respond as a JSON array of raw objects.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("["))
	for i, row := range rows {
		if i > 0 {
			_, _ = w.Write([]byte(","))
		}
		_, _ = w.Write(row)
	}
	_, _ = w.Write([]byte("]"))
}

// ----- SSE fanout -----

func (s *Server) addSSE(id string, ch chan schema.ProcessEvent) {
	s.sseMu.Lock()
	defer s.sseMu.Unlock()
	s.sseSubs[id] = append(s.sseSubs[id], ch)
}

func (s *Server) removeSSE(id string, ch chan schema.ProcessEvent) {
	s.sseMu.Lock()
	defer s.sseMu.Unlock()
	rest := s.sseSubs[id][:0]
	for _, c := range s.sseSubs[id] {
		if c != ch {
			rest = append(rest, c)
		}
	}
	s.sseSubs[id] = rest
	close(ch)
}

func (s *Server) fanoutSSE(ev schema.ProcessEvent) {
	s.sseMu.Lock()
	subs := append([]chan schema.ProcessEvent(nil), s.sseSubs[ev.ProcessID]...)
	s.sseMu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- ev:
		default: // slow consumer — drop
		}
	}
}

// ----- helpers -----

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
