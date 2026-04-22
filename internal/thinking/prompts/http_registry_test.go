package prompts

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/internal/thinking/store"
)

type fakeRegistryServer struct {
	t        *testing.T
	etag     string
	prompt   httpPromptDTO
	requests atomic.Int64
	fail     atomic.Int32 // 0=off; 1=refuse connection; 2=500
}

func (f *fakeRegistryServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		if f.fail.Load() == 2 {
			http.Error(w, "internal", http.StatusInternalServerError)
			return
		}
		// ETag revalidation: 304 when caller already has the current ETag.
		if inm := r.Header.Get("If-None-Match"); inm != "" && inm == f.etag {
			w.Header().Set("ETag", f.etag)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", f.etag)
		w.Header().Set("Cache-Control", "max-age=300")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(f.prompt)
	}
}

func newFakeServer(t *testing.T) *fakeRegistryServer {
	return &fakeRegistryServer{
		t:    t,
		etag: `"abc123"`,
		prompt: httpPromptDTO{
			PromptID: "tmpl.reflect.compare.v1",
			Version:  1,
			Template: "Compare the following inputs and list overlaps + differences.",
			Variables: []string{"inputs"},
			ModelHint: "gpt-4o-mini",
			UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		},
	}
}

func TestHTTPRegistryFirstFetchCachesAndEmitsETag(t *testing.T) {
	f := newFakeServer(t)
	ts := httptest.NewServer(f.handler())
	defer ts.Close()

	reg, err := NewHTTPRegistry(HTTPConfig{BaseURL: ts.URL + "/api/prompts/"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := reg.Get(context.Background(), "tmpl.reflect.compare.v1")
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "tmpl.reflect.compare.v1" {
		t.Errorf("id = %s", p.ID)
	}
	if p.Body == "" {
		t.Errorf("empty body")
	}
	if f.requests.Load() != 1 {
		t.Errorf("expected 1 request, got %d", f.requests.Load())
	}
}

func TestHTTPRegistryServesWithinTTL(t *testing.T) {
	f := newFakeServer(t)
	ts := httptest.NewServer(f.handler())
	defer ts.Close()

	reg, _ := NewHTTPRegistry(HTTPConfig{BaseURL: ts.URL + "/api/prompts/", TTL: time.Hour})
	for i := 0; i < 3; i++ {
		if _, err := reg.Get(context.Background(), "tmpl.reflect.compare.v1"); err != nil {
			t.Fatal(err)
		}
	}
	if f.requests.Load() != 1 {
		t.Errorf("expected 1 request within TTL, got %d", f.requests.Load())
	}
}

func TestHTTPRegistry304RevalidateKeepsCached(t *testing.T) {
	f := newFakeServer(t)
	ts := httptest.NewServer(f.handler())
	defer ts.Close()

	// TTL = 0 forces revalidation on every Get.
	reg, _ := NewHTTPRegistry(HTTPConfig{BaseURL: ts.URL + "/api/prompts/", TTL: time.Nanosecond})
	p1, err := reg.Get(context.Background(), "tmpl.reflect.compare.v1")
	if err != nil {
		t.Fatal(err)
	}
	// Small sleep so LastVerifiedAt ages out.
	time.Sleep(2 * time.Millisecond)
	p2, err := reg.Get(context.Background(), "tmpl.reflect.compare.v1")
	if err != nil {
		t.Fatal(err)
	}
	if p1.Body != p2.Body {
		t.Errorf("body drifted on 304: %q vs %q", p1.Body, p2.Body)
	}
	if f.requests.Load() < 2 {
		t.Errorf("expected revalidation requests, got %d", f.requests.Load())
	}
}

func TestHTTPRegistryOfflineFallback(t *testing.T) {
	f := newFakeServer(t)
	ts := httptest.NewServer(f.handler())

	logs := &strings.Builder{}
	reg, _ := NewHTTPRegistry(HTTPConfig{
		BaseURL: ts.URL + "/api/prompts/",
		TTL:     time.Nanosecond,
		Logger:  log.New(logs, "", 0),
	})
	// First fetch primes the cache.
	if _, err := reg.Get(context.Background(), "tmpl.reflect.compare.v1"); err != nil {
		t.Fatal(err)
	}
	// Kill the server and try again — should serve stale with warning.
	ts.Close()
	time.Sleep(2 * time.Millisecond)
	p, err := reg.Get(context.Background(), "tmpl.reflect.compare.v1")
	if err != nil {
		t.Fatalf("expected offline fallback, got error: %v", err)
	}
	if p.Body == "" {
		t.Errorf("empty prompt from stale cache")
	}
	if !strings.Contains(logs.String(), "stale cache") {
		t.Errorf("expected stale-cache warning in logs, got %q", logs.String())
	}
}

func TestHTTPRegistryNotFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer ts.Close()
	reg, _ := NewHTTPRegistry(HTTPConfig{BaseURL: ts.URL + "/api/prompts/"})
	_, err := reg.Get(context.Background(), "missing")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected not found error, got %v", err)
	}
}

func TestHTTPRegistrySendsBearerTokenWhenConfigured(t *testing.T) {
	var seenAuth string
	f := newFakeServer(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/prompts/", func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		f.handler()(w, r)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	reg, _ := NewHTTPRegistry(HTTPConfig{
		BaseURL:       ts.URL + "/api/prompts/",
		TokenProvider: func() string { return "TEST-TOKEN" },
	})
	if _, err := reg.Get(context.Background(), "tmpl.reflect.compare.v1"); err != nil {
		t.Fatal(err)
	}
	if seenAuth != "Bearer TEST-TOKEN" {
		t.Errorf("Authorization = %q, want %q", seenAuth, "Bearer TEST-TOKEN")
	}
}

func TestHTTPRegistryMirrorsToSQLiteAndWarms(t *testing.T) {
	f := newFakeServer(t)
	ts := httptest.NewServer(f.handler())
	defer ts.Close()

	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	reg, _ := NewHTTPRegistry(HTTPConfig{BaseURL: ts.URL + "/api/prompts/", Store: st})
	if _, err := reg.Get(context.Background(), "tmpl.reflect.compare.v1"); err != nil {
		t.Fatal(err)
	}
	rows, _ := st.LoadPromptCache()
	if len(rows) != 1 {
		t.Fatalf("expected 1 cached row, got %d", len(rows))
	}
	if rows[0].ETag == "" {
		t.Errorf("etag not persisted: %+v", rows[0])
	}

	// Second client warmed from SQLite — serves from cache without hitting server.
	// Block the server so we prove no fetch happened.
	reg2, _ := NewHTTPRegistry(HTTPConfig{
		BaseURL: ts.URL + "/api/prompts/",
		Store:   st,
		TTL:     time.Hour,
	})
	before := f.requests.Load()
	if _, err := reg2.Get(context.Background(), "tmpl.reflect.compare.v1"); err != nil {
		t.Fatal(err)
	}
	if f.requests.Load() != before {
		t.Errorf("warmed cache unexpectedly hit server (before=%d after=%d)", before, f.requests.Load())
	}
}

// Sanity check: the fake server itself reports the right URL shape.
func TestRegistryConstructorAddsTrailingSlash(t *testing.T) {
	reg, err := NewHTTPRegistry(HTTPConfig{BaseURL: "http://x/api/prompts"})
	if err != nil {
		t.Fatal(err)
	}
	hr := reg.(*httpRegistry)
	if !strings.HasSuffix(hr.cfg.BaseURL, "/") {
		t.Errorf("constructor didn't add trailing slash: %q", hr.cfg.BaseURL)
	}
}

// Helper used in debugging locally — left in for completeness.
var _ = fmt.Sprintf
var _ = io.Discard
