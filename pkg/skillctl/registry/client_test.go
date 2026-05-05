package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fixtureServer spins up an httptest.Server that mirrors the S5 admission
// API contract. It records every request path so tests can assert the
// client built the right URL.
type fixtureServer struct {
	t        *testing.T
	mux      *http.ServeMux
	srv      *httptest.Server
	requests []string
}

func newFixtureServer(t *testing.T) *fixtureServer {
	t.Helper()
	fs := &fixtureServer{t: t, mux: http.NewServeMux()}
	fs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fs.requests = append(fs.requests, r.Method+" "+r.URL.RequestURI())
		fs.mux.ServeHTTP(w, r)
	}))
	t.Cleanup(fs.srv.Close)
	return fs
}

// install lets a test register a handler for a specific URL pattern.
func (fs *fixtureServer) install(pattern string, h http.HandlerFunc) {
	fs.mux.HandleFunc(pattern, h)
}

// client returns a Client pointed at the fixture, with the test server's
// HTTPClient (httptest.Client respects the test's deadline).
func (fs *fixtureServer) client() *Client {
	c := New(fs.srv.URL+"/api/skills", fs.srv.Client())
	// Tighten the timeout for tests so a missed handler fails fast.
	c.HTTPClient.Timeout = 5 * time.Second
	return c
}

// ---------- ResolveByName ----------

func TestResolveByName_OK(t *testing.T) {
	fs := newFixtureServer(t)
	fs.install("/api/skills/by-name/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name": "fetch-contract",
			"versions": []map[string]any{
				{
					"version":       "1.0.0",
					"digest":        "sha256:abc123",
					"author_intent": "green",
					"admitted_at":   "2026-05-05T19:30:00Z",
					"status":        "admitted",
				},
				{
					"version":       "0.9.0",
					"digest":        "sha256:def456",
					"author_intent": "yellow",
					"admitted_at":   "2026-05-01T10:00:00Z",
					"status":        "admitted",
				},
			},
		})
	})

	c := fs.client()
	versions, err := c.ResolveByName(context.Background(), "fetch-contract")
	if err != nil {
		t.Fatalf("ResolveByName: %v", err)
	}
	if len(versions) != 2 {
		t.Fatalf("got %d versions, want 2", len(versions))
	}
	if versions[0].Version != "1.0.0" || versions[0].Digest != "sha256:abc123" {
		t.Errorf("v0 wrong: %+v", versions[0])
	}
	if versions[0].Status != "admitted" {
		t.Errorf("v0 status = %q", versions[0].Status)
	}
	if versions[0].AdmittedAt.IsZero() {
		t.Errorf("v0 AdmittedAt should be parsed; got zero")
	}
}

func TestResolveByName_404(t *testing.T) {
	fs := newFixtureServer(t)
	fs.install("/api/skills/by-name/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	c := fs.client()
	_, err := c.ResolveByName(context.Background(), "no-such-skill")
	if err == nil {
		t.Fatalf("expected error on 404")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("404 should wrap ErrNotFound; got %v", err)
	}
}

func TestResolveByName_5xxNoRetry(t *testing.T) {
	hits := 0
	fs := newFixtureServer(t)
	fs.install("/api/skills/by-name/", func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	c := fs.client()
	_, err := c.ResolveByName(context.Background(), "x")
	if err == nil {
		t.Fatalf("expected error")
	}
	if hits != 1 {
		t.Errorf("server hit %d times, want 1 (no-retry policy)", hits)
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention HTTP 500: %v", err)
	}
}

func TestResolveByName_Empty(t *testing.T) {
	fs := newFixtureServer(t)
	c := fs.client()
	if _, err := c.ResolveByName(context.Background(), ""); err == nil {
		t.Errorf("expected error for empty name")
	}
}

func TestResolveByName_RejectsPathTraversal(t *testing.T) {
	fs := newFixtureServer(t)
	c := fs.client()
	for _, bad := range []string{"a/b", "..\\.\\evil", "ctrl\x01"} {
		if _, err := c.ResolveByName(context.Background(), bad); err == nil {
			t.Errorf("name %q should be rejected", bad)
		}
	}
}

// ---------- GetBundle ----------

func TestGetBundle_OK(t *testing.T) {
	fs := newFixtureServer(t)
	expected := []byte("fake gzipped tarball bytes")
	fs.install("/api/skills/bundles/", func(w http.ResponseWriter, r *http.Request) {
		// The path includes the digest after /bundles/. We don't enforce
		// it here; just serve the blob.
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(expected)
	})
	c := fs.client()
	got, err := c.GetBundle(context.Background(), "sha256:abc123")
	if err != nil {
		t.Fatalf("GetBundle: %v", err)
	}
	if string(got) != string(expected) {
		t.Errorf("body mismatch: got %q want %q", got, expected)
	}
}

func TestGetBundle_404(t *testing.T) {
	fs := newFixtureServer(t)
	fs.install("/api/skills/bundles/", http.NotFound)
	c := fs.client()
	_, err := c.GetBundle(context.Background(), "sha256:nope")
	if err == nil || !errors.Is(err, ErrNotFound) {
		t.Errorf("404 should wrap ErrNotFound; got %v", err)
	}
}

func TestGetBundle_Empty(t *testing.T) {
	fs := newFixtureServer(t)
	fs.install("/api/skills/bundles/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		// no body
	})
	c := fs.client()
	if _, err := c.GetBundle(context.Background(), "sha256:empty"); err == nil {
		t.Errorf("expected error on empty body")
	}
}

func TestGetBundle_ExceedsMaxSize(t *testing.T) {
	fs := newFixtureServer(t)
	fs.install("/api/skills/bundles/", func(w http.ResponseWriter, r *http.Request) {
		// Stream MaxBlobSize+1 bytes of zeros. Server will close after.
		// Avoid actually allocating 256 MiB by writing in a loop.
		const chunk = 1 << 20 // 1 MiB
		buf := make([]byte, chunk)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		// Write MaxBlobSize/chunk + 1 chunks → just over the limit.
		for written := int64(0); written <= MaxBlobSize+1; written += chunk {
			if _, err := w.Write(buf); err != nil {
				return
			}
		}
	})
	c := fs.client()
	_, err := c.GetBundle(context.Background(), "sha256:huge")
	if err == nil {
		t.Errorf("expected error when blob exceeds max size")
	}
}

// ---------- GetBundleMeta ----------

func TestGetBundleMeta_OK(t *testing.T) {
	fs := newFixtureServer(t)
	fs.install("/api/skills/bundles/", func(w http.ResponseWriter, r *http.Request) {
		// Only the meta variant should be hit by GetBundleMeta — assert.
		if r.URL.Query().Get("meta") != "1" {
			t.Errorf("expected ?meta=1, got %q", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"bundle": map[string]any{
				"bundle_digest": "sha256:abc123",
				"name":          "fetch-contract",
				"version":       "1.0.0",
			},
			"signatures": []map[string]any{
				{
					"role":          "author",
					"identity_id":   "id:kamir@m3c",
					"signature_b64": "AAAA",
					"status":        "active",
				},
				{
					"role":          "registry",
					"identity_id":   "id:registry@aims-core",
					"signature_b64": "BBBB",
					"status":        "active",
				},
			},
			"manifest": map[string]any{
				"governance_intent": "green",
			},
		})
	})

	c := fs.client()
	meta, err := c.GetBundleMeta(context.Background(), "sha256:abc123")
	if err != nil {
		t.Fatalf("GetBundleMeta: %v", err)
	}
	if meta.Bundle["name"] != "fetch-contract" {
		t.Errorf("bundle.name = %v", meta.Bundle["name"])
	}
	if len(meta.Signatures) != 2 {
		t.Fatalf("signatures len = %d", len(meta.Signatures))
	}
	if meta.Signatures[0].Role != "author" || meta.Signatures[0].SignatureB64 != "AAAA" {
		t.Errorf("sig[0] = %+v", meta.Signatures[0])
	}
	if meta.Manifest["governance_intent"] != "green" {
		t.Errorf("manifest.governance_intent = %v", meta.Manifest["governance_intent"])
	}
}

func TestGetBundleMeta_404(t *testing.T) {
	fs := newFixtureServer(t)
	fs.install("/api/skills/bundles/", http.NotFound)
	c := fs.client()
	if _, err := c.GetBundleMeta(context.Background(), "sha256:nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("404 should wrap ErrNotFound; got %v", err)
	}
}

// ---------- GetIdentity ----------

func TestGetIdentity_OK_PubkeyB64Field(t *testing.T) {
	fs := newFixtureServer(t)
	fs.install("/api/skills/identities/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":          "id:kamir@m3c",
			"pubkey_b64":  "Zm9v",
			"auth_source": "manual",
		})
	})
	c := fs.client()
	got, err := c.GetIdentity(context.Background(), "id:kamir@m3c")
	if err != nil {
		t.Fatalf("GetIdentity: %v", err)
	}
	if got.ID != "id:kamir@m3c" {
		t.Errorf("ID = %q", got.ID)
	}
	if got.PubkeyB64 != "Zm9v" {
		t.Errorf("PubkeyB64 = %q", got.PubkeyB64)
	}
	if got.AuthSource != "manual" {
		t.Errorf("AuthSource = %q", got.AuthSource)
	}
	if got.IsRevoked() {
		t.Errorf("identity should not be revoked")
	}
}

func TestGetIdentity_OK_PubkeyAltField(t *testing.T) {
	// S5 brief vs older skill_registry models may spell the field
	// differently; client should tolerate `pubkey` too.
	fs := newFixtureServer(t)
	fs.install("/api/skills/identities/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":     "id:kamir@m3c",
			"pubkey": "YmFy",
		})
	})
	c := fs.client()
	got, err := c.GetIdentity(context.Background(), "id:kamir@m3c")
	if err != nil {
		t.Fatalf("GetIdentity: %v", err)
	}
	if got.PubkeyB64 != "YmFy" {
		t.Errorf("PubkeyB64 = %q (alt field path)", got.PubkeyB64)
	}
}

func TestGetIdentity_Revoked(t *testing.T) {
	fs := newFixtureServer(t)
	fs.install("/api/skills/identities/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":          "id:old@m3c",
			"pubkey_b64":  "Zm9v",
			"auth_source": "manual",
			"revoked_at":  "2026-04-01T00:00:00Z",
		})
	})
	c := fs.client()
	got, err := c.GetIdentity(context.Background(), "id:old@m3c")
	if err != nil {
		t.Fatalf("GetIdentity: %v", err)
	}
	if !got.IsRevoked() {
		t.Errorf("expected revoked")
	}
}

func TestGetIdentity_404(t *testing.T) {
	fs := newFixtureServer(t)
	fs.install("/api/skills/identities/", http.NotFound)
	c := fs.client()
	if _, err := c.GetIdentity(context.Background(), "id:ghost"); !errors.Is(err, ErrNotFound) {
		t.Errorf("404 should wrap ErrNotFound; got %v", err)
	}
}

func TestGetIdentity_EmptyIDInResponse(t *testing.T) {
	fs := newFixtureServer(t)
	fs.install("/api/skills/identities/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"pubkey_b64":"Zm9v"}`))
	})
	c := fs.client()
	if _, err := c.GetIdentity(context.Background(), "id:malformed"); err == nil {
		t.Errorf("expected error on response with empty id")
	}
}

func TestGetIdentity_EmptyArg(t *testing.T) {
	fs := newFixtureServer(t)
	c := fs.client()
	if _, err := c.GetIdentity(context.Background(), ""); err == nil {
		t.Errorf("expected error for empty id")
	}
}

// ---------- redirect cap ----------

func TestRedirectCap(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		// Bounce forever — the client should give up.
		http.Redirect(w, r, r.URL.String()+"x", http.StatusFound)
	}))
	defer srv.Close()
	// Pass nil so New installs its default redirect-capped client. We
	// can't use srv.Client() here because httptest's transport doesn't
	// tunnel the CheckRedirect we configure into it.
	c := New(srv.URL+"/api/skills", nil)
	c.HTTPClient.Timeout = 5 * time.Second
	if _, err := c.ResolveByName(context.Background(), "name"); err == nil {
		t.Errorf("expected error on redirect storm")
	}
	// The client itself counts the initial request as via[0], so a
	// ceiling of MaxRedirects+1 hits is the strict expectation.
	if hits > MaxRedirects+1 {
		t.Errorf("server hit %d times, want ≤ %d", hits, MaxRedirects+1)
	}
}

// ---------- ContextCancel ----------

func TestContextCancel(t *testing.T) {
	// Server hangs forever.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	defer srv.Close()
	c := New(srv.URL+"/api/skills", srv.Client())
	c.HTTPClient.Timeout = 2 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	_, err := c.ResolveByName(ctx, "x")
	if err == nil {
		t.Errorf("expected error on canceled context")
	}
}

// ---------- URL building ----------

func TestNew_TrimsTrailingSlash(t *testing.T) {
	c := New("https://example.com/api/skills/", nil)
	if !strings.HasSuffix(c.BaseURL, "/skills") || strings.HasSuffix(c.BaseURL, "/") {
		t.Errorf("BaseURL = %q, expected no trailing slash", c.BaseURL)
	}
}

func TestRequestPaths(t *testing.T) {
	// Verify the client builds the paths the S5 contract documents.
	fs := newFixtureServer(t)
	fs.install("/api/skills/by-name/foo", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "foo", "versions": []any{}})
	})
	fs.install("/api/skills/bundles/sha256:abc", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("meta") == "1" {
			_ = json.NewEncoder(w).Encode(map[string]any{"bundle": map[string]any{}, "signatures": []any{}})
			return
		}
		_, _ = fmt.Fprint(w, "blob")
	})
	fs.install("/api/skills/identities/id:foo", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "id:foo", "pubkey_b64": "Zm9v"})
	})
	c := fs.client()
	if _, err := c.ResolveByName(context.Background(), "foo"); err != nil {
		t.Errorf("ResolveByName: %v", err)
	}
	if _, err := c.GetBundle(context.Background(), "sha256:abc"); err != nil {
		t.Errorf("GetBundle: %v", err)
	}
	if _, err := c.GetBundleMeta(context.Background(), "sha256:abc"); err != nil {
		t.Errorf("GetBundleMeta: %v", err)
	}
	if _, err := c.GetIdentity(context.Background(), "id:foo"); err != nil {
		t.Errorf("GetIdentity: %v", err)
	}
	wantPaths := []string{
		"GET /api/skills/by-name/foo",
		"GET /api/skills/bundles/sha256:abc",
		"GET /api/skills/bundles/sha256:abc?meta=1",
		"GET /api/skills/identities/id:foo",
	}
	if len(fs.requests) != len(wantPaths) {
		t.Fatalf("requests = %v, want %v", fs.requests, wantPaths)
	}
	for i, w := range wantPaths {
		if fs.requests[i] != w {
			t.Errorf("request[%d] = %q, want %q", i, fs.requests[i], w)
		}
	}
}
