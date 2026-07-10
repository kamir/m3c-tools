package browse

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/model"
)

// SEC-M3: the browse server must bind loopback only and enforce a loopback
// Host-header allowlist plus a per-launch token on its data endpoints.

func newSecServer() *Server {
	inv := &model.Inventory{}
	return NewServer(":9116", inv)
}

func TestSecLoopbackAddr(t *testing.T) {
	cases := map[string]string{
		":9116":          "127.0.0.1:9116",
		"0.0.0.0:9116":   "127.0.0.1:9116",
		"[::]:9116":      "127.0.0.1:9116",
		"127.0.0.1:9116": "127.0.0.1:9116",
	}
	for in, want := range cases {
		if got := loopbackAddr(in); got != want {
			t.Errorf("loopbackAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSecDefaultBindIsLoopback(t *testing.T) {
	s := NewServer("", &model.Inventory{})
	host, _, err := net.SplitHostPort(s.Addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", s.Addr, err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		t.Fatalf("default Addr host %q is not loopback (Addr=%q)", host, s.Addr)
	}
}

func TestSecGuardRejectsNonLoopbackHost(t *testing.T) {
	s := newSecServer()
	h := s.GuardedHandler()

	req := httptest.NewRequest(http.MethodGet, "/api/graph?token="+s.Token(), nil)
	req.Host = "172.16.4.9:9116"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("non-loopback Host = %d, want 403", w.Code)
	}
}

func TestSecGuardRejectsMissingToken(t *testing.T) {
	s := newSecServer()
	h := s.GuardedHandler()

	req := httptest.NewRequest(http.MethodGet, "/api/graph", nil)
	req.Host = "127.0.0.1:9116"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("missing token = %d, want 403", w.Code)
	}
}

func TestSecGuardAcceptsLoopbackWithToken(t *testing.T) {
	s := newSecServer()
	h := s.GuardedHandler()

	req := httptest.NewRequest(http.MethodGet, "/api/graph", nil)
	req.Host = "127.0.0.1:9116"
	req.Header.Set("X-M3C-Token", s.Token())
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("loopback+token = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

func TestSecUIExemptFromTokenButHostChecked(t *testing.T) {
	s := newSecServer()
	h := s.GuardedHandler()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "localhost:9116"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET / (loopback, no token) = %d, want 200", w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "evil.lan"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("GET / (non-loopback) = %d, want 403", w.Code)
	}
}

func TestSecRebuildRequiresToken(t *testing.T) {
	s := newSecServer()
	h := s.GuardedHandler()

	// State-mutating endpoint must reject an untokenised loopback request.
	req := httptest.NewRequest(http.MethodPost, "/api/graph/rebuild", nil)
	req.Host = "127.0.0.1:9116"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("rebuild without token = %d, want 403", w.Code)
	}
}
