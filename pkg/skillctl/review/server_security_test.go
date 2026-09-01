package review

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// SEC-M3: the review server must bind loopback only and enforce a loopback
// Host-header allowlist plus a per-launch token on its data endpoints.

func TestSecLoopbackAddr(t *testing.T) {
	cases := map[string]string{
		":9115":          "127.0.0.1:9115",
		"0.0.0.0:9115":   "127.0.0.1:9115",
		"[::]:9115":      "127.0.0.1:9115",
		"127.0.0.1:9115": "127.0.0.1:9115",
	}
	for in, want := range cases {
		if got := loopbackAddr(in); got != want {
			t.Errorf("loopbackAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSecDefaultBindIsLoopback(t *testing.T) {
	s := NewServer("", "/tmp/delta.json")
	host, _, err := net.SplitHostPort(s.Addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", s.Addr, err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		t.Fatalf("default Addr host %q is not loopback (Addr=%q)", host, s.Addr)
	}
}

func TestSecGuardRejectsNonLoopbackHost(t *testing.T) {
	s := setupServer(t)
	h := s.GuardedHandler()

	req := httptest.NewRequest(http.MethodGet, "/api/delta?token="+s.Token(), nil)
	req.Host = "10.0.0.7:9115"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("non-loopback Host = %d, want 403", w.Code)
	}
}

func TestSecGuardRejectsMissingToken(t *testing.T) {
	s := setupServer(t)
	h := s.GuardedHandler()

	req := httptest.NewRequest(http.MethodGet, "/api/delta", nil)
	req.Host = "127.0.0.1:9115"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("missing token = %d, want 403", w.Code)
	}
}

func TestSecGuardAcceptsLoopbackWithToken(t *testing.T) {
	s := setupServer(t)
	h := s.GuardedHandler()

	req := httptest.NewRequest(http.MethodGet, "/api/delta", nil)
	req.Host = "127.0.0.1:9115"
	req.Header.Set("X-M3C-Token", s.Token())
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("loopback+token = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

func TestSecUIExemptFromTokenButHostChecked(t *testing.T) {
	s := setupServer(t)
	h := s.GuardedHandler()

	// UI page reachable without token on loopback.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "localhost:9115"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET / (loopback, no token) = %d, want 200", w.Code)
	}

	// But denied to a non-loopback Host.
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "attacker.lan"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("GET / (non-loopback) = %d, want 403", w.Code)
	}
}

func TestSecHealthIsLoopbackHostChecked(t *testing.T) {
	s := setupServer(t)
	h := s.GuardedHandler()

	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	req.Host = "192.168.0.5"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("health on non-loopback Host = %d, want 403", w.Code)
	}
}
