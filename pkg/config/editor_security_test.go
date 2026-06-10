package config

import (
	"net"
	"net/http/httptest"
	"strings"
	"testing"
)

// SEC-M3: the settings editor exposes a secret-bearing profile API and MUST be
// reachable on loopback only, behind a Host-header allowlist and a per-launch
// token. These tests assert the guard rejects non-loopback Host headers and
// missing/invalid tokens, while keeping the loopback + correct-token path open.

func TestSecLoopbackAddr(t *testing.T) {
	cases := map[string]string{
		":9116":          "127.0.0.1:9116",
		"0.0.0.0:9116":   "127.0.0.1:9116",
		"[::]:9116":      "127.0.0.1:9116",
		"127.0.0.1:9116": "127.0.0.1:9116",
		"localhost:9116": "localhost:9116",
	}
	for in, want := range cases {
		if got := loopbackAddr(in); got != want {
			t.Errorf("loopbackAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSecDefaultBindIsLoopback(t *testing.T) {
	srv := NewEditorServer("")
	host, _, err := net.SplitHostPort(srv.Addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", srv.Addr, err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		t.Fatalf("default Addr host %q is not loopback (Addr=%q)", host, srv.Addr)
	}
}

func TestSecGuardRejectsNonLoopbackHost(t *testing.T) {
	srv := newTestServer(t)
	h := srv.GuardedHandler()

	// A request claiming a non-loopback Host (DNS-rebinding / LAN attacker)
	// must be rejected even with the correct token.
	req := httptest.NewRequest("GET", "/api/profiles?token="+srv.Token(), nil)
	req.Host = "192.168.1.50:9116"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatalf("non-loopback Host = %d, want 403; body: %s", w.Code, w.Body.String())
	}
	// And the secret-bearing payload must not have leaked.
	if strings.Contains(w.Body.String(), "ER1_API_KEY") ||
		strings.Contains(w.Body.String(), "secret-key") {
		t.Fatalf("secret leaked in rejected response: %s", w.Body.String())
	}
}

func TestSecGuardRejectsMissingToken(t *testing.T) {
	srv := newTestServer(t)
	h := srv.GuardedHandler()

	req := httptest.NewRequest("GET", "/api/profiles", nil)
	req.Host = "127.0.0.1:9116"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatalf("missing token = %d, want 403; body: %s", w.Code, w.Body.String())
	}
}

func TestSecGuardRejectsWrongToken(t *testing.T) {
	srv := newTestServer(t)
	h := srv.GuardedHandler()

	req := httptest.NewRequest("GET", "/api/profiles?token=deadbeef", nil)
	req.Host = "localhost:9116"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatalf("wrong token = %d, want 403", w.Code)
	}
}

func TestSecGuardAcceptsLoopbackWithToken(t *testing.T) {
	srv := newTestServer(t)
	h := srv.GuardedHandler()

	// Token via query parameter.
	req := httptest.NewRequest("GET", "/api/profiles?token="+srv.Token(), nil)
	req.Host = "127.0.0.1:9116"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("loopback+token (query) = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	// Token via header.
	req = httptest.NewRequest("GET", "/api/profiles", nil)
	req.Host = "localhost"
	req.Header.Set("X-M3C-Token", srv.Token())
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("loopback+token (header) = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

func TestSecUIServedWithoutTokenButInjectsIt(t *testing.T) {
	srv := newTestServer(t)
	h := srv.GuardedHandler()

	// The bootstrap page is reachable without a token (it carries no secrets),
	// but the server injects the token so the JS can authenticate later calls.
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "127.0.0.1:9116"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("GET / (no token) = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), srv.Token()) {
		t.Fatal("served UI page should contain the injected launch token")
	}
}

func TestSecUIPageRejectedOnNonLoopbackHost(t *testing.T) {
	srv := newTestServer(t)
	h := srv.GuardedHandler()

	// Even the token-exempt UI page must be denied to a non-loopback Host.
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "evil.example.com"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatalf("non-loopback Host on / = %d, want 403", w.Code)
	}
}

func TestSecEmptyTokenFailsClosed(t *testing.T) {
	srv := newTestServer(t)
	srv.token = "" // simulate RNG failure
	h := srv.GuardedHandler()

	req := httptest.NewRequest("GET", "/api/profiles?token=", nil)
	req.Host = "127.0.0.1"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatalf("empty server token = %d, want 403 (fail closed)", w.Code)
	}
}
