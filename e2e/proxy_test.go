// Unit tests for proxy configuration and CLI flag wiring.
// These tests are offline — no network required.
//
// Run: go test -v ./e2e/ -run TestProxy
package e2e

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/transcript"
)

// -- GenericProxyConfig.BuildProxyURL tests --

func TestProxyBuildURLNoAuth(t *testing.T) {
	cfg := &transcript.GenericProxyConfig{
		ProxyURL: "http://proxy.example.com:8080",
	}
	got, err := cfg.BuildProxyURL()
	if err != nil {
		t.Fatalf("BuildProxyURL() error: %v", err)
	}
	if got != "http://proxy.example.com:8080" {
		t.Errorf("expected unchanged URL, got %q", got)
	}
}

func TestProxyBuildURLWithAuth(t *testing.T) {
	cfg := &transcript.GenericProxyConfig{
		ProxyURL:  "http://proxy.example.com:8080",
		ProxyAuth: "alice:s3cret",
	}
	got, err := cfg.BuildProxyURL()
	if err != nil {
		t.Fatalf("BuildProxyURL() error: %v", err)
	}
	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatalf("url.Parse() error: %v", err)
	}
	if parsed.User.Username() != "alice" {
		t.Errorf("expected username alice, got %q", parsed.User.Username())
	}
	pass, ok := parsed.User.Password()
	if !ok || pass != "s3cret" {
		t.Errorf("expected password s3cret, got %q (ok=%v)", pass, ok)
	}
	if parsed.Host != "proxy.example.com:8080" {
		t.Errorf("expected host proxy.example.com:8080, got %q", parsed.Host)
	}
}

func TestProxyBuildURLAuthOverridesEmbedded(t *testing.T) {
	cfg := &transcript.GenericProxyConfig{
		ProxyURL:  "http://old:pass@proxy.example.com:8080",
		ProxyAuth: "new:newpass",
	}
	got, err := cfg.BuildProxyURL()
	if err != nil {
		t.Fatalf("BuildProxyURL() error: %v", err)
	}
	parsed, _ := url.Parse(got)
	if parsed.User.Username() != "new" {
		t.Errorf("expected username new, got %q", parsed.User.Username())
	}
	pass, _ := parsed.User.Password()
	if pass != "newpass" {
		t.Errorf("expected password newpass, got %q", pass)
	}
}

func TestProxyBuildURLAuthUsernameOnly(t *testing.T) {
	cfg := &transcript.GenericProxyConfig{
		ProxyURL:  "http://proxy.example.com:8080",
		ProxyAuth: "onlyuser",
	}
	got, err := cfg.BuildProxyURL()
	if err != nil {
		t.Fatalf("BuildProxyURL() error: %v", err)
	}
	parsed, _ := url.Parse(got)
	if parsed.User.Username() != "onlyuser" {
		t.Errorf("expected username onlyuser, got %q", parsed.User.Username())
	}
	_, hasPass := parsed.User.Password()
	if hasPass {
		t.Error("expected no password for username-only auth")
	}
}

func TestProxyBuildURLEmptyURLError(t *testing.T) {
	cfg := &transcript.GenericProxyConfig{ProxyURL: ""}
	_, err := cfg.BuildProxyURL()
	if err == nil {
		t.Fatal("expected error for empty proxy URL")
	}
}

func TestProxySocks5URL(t *testing.T) {
	cfg := &transcript.GenericProxyConfig{
		ProxyURL:  "socks5://localhost:1080",
		ProxyAuth: "user:pass",
	}
	got, err := cfg.BuildProxyURL()
	if err != nil {
		t.Fatalf("BuildProxyURL() error: %v", err)
	}
	if !strings.HasPrefix(got, "socks5://") {
		t.Errorf("expected socks5 scheme, got %q", got)
	}
	parsed, _ := url.Parse(got)
	if parsed.User.Username() != "user" {
		t.Errorf("expected username user, got %q", parsed.User.Username())
	}
}

// -- GetTransport tests --

func TestProxyGetTransportValid(t *testing.T) {
	cfg := &transcript.GenericProxyConfig{
		ProxyURL: "http://proxy.example.com:8080",
	}
	tr, err := cfg.GetTransport()
	if err != nil {
		t.Fatalf("GetTransport() error: %v", err)
	}
	if tr == nil {
		t.Fatal("expected non-nil transport")
	}
	if tr.Proxy == nil {
		t.Error("expected Proxy function to be set")
	}
}

func TestProxyGetTransportWithAuth(t *testing.T) {
	cfg := &transcript.GenericProxyConfig{
		ProxyURL:  "http://proxy.example.com:8080",
		ProxyAuth: "user:pass",
	}
	tr, err := cfg.GetTransport()
	if err != nil {
		t.Fatalf("GetTransport() error: %v", err)
	}
	// Verify the proxy function returns the correct URL with credentials
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	proxyURL, err := tr.Proxy(req)
	if err != nil {
		t.Fatalf("Proxy() error: %v", err)
	}
	if proxyURL.User.Username() != "user" {
		t.Errorf("expected proxy username user, got %q", proxyURL.User.Username())
	}
}

func TestProxyGetTransportEmptyURLError(t *testing.T) {
	cfg := &transcript.GenericProxyConfig{ProxyURL: ""}
	_, err := cfg.GetTransport()
	if err == nil {
		t.Fatal("expected error for empty proxy URL")
	}
}

// -- NewWithProxy integration --

func TestProxyNewWithProxyValid(t *testing.T) {
	cfg := &transcript.GenericProxyConfig{
		ProxyURL: "http://proxy.example.com:8080",
	}
	api, err := transcript.NewWithProxy(cfg)
	if err != nil {
		t.Fatalf("NewWithProxy() error: %v", err)
	}
	if api == nil {
		t.Fatal("expected non-nil API")
	}
}

func TestProxyNewWithProxyInvalidURL(t *testing.T) {
	cfg := &transcript.GenericProxyConfig{
		ProxyURL: "://bad-url",
	}
	_, err := transcript.NewWithProxy(cfg)
	if err == nil {
		t.Fatal("expected error for invalid proxy URL")
	}
}

// -- HTTP proxy integration test using httptest --

func TestProxyHTTPIntegration(t *testing.T) {
	// Start a fake "proxy" server that just echoes the request info
	proxyHit := false
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHit = true
		// Check for Proxy-Authorization header when using basic auth
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "proxied: %s %s", r.Method, r.URL.String())
	}))
	defer proxy.Close()

	cfg := &transcript.GenericProxyConfig{
		ProxyURL: proxy.URL,
	}
	tr, err := cfg.GetTransport()
	if err != nil {
		t.Fatalf("GetTransport() error: %v", err)
	}

	client := &http.Client{Transport: tr}
	// Make a request through the proxy to a non-existent target
	// The proxy will intercept it
	resp, err := client.Get(proxy.URL + "/test")
	if err != nil {
		t.Fatalf("GET error: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "proxied:") {
		t.Errorf("expected proxied response, got %q", string(body))
	}
	if !proxyHit {
		t.Error("proxy was not hit")
	}
}

// -- WebshareProxyConfig tests --

func TestProxyWebshareEmptyError(t *testing.T) {
	cfg := &transcript.WebshareProxyConfig{Proxies: []string{}}
	_, err := cfg.GetTransport()
	if err == nil {
		t.Fatal("expected error for empty proxy list")
	}
}

func TestProxyWebsharePicksFromList(t *testing.T) {
	cfg := &transcript.WebshareProxyConfig{
		Proxies: []string{
			"http://proxy1.example.com:8080",
			"http://proxy2.example.com:8080",
		},
	}
	tr, err := cfg.GetTransport()
	if err != nil {
		t.Fatalf("GetTransport() error: %v", err)
	}
	if tr == nil {
		t.Fatal("expected non-nil transport")
	}
}
