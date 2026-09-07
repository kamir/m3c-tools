package importer

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHealthCheck_CrossHostRedirectDoesNotLeakAPIKey is the AUDIT-0001
// Befund 1.1 regression proof for this package. Go's stdlib redirect policy
// strips Authorization/Cookie on a cross-host redirect but NOT custom headers
// such as X-API-KEY. Before the fix, the client built by NewClient had no
// CheckRedirect, so a registry answering "302 Location: http://collector/..."
// received the full X-API-KEY on the follow-up request. The first leg of this
// test reproduces exactly that pre-fix behavior by nil-ing the policy; the
// second leg asserts the constructor-installed policy stops the leak.
func TestHealthCheck_CrossHostRedirectDoesNotLeakAPIKey(t *testing.T) {
	t.Setenv("ER1_DEVICE_TOKEN", "") // force the X-API-KEY path in auth.ApplyAuth

	const victimHost = "registry.test"
	const collectorHost = "collector.test"

	var gotKey string
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("X-API-KEY")
		w.WriteHeader(http.StatusOK)
	}))
	defer collector.Close()

	victim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://"+collectorHost+r.URL.Path, http.StatusFound)
	}))
	defer victim.Close()

	// Map the two fake hostnames onto the real loopback listeners: httptest's
	// same-host-different-port setup does not exercise the cross-host header
	// propagation this finding is about.
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

	newTestClient := func() *Client {
		c, err := NewClient("http://"+victimHost, "super-secret-key", "user-1")
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		// Keep the constructor's CheckRedirect; only the dialer is swapped.
		c.HTTPClient.Transport = &http.Transport{DialContext: dial}
		return c
	}

	// Leg 1, the documented PRE-FIX behavior: no CheckRedirect leaks the key.
	pre := newTestClient()
	pre.HTTPClient.CheckRedirect = nil
	gotKey = ""
	if err := pre.HealthCheck(); err != nil {
		t.Fatalf("pre-fix leg HealthCheck: %v", err)
	}
	if gotKey == "" {
		t.Skip("environment did not reproduce cross-host custom-header propagation; leak mechanism unverified here")
	}

	// Leg 2, the fix: NewClient's policy must prevent the leak.
	c := newTestClient()
	if c.HTTPClient.CheckRedirect == nil {
		t.Fatal("NewClient must install a CheckRedirect policy (AUDIT-0001 Befund 1.1)")
	}
	gotKey = "unset"
	if err := c.HealthCheck(); err != nil {
		t.Fatalf("HealthCheck: %v", err)
	}
	if gotKey != "" {
		t.Errorf("X-API-KEY leaked across hosts despite the redirect policy: collector received %q", gotKey)
	}
}
