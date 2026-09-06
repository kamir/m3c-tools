package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestNew_InjectedBareClientGetsRedirectPolicy pins AUDIT-0001 Befund 1.3:
// the redirect cap used to be installed only for httpClient == nil, while
// every productive newRegistryClient caller injects a client WITHOUT a
// CheckRedirect. The Bearer token then followed stdlib redirects, including a
// same-host https to http downgrade. New must install the policy on any
// injected client that has none.
func TestNew_InjectedBareClientGetsRedirectPolicy(t *testing.T) {
	bare := &http.Client{}
	c := New("https://registry.example/api/skills", bare)
	if c.HTTPClient.CheckRedirect == nil {
		t.Fatal("New must install a CheckRedirect policy on an injected client without one")
	}
}

// TestRegistryClient_RefusesDowngradeRedirect drives the injected-bare-client
// path end to end: an https registry answering with a redirect onto plain http
// (same host) must be refused before the request reaches the plaintext target.
// Before the fix the bare client followed it, carrying the Bearer token onto
// an unencrypted connection.
func TestRegistryClient_RefusesDowngradeRedirect(t *testing.T) {
	reached := false
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	defer plain.Close()

	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+r.URL.Path, http.StatusFound)
	}))
	defer tlsSrv.Close()

	// Inject a BARE client (it trusts the test TLS cert but sets no
	// CheckRedirect), exactly like the productive newRegistryClient callers.
	bare := &http.Client{Transport: tlsSrv.Client().Transport}
	c := New(tlsSrv.URL+"/api/skills", bare)
	c.Token = "bearer-secret"

	_, err := c.ResolveByName(context.Background(), "some-skill")
	if err == nil {
		t.Fatal("expected the https to http downgrade redirect to be refused")
	}
	if !strings.Contains(err.Error(), "downgrade") {
		t.Errorf("error should name the downgrade refusal, got: %v", err)
	}
	if reached {
		t.Error("request reached the plaintext target despite the redirect policy")
	}
}
