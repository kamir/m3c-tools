package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/diag"
)

// BUG-0447: doctor printed "valid" for a Plaud token it had only found on
// disk. These tests route every outbound request of the test process to a
// local fake Plaud API, so nothing reaches the real service.

type fakePlaudTransport struct {
	mu    sync.Mutex
	hosts []string
	srv   *httptest.Server
	next  http.RoundTripper
	fail  bool
}

func (f *fakePlaudTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.hosts = append(f.hosts, r.URL.Host)
	f.mu.Unlock()
	if f.fail {
		return nil, errors.New("simulated network failure")
	}
	u, _ := url.Parse(f.srv.URL)
	r2 := r.Clone(r.Context())
	r2.URL.Scheme, r2.URL.Host = u.Scheme, u.Host
	return f.next.RoundTrip(r2)
}

func setupDoctorPlaudFake(t *testing.T, handler http.HandlerFunc, fail bool) *fakePlaudTransport {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	for _, k := range []string{"ER1_API_URL", "ER1_API_KEY", "ER1_DEVICE_TOKEN", "ER1_CONTEXT_ID", "PLAUD_API_URL"} {
		t.Setenv(k, "")
	}
	tokenPath := filepath.Join(home, "plaud-token.json")
	t.Setenv("PLAUD_TOKEN_FILE", tokenPath)
	// A JWT-shaped token with no readable claims, built at run time so no
	// token-like literal sits in the source for secret scanners to flag.
	fake := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`)) + ".bm90LWEt.c2ln"
	body := fmt.Sprintf(`{"token":%q,"saved_at":%q}`, fake, time.Now().Format(time.RFC3339))
	if err := os.WriteFile(tokenPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	orig := http.DefaultTransport
	ft := &fakePlaudTransport{srv: srv, next: orig, fail: fail}
	http.DefaultTransport = ft
	t.Cleanup(func() { http.DefaultTransport = orig })
	return ft
}

func plaudTokenCheck(t *testing.T) diag.Check {
	t.Helper()
	for _, c := range doctorPlaud().Checks {
		if c.Name == "Plaud token" {
			return c
		}
	}
	t.Fatal("no Plaud token check")
	return diag.Check{}
}

func plaudStatusHandler(status string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, status)
	}
}

func TestDoctorPlaudToken_RejectedByPlaudIsFail(t *testing.T) {
	ft := setupDoctorPlaudFake(t, plaudStatusHandler(`{"status":-3900,"msg":"invalid auth header"}`), false)
	c := plaudTokenCheck(t)
	if c.Status != diag.Fail || strings.Contains(c.Detail, "valid (") {
		t.Errorf("rejected token: %v %q, want Fail", c.Status, c.Detail)
	}
	if len(ft.hosts) == 0 || !strings.HasSuffix(ft.hosts[0], "plaud.ai") {
		t.Errorf("doctor did not ask the configured Plaud API: hosts=%v", ft.hosts)
	}
}

func TestDoctorPlaudToken_HTTP401IsFail(t *testing.T) {
	setupDoctorPlaudFake(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusUnauthorized) }, false)
	if c := plaudTokenCheck(t); c.Status != diag.Fail {
		t.Errorf("HTTP 401: %v %q, want Fail", c.Status, c.Detail)
	}
}

func TestDoctorPlaudToken_AcceptedByPlaudIsOK(t *testing.T) {
	setupDoctorPlaudFake(t, plaudStatusHandler(`{"status":0,"data_file_total":0,"data_file_list":[]}`), false)
	c := plaudTokenCheck(t)
	if c.Status != diag.OK || !strings.Contains(c.Detail, "accepted by Plaud") {
		t.Errorf("accepted token: %v %q, want OK saying Plaud accepted it", c.Status, c.Detail)
	}
}

func TestDoctorPlaudToken_UnreachableIsNotValid(t *testing.T) {
	setupDoctorPlaudFake(t, plaudStatusHandler(`{}`), true)
	c := plaudTokenCheck(t)
	if c.Status != diag.Warn || !strings.Contains(c.Detail, "not verified") {
		t.Errorf("unreachable API: %v %q, want Warn saying the token is not verified", c.Status, c.Detail)
	}
}

// A body that is not Plaud's JSON envelope (a captive portal, a proxy page) is
// not proof that the token expired: the detail must not claim it was.
func TestDoctorPlaudToken_NonJSONAnswerDoesNotClaimExpiry(t *testing.T) {
	setupDoctorPlaudFake(t, plaudStatusHandler(`<html>sign in to the wifi</html>`), false)
	c := plaudTokenCheck(t)
	if c.Status == diag.OK || strings.Contains(c.Detail, "expired") || strings.Contains(c.Detail, "revoked") {
		t.Errorf("non-JSON answer: %v %q, want not OK and no expiry claim", c.Status, c.Detail)
	}
}
