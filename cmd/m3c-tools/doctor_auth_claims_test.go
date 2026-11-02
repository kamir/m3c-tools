package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/auth"
	"github.com/kamir/m3c-tools/pkg/diag"
)

// BUG-0447: doctor printed "Device token: ✓ valid (no expiry set)" above an
// "Auth endpoint: ✗ HTTP 401" in another block. The token is opaque; "valid"
// only meant "present, no local expiry".

func doctorClaimsHome(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	for _, k := range []string{"ER1_API_URL", "ER1_API_KEY", "ER1_DEVICE_TOKEN", "ER1_CONTEXT_ID", "PLAUD_TOKEN_FILE"} {
		t.Setenv(k, "")
	}
}

func checkNamed(s diag.Section, name string) (diag.Check, bool) {
	for _, c := range s.Checks {
		if c.Name == name {
			return c, true
		}
	}
	return diag.Check{}, false
}

// AC-01/AC-02 through the public section: a token only seen in the env gets no
// green mark and no claim of validity.
func TestDoctorAuth_EnvTokenIsNotGreen(t *testing.T) {
	doctorClaimsHome(t)
	t.Setenv("ER1_DEVICE_TOKEN", "opaque-test-token")
	c, ok := checkNamed(doctorAuth(), "Device token")
	if !ok {
		t.Fatal("no Device token check")
	}
	if c.Status == diag.OK || strings.Contains(c.Detail, "valid") {
		t.Errorf("env-only token: %v %q, want a neutral mark and no validity claim", c.Status, c.Detail)
	}
}

func TestDoctorDeviceTokenCheck_SaysWhatWasChecked(t *testing.T) {
	future := time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)
	soon := time.Now().Add(2 * 24 * time.Hour).UTC().Format(time.RFC3339)
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	cases := []struct {
		name   string
		dt     *auth.DeviceToken
		status diag.Status
		want   string
	}{
		{"opaque", &auth.DeviceToken{Token: "x"}, diag.Unverified, "present, opaque, no local expiry"},
		{"unparsed", &auth.DeviceToken{Token: "x", ExpiresAt: "tomorrow"}, diag.Fail, "expired"},
		{"future", &auth.DeviceToken{Token: "x", ExpiresAt: future}, diag.Unverified, "not checked against the server"},
		{"soon", &auth.DeviceToken{Token: "x", ExpiresAt: soon}, diag.Warn, "expiring soon"},
		{"past", &auth.DeviceToken{Token: "x", ExpiresAt: past}, diag.Fail, "expired"},
		{"env only", nil, diag.Unverified, "not checked against the server"},
	}
	for _, c := range cases {
		got := doctorDeviceTokenCheck(c.dt)
		if got.Status != c.status || !strings.Contains(got.Detail, c.want) || strings.Contains(got.Detail, "valid") {
			t.Errorf("%s: %v %q, want %v containing %q and no validity claim", c.name, got.Status, got.Detail, c.status, c.want)
		}
	}
}

// AC-03/AC-04: the 401 quotes the server and sits in the Authentication block.
func TestDoctorReport_AuthEndpointQuotesServerInAuthBlock(t *testing.T) {
	doctorClaimsHome(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			fmt.Fprint(w, "ok")
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"Authentication required"}`)
	}))
	defer srv.Close()
	t.Setenv("ER1_API_URL", srv.URL+"/upload_2")
	t.Setenv("ER1_API_KEY", "test-key")
	_ = os.Unsetenv("ER1_DEVICE_TOKEN")

	var authSec, connSec diag.Section
	for _, s := range buildDoctorReport().Sections {
		switch s.Title {
		case "Authentication":
			authSec = s
		case "Connectivity":
			connSec = s
		}
	}
	c, ok := checkNamed(authSec, "Auth endpoint")
	if !ok {
		t.Fatalf("Authentication block has no Auth endpoint check: %+v", authSec.Checks)
	}
	if c.Status != diag.Fail || !strings.Contains(c.Detail, `{"error":"Authentication required"}`) || strings.Contains(c.Detail, "invalid or expired") {
		t.Errorf("Auth endpoint: %v %q, want Fail quoting the server body and no guessed cause", c.Status, c.Detail)
	}
	if _, dup := checkNamed(connSec, "Auth endpoint"); dup {
		t.Error("Auth endpoint is still reported in Connectivity as well")
	}
}

func TestQuoteServerBody(t *testing.T) {
	if got := quoteServerBody([]byte("  {\"error\":\"bad key sk-123\"}\r\n"), "sk-123", ""); got != `{"error":"bad key [redacted]"}` {
		t.Errorf("redaction/trim: %q", got)
	}
	if got := quoteServerBody(nil); got != "(empty body)" {
		t.Errorf("empty: %q", got)
	}
	if got := quoteServerBody([]byte("a\u009bb\u202ec\u2028d\u0085e")); got != "a b c d e" {
		t.Errorf("C1, bidi and separators: %q", got)
	}
	if got := quoteServerBody([]byte("a\nb\x1bc")); got != "a b c" {
		t.Errorf("control chars: %q", got)
	}
	if got := quoteServerBody([]byte(strings.Repeat("x", 500))); len(got) != 203 || !strings.HasSuffix(got, "...") {
		t.Errorf("truncation: len %d", len(got))
	}
}

// BUG-0447 follow-up: once the server accepts the device token, the Device
// token line is covered by a server answer and turns green, so a healthy
// device-token setup ends with ALL CHECKS PASSED (QA check C2 keys on it).
func TestDoctorReport_ServerAcceptedDeviceTokenIsGreen(t *testing.T) {
	doctorClaimsHome(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"devices":[{"device_type":"cli","device_name":"test","status":"active"}]}`)
	}))
	defer srv.Close()
	t.Setenv("ER1_API_URL", srv.URL+"/upload_2")
	t.Setenv("ER1_DEVICE_TOKEN", "opaque-test-token")
	t.Setenv("ER1_CONTEXT_ID", "testuser___testctx") // a configured install has one

	report := buildDoctorReport()
	var authSec diag.Section
	for _, s := range report.Sections {
		if s.Title == "Authentication" {
			authSec = s
		}
	}
	if c, _ := checkNamed(authSec, "Auth endpoint"); c.Status != diag.OK {
		t.Fatalf("precondition: Auth endpoint = %v %q, want OK", c.Status, c.Detail)
	}
	c, _ := checkNamed(authSec, "Device token")
	if c.Status != diag.OK || !strings.Contains(c.Detail, "accepted by the server") {
		t.Errorf("Device token after HTTP 200: %v %q, want OK naming the server answer", c.Status, c.Detail)
	}
	if got := report.ResultLine(); !strings.Contains(got, "ALL CHECKS PASSED") {
		for _, s := range report.Sections {
			for _, ch := range s.Checks {
				t.Logf("%s / %s", s.Title, ch.String())
			}
		}
		t.Errorf("result line = %q, want ALL CHECKS PASSED", got)
	}
}

// Without a server answer the line stays neutral (AC-02).
func TestDoctorReport_RejectedDeviceTokenStaysUnverified(t *testing.T) {
	doctorClaimsHome(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	t.Setenv("ER1_API_URL", srv.URL+"/upload_2")
	t.Setenv("ER1_DEVICE_TOKEN", "opaque-test-token")
	for _, s := range buildDoctorReport().Sections {
		if s.Title == "Authentication" {
			if c, _ := checkNamed(s, "Device token"); c.Status != diag.Unverified {
				t.Errorf("Device token after HTTP 401: %v %q, want Unverified", c.Status, c.Detail)
			}
		}
	}
}

// A redirect never confirms the credential: a followed hop drops the
// Authorization header and any login page answers 200. Neither redirect may
// produce an OK Auth endpoint, an OK Device token or ALL CHECKS PASSED.
func TestDoctorReport_RedirectIsNotAcceptance(t *testing.T) {
	sso := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html>sign in</html>")
	}))
	defer sso.Close()
	cases := map[string]func(base string) string{
		"cross-origin SSO":  func(string) string { return sso.URL + "/sso/login?next=x" },
		"same-origin login": func(base string) string { return "/login" },
	}
	for name, location := range cases {
		t.Run(name, func(t *testing.T) {
			doctorClaimsHome(t)
			var srv *httptest.Server
			srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/health", "/login":
					fmt.Fprint(w, "<html>ok</html>")
				default:
					http.Redirect(w, r, location(srv.URL), http.StatusFound)
				}
			}))
			defer srv.Close()
			t.Setenv("ER1_API_URL", srv.URL+"/upload_2")
			t.Setenv("ER1_DEVICE_TOKEN", "bogus-test-token")
			t.Setenv("ER1_CONTEXT_ID", "testuser___testctx")

			report := buildDoctorReport()
			var authSec diag.Section
			for _, s := range report.Sections {
				if s.Title == "Authentication" {
					authSec = s
				}
			}
			ep, _ := checkNamed(authSec, "Auth endpoint")
			if ep.Status == diag.OK || !strings.Contains(ep.Detail, "redirect") || strings.Contains(ep.Detail, "bogus-test-token") {
				t.Errorf("Auth endpoint after a redirect: %v %q, want a non-OK line naming the redirect", ep.Status, ep.Detail)
			}
			if dt, _ := checkNamed(authSec, "Device token"); dt.Status == diag.OK {
				t.Errorf("Device token after a redirect: %v %q, want not OK", dt.Status, dt.Detail)
			}
			if got := report.ResultLine(); strings.Contains(got, "ALL CHECKS PASSED") {
				t.Errorf("result line after a redirect = %q", got)
			}
		})
	}
}
