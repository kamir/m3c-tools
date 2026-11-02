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
	if got := quoteServerBody([]byte("a\nb\x1bc")); got != "a b c" {
		t.Errorf("control chars: %q", got)
	}
	if got := quoteServerBody([]byte(strings.Repeat("x", 500))); len(got) != 203 || !strings.HasSuffix(got, "...") {
		t.Errorf("truncation: len %d", len(got))
	}
}
