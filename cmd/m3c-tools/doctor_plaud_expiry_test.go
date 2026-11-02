package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/diag"
)

// BUG-0446: a Plaud token that expired 822 hours ago must be reported by
// doctor, for both token files the Plaud paths read.

func doctorTestJWT(exp time.Time) string {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, exp.Unix())))
	return hdr + "." + payload + ".sig"
}

func doctorPlaudTestHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	for _, k := range []string{"ER1_API_URL", "ER1_API_KEY", "ER1_DEVICE_TOKEN", "ER1_CONTEXT_ID", "PLAUD_TOKEN_FILE", "PLAUD_API_URL"} {
		t.Setenv(k, "")
	}
	return home
}

func findDoctorCheck(t *testing.T, s diag.Section, name string) diag.Check {
	t.Helper()
	for _, c := range s.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("section %q has no check %q: %+v", s.Title, name, s.Checks)
	return diag.Check{}
}

func TestDoctorPlaud_ReportsJWTExpiredWebToken(t *testing.T) {
	home := doctorPlaudTestHome(t)
	tokenPath := filepath.Join(home, "plaud-token.json")
	t.Setenv("PLAUD_TOKEN_FILE", tokenPath)
	body := fmt.Sprintf(`{"token":%q,"saved_at":%q}`, doctorTestJWT(time.Now().Add(-822*time.Hour)), time.Now().Format(time.RFC3339))
	if err := os.WriteFile(tokenPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c := findDoctorCheck(t, doctorPlaud(), "Plaud token")
	if c.Status != diag.Fail || !strings.Contains(c.Detail, "expired") {
		t.Errorf("Plaud token = %v %q, want Fail naming the expiry", c.Status, c.Detail)
	}
}

func writeDevTokenFile(t *testing.T, home string, exp time.Time, refresh string) {
	t.Helper()
	dir := filepath.Join(home, ".plaud")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"access_token":"at","refresh_token":%q,"token_type":"bearer","expires_at":%d}`, refresh, exp.UnixMilli())
	if err := os.WriteFile(filepath.Join(dir, "tokens-mcp.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDoctorPlaud_ReportsExpiredDeveloperToken(t *testing.T) {
	home := doctorPlaudTestHome(t)
	writeDevTokenFile(t, home, time.Now().Add(-822*time.Hour), "")
	c := findDoctorCheck(t, doctorPlaud(), "Plaud developer token")
	if c.Status != diag.Fail || !strings.Contains(c.Detail, "822h") {
		t.Errorf("Plaud developer token = %v %q, want Fail saying it expired 822h ago", c.Status, c.Detail)
	}
}

func TestDoctorPlaud_ExpiredDeveloperTokenWithRefreshIsWarn(t *testing.T) {
	home := doctorPlaudTestHome(t)
	writeDevTokenFile(t, home, time.Now().Add(-822*time.Hour), "rt")
	c := findDoctorCheck(t, doctorPlaud(), "Plaud developer token")
	if c.Status != diag.Warn || !strings.Contains(c.Detail, "822h") || !strings.Contains(c.Detail, "refresh") {
		t.Errorf("Plaud developer token = %v %q, want Warn naming the expiry and the pending refresh", c.Status, c.Detail)
	}
}

func TestDoctorPlaud_DeveloperTokenStates(t *testing.T) {
	home := doctorPlaudTestHome(t)
	if c := findDoctorCheck(t, doctorPlaud(), "Plaud developer token"); c.Status != diag.Skipped {
		t.Errorf("missing file: status %v, want Skipped", c.Status)
	}
	writeDevTokenFile(t, home, time.Now().Add(20*time.Hour), "rt")
	if c := findDoctorCheck(t, doctorPlaud(), "Plaud developer token"); c.Status != diag.OK || strings.Contains(c.Detail, "valid") {
		t.Errorf("unexpired file: %v %q, want OK that does not claim validity", c.Status, c.Detail)
	}
	if err := os.WriteFile(filepath.Join(home, ".plaud", "tokens-mcp.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if c := findDoctorCheck(t, doctorPlaud(), "Plaud developer token"); c.Status != diag.Fail {
		t.Errorf("unreadable file: status %v, want Fail", c.Status)
	}
}
