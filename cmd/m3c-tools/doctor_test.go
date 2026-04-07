// doctor_test.go — Unit tests for the doctor command section functions.
//
// These tests run in package main and exercise the individual diagnostic
// section builders without requiring a running ER1 server.
package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kamir/m3c-tools/pkg/diag"
)

func TestDoctorProfile_NoProfile(t *testing.T) {
	// Point HOME at an empty temp dir so no profile is found.
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	s := doctorProfile()
	if s.Title != "Profile" {
		t.Errorf("section title = %q, want Profile", s.Title)
	}
	if len(s.Checks) == 0 {
		t.Fatal("expected at least one check")
	}
	// With no profile configured, the active-profile check should fail.
	if s.Checks[0].Status != diag.Fail {
		t.Errorf("active profile status = %v, want Fail", s.Checks[0].Status)
	}
}

func TestDoctorProfile_WithActiveProfile(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	// Create profile directory structure.
	profilesDir := filepath.Join(tmp, ".m3c-tools", "profiles")
	if err := os.MkdirAll(profilesDir, 0700); err != nil {
		t.Fatal(err)
	}
	// Write a profile file.
	profileContent := "ER1_API_URL=https://test.example.com/upload_2\nER1_API_KEY=test-key\n"
	if err := os.WriteFile(filepath.Join(profilesDir, "test.env"), []byte(profileContent), 0600); err != nil {
		t.Fatal(err)
	}
	// Write the active-profile pointer.
	if err := os.WriteFile(filepath.Join(tmp, ".m3c-tools", "active-profile"), []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}

	s := doctorProfile()
	if len(s.Checks) < 2 {
		t.Fatalf("expected at least 2 checks, got %d", len(s.Checks))
	}
	if s.Checks[0].Status != diag.OK {
		t.Errorf("active profile check status = %v, want OK (detail: %s)", s.Checks[0].Status, s.Checks[0].Detail)
	}
	if s.Checks[1].Status != diag.OK {
		t.Errorf("profile file check status = %v, want OK (detail: %s)", s.Checks[1].Status, s.Checks[1].Detail)
	}
}

func TestDoctorAuth_TokenOnly(t *testing.T) {
	t.Setenv("ER1_DEVICE_TOKEN", "fake-test-token")
	t.Setenv("ER1_API_KEY", "")
	os.Unsetenv("ER1_API_KEY")

	s := doctorAuth()
	if s.Title != "Authentication" {
		t.Errorf("section title = %q, want Authentication", s.Title)
	}

	// Find the auth method check.
	found := false
	for _, c := range s.Checks {
		if c.Name == "Auth method" {
			found = true
			if c.Status != diag.OK {
				t.Errorf("auth method status = %v, want OK", c.Status)
			}
			if c.Detail != "Bearer token (SPEC-0127)" {
				t.Errorf("auth method detail = %q, want 'Bearer token (SPEC-0127)'", c.Detail)
			}
		}
	}
	if !found {
		t.Error("auth method check not found in section")
	}
}

func TestDoctorAuth_NoAuth(t *testing.T) {
	t.Setenv("ER1_DEVICE_TOKEN", "")
	os.Unsetenv("ER1_DEVICE_TOKEN")
	t.Setenv("ER1_API_KEY", "")
	os.Unsetenv("ER1_API_KEY")

	s := doctorAuth()

	// Auth method should show failure.
	for _, c := range s.Checks {
		if c.Name == "Auth method" {
			if c.Status != diag.Fail {
				t.Errorf("auth method status = %v, want Fail", c.Status)
			}
			if c.Detail != "NO AUTH — run 'm3c-tools login' or set ER1_API_KEY" {
				t.Errorf("auth method detail = %q", c.Detail)
			}
		}
	}
}

func TestDoctorAuth_APIKeyOnly(t *testing.T) {
	t.Setenv("ER1_DEVICE_TOKEN", "")
	os.Unsetenv("ER1_DEVICE_TOKEN")
	t.Setenv("ER1_API_KEY", "test-api-key-1234")

	s := doctorAuth()

	for _, c := range s.Checks {
		if c.Name == "Auth method" {
			if c.Status != diag.Warn {
				t.Errorf("auth method status = %v, want Warn (legacy API key)", c.Status)
			}
		}
	}
}

func TestDoctorConfigConsistency_AllSet(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("ER1_API_URL", "https://test.example.com/upload_2")
	t.Setenv("ER1_CONTEXT_ID", "user123___mft")
	t.Setenv("ER1_VERIFY_SSL", "true")

	s := doctorConfigConsistency()
	if s.Title != "Config Consistency" {
		t.Errorf("section title = %q, want 'Config Consistency'", s.Title)
	}

	// ER1_API_URL check should be OK.
	for _, c := range s.Checks {
		if c.Name == "ER1_API_URL" {
			if c.Status != diag.OK {
				t.Errorf("ER1_API_URL status = %v, want OK (detail: %s)", c.Status, c.Detail)
			}
		}
	}
}

func TestDoctorConfigConsistency_NoURL(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("ER1_API_URL", "")
	os.Unsetenv("ER1_API_URL")
	t.Setenv("ER1_CONTEXT_ID", "")
	os.Unsetenv("ER1_CONTEXT_ID")

	s := doctorConfigConsistency()

	for _, c := range s.Checks {
		if c.Name == "ER1_API_URL" {
			if c.Status != diag.Fail {
				t.Errorf("ER1_API_URL status = %v, want Fail", c.Status)
			}
		}
	}
}

func TestDoctorConnectivity_NoURL(t *testing.T) {
	t.Setenv("ER1_API_URL", "")
	os.Unsetenv("ER1_API_URL")

	s := doctorConnectivity()
	if s.Title != "Connectivity" {
		t.Errorf("section title = %q, want Connectivity", s.Title)
	}

	// With the default localhost URL, DNS should still resolve (127.0.0.1).
	// But the actual test is that the function doesn't panic.
	if len(s.Checks) == 0 {
		t.Error("expected at least one connectivity check")
	}
}

func TestDoctorConnectivity_LocalhostSkipsTLS(t *testing.T) {
	t.Setenv("ER1_API_URL", "https://127.0.0.1:8081/upload_2")
	t.Setenv("ER1_VERIFY_SSL", "false")

	s := doctorConnectivity()

	// The TLS check should not be present for 127.0.0.1 when using http
	// or when it fails gracefully. Just ensure no panic and checks exist.
	if len(s.Checks) == 0 {
		t.Error("expected at least one connectivity check")
	}
}

func TestDoctorPlaud_NoToken(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	// Ensure PLAUD_TOKEN_FILE points to nonexistent file.
	t.Setenv("PLAUD_TOKEN_FILE", filepath.Join(tmp, "nonexistent-token.json"))

	s := doctorPlaud()
	if s.Title != "Plaud" {
		t.Errorf("section title = %q, want Plaud", s.Title)
	}

	if len(s.Checks) == 0 {
		t.Fatal("expected at least one check")
	}
	// With no token file, status should be Skipped.
	if s.Checks[0].Status != diag.Skipped {
		t.Errorf("plaud token status = %v, want Skipped (detail: %s)", s.Checks[0].Status, s.Checks[0].Detail)
	}
}

func TestDoctorDevices_NoAuth(t *testing.T) {
	t.Setenv("ER1_DEVICE_TOKEN", "")
	os.Unsetenv("ER1_DEVICE_TOKEN")
	t.Setenv("ER1_API_KEY", "")
	os.Unsetenv("ER1_API_KEY")

	s := doctorDevices()
	if s.Title != "Device Pairing" {
		t.Errorf("section title = %q, want 'Device Pairing'", s.Title)
	}

	if len(s.Checks) == 0 {
		t.Fatal("expected at least one check")
	}
	// No auth means devices check should be skipped.
	if s.Checks[0].Status != diag.Skipped {
		t.Errorf("devices status = %v, want Skipped (detail: %s)", s.Checks[0].Status, s.Checks[0].Detail)
	}
}

func TestMaskID(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"short", "short"},
		{"exactly10!", "exactly10!"},
		{"a-very-long-identifier-123", "a-ver...123"},
	}
	for _, tt := range tests {
		got := maskID(tt.in)
		if got != tt.want {
			t.Errorf("maskID(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
