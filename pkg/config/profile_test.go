package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseEnvFile(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "test.env")

	content := `# M3C Profile: mytest
# Description: Test profile for unit tests
# Created: 2026-04-02

ER1_API_URL=https://example.com/upload_2
ER1_API_KEY=secret-key-1234567890
ER1_VERIFY_SSL=true
CUSTOM_VAR="quoted value"
`
	if err := os.WriteFile(envPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	p, err := ParseEnvFile(envPath)
	if err != nil {
		t.Fatalf("ParseEnvFile: %v", err)
	}

	if p.Name != "mytest" {
		t.Errorf("Name = %q, want %q", p.Name, "mytest")
	}
	if p.Description != "Test profile for unit tests" {
		t.Errorf("Description = %q, want %q", p.Description, "Test profile for unit tests")
	}
	if p.Vars["ER1_API_URL"] != "https://example.com/upload_2" {
		t.Errorf("ER1_API_URL = %q", p.Vars["ER1_API_URL"])
	}
	if p.Vars["ER1_API_KEY"] != "secret-key-1234567890" {
		t.Errorf("ER1_API_KEY = %q", p.Vars["ER1_API_KEY"])
	}
	if p.Vars["CUSTOM_VAR"] != "quoted value" {
		t.Errorf("CUSTOM_VAR = %q, want %q", p.Vars["CUSTOM_VAR"], "quoted value")
	}
}

func TestParseEnvFileNoMetadata(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, "plain.env")

	content := `ER1_API_URL=https://localhost/upload_2
ER1_API_KEY=abc
`
	if err := os.WriteFile(envPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	p, err := ParseEnvFile(envPath)
	if err != nil {
		t.Fatalf("ParseEnvFile: %v", err)
	}

	// Name should be derived from filename.
	if p.Name != "plain" {
		t.Errorf("Name = %q, want %q", p.Name, "plain")
	}
	if p.Description != "" {
		t.Errorf("Description = %q, want empty", p.Description)
	}
	if p.Vars["ER1_API_URL"] != "https://localhost/upload_2" {
		t.Errorf("ER1_API_URL = %q", p.Vars["ER1_API_URL"])
	}
}

func TestCreateProfileAndGetProfile(t *testing.T) {
	dir := t.TempDir()
	pm := &ProfileManager{BaseDir: dir}

	vars := map[string]string{
		"ER1_API_URL": "https://test.example.com/upload_2",
		"ER1_API_KEY": "test-key-abc123",
		"CUSTOM":      "hello",
	}

	if err := pm.CreateProfile("staging", "Staging server", vars); err != nil {
		t.Fatalf("CreateProfile: %v", err)
	}

	// Verify file exists.
	path := filepath.Join(dir, ProfilesDir, "staging.env")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("profile file not created: %v", err)
	}

	// Read it back.
	p, err := pm.GetProfile("staging")
	if err != nil {
		t.Fatalf("GetProfile: %v", err)
	}

	if p.Name != "staging" {
		t.Errorf("Name = %q, want %q", p.Name, "staging")
	}
	if p.Description != "Staging server" {
		t.Errorf("Description = %q, want %q", p.Description, "Staging server")
	}
	if p.Vars["ER1_API_URL"] != "https://test.example.com/upload_2" {
		t.Errorf("ER1_API_URL = %q", p.Vars["ER1_API_URL"])
	}
	if p.Vars["ER1_API_KEY"] != "test-key-abc123" {
		t.Errorf("ER1_API_KEY = %q", p.Vars["ER1_API_KEY"])
	}
	if p.Vars["CUSTOM"] != "hello" {
		t.Errorf("CUSTOM = %q", p.Vars["CUSTOM"])
	}
}

func TestListProfiles(t *testing.T) {
	dir := t.TempDir()
	pm := &ProfileManager{BaseDir: dir}

	// Create a few profiles.
	_ = pm.CreateProfile("alpha", "First", map[string]string{"ER1_API_URL": "https://a"})
	_ = pm.CreateProfile("beta", "Second", map[string]string{"ER1_API_URL": "https://b"})

	profiles, err := pm.ListProfiles()
	if err != nil {
		t.Fatalf("ListProfiles: %v", err)
	}

	if len(profiles) != 2 {
		t.Fatalf("got %d profiles, want 2", len(profiles))
	}

	names := map[string]bool{}
	for _, p := range profiles {
		names[p.Name] = true
	}
	if !names["alpha"] || !names["beta"] {
		t.Errorf("expected alpha and beta, got %v", names)
	}
}

func TestEnsureDefaults(t *testing.T) {
	dir := t.TempDir()
	pm := &ProfileManager{BaseDir: dir}

	if err := pm.EnsureDefaults(); err != nil {
		t.Fatalf("EnsureDefaults: %v", err)
	}

	// Should have created dev.env and cloud.env.
	profiles, err := pm.ListProfiles()
	if err != nil {
		t.Fatalf("ListProfiles: %v", err)
	}

	names := map[string]bool{}
	for _, p := range profiles {
		names[p.Name] = true
	}
	if !names["dev"] {
		t.Error("missing dev profile")
	}
	if !names["cloud"] {
		t.Error("missing cloud profile")
	}

	// Active profile should be "dev".
	active := pm.ActiveProfileName()
	if active != "dev" {
		t.Errorf("active = %q, want %q", active, "dev")
	}
}

func TestSwitchProfile(t *testing.T) {
	dir := t.TempDir()
	pm := &ProfileManager{BaseDir: dir}

	_ = pm.CreateProfile("one", "First", map[string]string{"ER1_API_URL": "https://one"})
	_ = pm.CreateProfile("two", "Second", map[string]string{"ER1_API_URL": "https://two"})
	_ = pm.writeActiveProfile("one")

	if err := pm.SwitchProfile("two"); err != nil {
		t.Fatalf("SwitchProfile: %v", err)
	}

	active := pm.ActiveProfileName()
	if active != "two" {
		t.Errorf("active = %q, want %q", active, "two")
	}

	// Environment should reflect the switched profile.
	if got := os.Getenv("ER1_API_URL"); got != "https://two" {
		t.Errorf("ER1_API_URL = %q, want %q", got, "https://two")
	}
}

func TestApplyProfileSetsEnvVars(t *testing.T) {
	// Clear any existing value.
	os.Unsetenv("ER1_API_URL")
	os.Unsetenv("TEST_PROFILE_VAR")

	p := &Profile{
		Name: "test",
		Vars: map[string]string{
			"ER1_API_URL":      "https://applied.example.com/upload_2",
			"TEST_PROFILE_VAR": "profile_value",
		},
	}

	pm := &ProfileManager{BaseDir: t.TempDir()}
	if err := pm.ApplyProfile(p); err != nil {
		t.Fatalf("ApplyProfile: %v", err)
	}

	if got := os.Getenv("ER1_API_URL"); got != "https://applied.example.com/upload_2" {
		t.Errorf("ER1_API_URL = %q", got)
	}
	if got := os.Getenv("TEST_PROFILE_VAR"); got != "profile_value" {
		t.Errorf("TEST_PROFILE_VAR = %q", got)
	}

	// Clean up.
	os.Unsetenv("TEST_PROFILE_VAR")
}

func TestDeleteProfile(t *testing.T) {
	dir := t.TempDir()
	pm := &ProfileManager{BaseDir: dir}

	_ = pm.CreateProfile("deleteme", "To delete", map[string]string{"X": "1"})
	_ = pm.CreateProfile("keep", "To keep", map[string]string{"X": "2"})
	_ = pm.writeActiveProfile("keep")

	// Should succeed: not active.
	if err := pm.DeleteProfile("deleteme"); err != nil {
		t.Fatalf("DeleteProfile: %v", err)
	}

	// Verify file is gone.
	path := filepath.Join(dir, ProfilesDir, "deleteme.env")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("profile file should have been deleted")
	}

	// Should fail: profile is active.
	if err := pm.DeleteProfile("keep"); err == nil {
		t.Error("expected error when deleting active profile")
	}
}

func TestDeleteProfileNotFound(t *testing.T) {
	dir := t.TempDir()
	pm := &ProfileManager{BaseDir: dir}

	if err := pm.DeleteProfile("nonexistent"); err == nil {
		t.Error("expected error for nonexistent profile")
	}
}

func TestImportProfile(t *testing.T) {
	dir := t.TempDir()
	pm := &ProfileManager{BaseDir: dir}

	// Create a source .env file outside the profiles dir.
	srcPath := filepath.Join(dir, "external.env")
	content := `# Description: External config
ER1_API_URL=https://imported.example.com/upload_2
ER1_API_KEY=imported-key-xyz
EXTRA=imported_extra
`
	if err := os.WriteFile(srcPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	if err := pm.ImportProfile("imported", srcPath); err != nil {
		t.Fatalf("ImportProfile: %v", err)
	}

	// Verify the profile was created.
	p, err := pm.GetProfile("imported")
	if err != nil {
		t.Fatalf("GetProfile: %v", err)
	}

	if p.Vars["ER1_API_URL"] != "https://imported.example.com/upload_2" {
		t.Errorf("ER1_API_URL = %q", p.Vars["ER1_API_URL"])
	}
	if p.Vars["ER1_API_KEY"] != "imported-key-xyz" {
		t.Errorf("ER1_API_KEY = %q", p.Vars["ER1_API_KEY"])
	}
	if p.Vars["EXTRA"] != "imported_extra" {
		t.Errorf("EXTRA = %q", p.Vars["EXTRA"])
	}
	if p.Description != "External config" {
		t.Errorf("Description = %q, want %q", p.Description, "External config")
	}
}

func TestMaskAPIKey(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", "(not set)"},
		{"short", "****"},
		{"abcd5678xy", "abcd****78xy"},
		{"democredential-er1-api-key", "demo****-key"},
	}
	for _, tt := range tests {
		got := MaskAPIKey(tt.input)
		if got != tt.want {
			t.Errorf("MaskAPIKey(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestActiveProfileNoFile(t *testing.T) {
	dir := t.TempDir()
	pm := &ProfileManager{BaseDir: dir}

	name := pm.ActiveProfileName()
	if name != "" {
		t.Errorf("expected empty active profile name, got %q", name)
	}

	_, err := pm.ActiveProfile()
	if err == nil {
		t.Error("expected error when no active profile is set")
	}
}

func TestSwitchProfileNonexistent(t *testing.T) {
	dir := t.TempDir()
	pm := &ProfileManager{BaseDir: dir}

	if err := pm.SwitchProfile("doesnotexist"); err == nil {
		t.Error("expected error when switching to nonexistent profile")
	}
}

func TestCreateProfileEmptyName(t *testing.T) {
	dir := t.TempDir()
	pm := &ProfileManager{BaseDir: dir}

	if err := pm.CreateProfile("", "desc", map[string]string{}); err == nil {
		t.Error("expected error for empty profile name")
	}
}

func TestImportProfileEmptyName(t *testing.T) {
	dir := t.TempDir()
	pm := &ProfileManager{BaseDir: dir}

	if err := pm.ImportProfile("", "/some/file.env"); err == nil {
		t.Error("expected error for empty profile name")
	}
}

func TestLegacyFallbackWhenNoProfilesDir(t *testing.T) {
	// This tests the scenario where there's no profiles directory.
	// ActiveProfile should return an error, signaling the caller
	// to fall back to legacy .env loading.
	dir := t.TempDir()
	// Do NOT call EnsureDefaults — simulate pre-profile installation.
	pm := &ProfileManager{BaseDir: dir}

	_, err := pm.ActiveProfile()
	if err == nil {
		t.Error("expected error when no active profile file exists")
	}
}
