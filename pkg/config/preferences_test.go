package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPreferencesPath_RespectsHOME(t *testing.T) {
	t.Setenv("HOME", "/tmp/m3c-test-home")
	got := PreferencesPath()
	want := "/tmp/m3c-test-home/.m3c-tools/preferences.env"
	if got != want {
		t.Errorf("PreferencesPath() = %q, want %q", got, want)
	}
}

func TestLegacyPreferencesPath_RespectsHOME(t *testing.T) {
	t.Setenv("HOME", "/tmp/m3c-test-home")
	got := LegacyPreferencesPath()
	want := "/tmp/m3c-test-home/.m3c-tools.env"
	if got != want {
		t.Errorf("LegacyPreferencesPath() = %q, want %q", got, want)
	}
}

func TestPreferencesExist_FreshInstall(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if PreferencesExist() {
		t.Error("expected false on fresh install (no files), got true")
	}
}

func TestPreferencesExist_LegacyOnly(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.WriteFile(filepath.Join(home, ".m3c-tools.env"), []byte("X=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !PreferencesExist() {
		t.Error("expected true when legacy exists, got false")
	}
}

func TestPreferencesExist_CanonicalOnly(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".m3c-tools")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "preferences.env"), []byte("X=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !PreferencesExist() {
		t.Error("expected true when canonical exists, got false")
	}
}

func TestMigrateLegacyPreferences_FreshInstall(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	got, err := MigrateLegacyPreferences()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != filepath.Join(home, ".m3c-tools", "preferences.env") {
		t.Errorf("fresh install should return canonical path, got %q", got)
	}
}

func TestMigrateLegacyPreferences_MigratesContent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	legacy := filepath.Join(home, ".m3c-tools.env")
	const content = "M3C_WHISPER_MODEL=large-v3\nER1_RETRY_INTERVAL=120\n"
	if err := os.WriteFile(legacy, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := MigrateLegacyPreferences()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	canonical := filepath.Join(home, ".m3c-tools", "preferences.env")
	if got != canonical {
		t.Errorf("returned path = %q, want canonical %q", got, canonical)
	}

	canonicalData, err := os.ReadFile(canonical)
	if err != nil {
		t.Fatalf("canonical not created: %v", err)
	}
	if string(canonicalData) != content {
		t.Errorf("canonical content = %q, want %q", canonicalData, content)
	}

	// Legacy should still exist (annotated, not deleted).
	legacyData, err := os.ReadFile(legacy)
	if err != nil {
		t.Fatalf("legacy was deleted (should be preserved): %v", err)
	}
	if !bytesContain(legacyData, []byte("Migrated")) {
		t.Errorf("legacy not annotated: %q", legacyData)
	}
}

func TestMigrateLegacyPreferences_DoesNotOverwriteCanonical(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".m3c-tools")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	canonical := filepath.Join(dir, "preferences.env")
	if err := os.WriteFile(canonical, []byte("CANON=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".m3c-tools.env"), []byte("LEG=2\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := MigrateLegacyPreferences()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != canonical {
		t.Errorf("returned path = %q, want %q (canonical wins)", got, canonical)
	}
	data, _ := os.ReadFile(canonical)
	if string(data) != "CANON=1\n" {
		t.Errorf("canonical was clobbered: %q", data)
	}
}

func bytesContain(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}
