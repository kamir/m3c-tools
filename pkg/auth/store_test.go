package auth

import (
	"os"
	"path/filepath"
	"testing"

	keyring "github.com/zalando/go-keyring"
)

func sampleToken() *DeviceToken {
	return &DeviceToken{
		Token:     "bearer-abc123",
		UserID:    "107677460544181387647",
		ContextID: "107677460544181387647___mft",
		DeviceID:  "test-host",
		SavedAt:   "2026-06-09T00:00:00Z",
	}
}

// isolate points HOME at a temp dir (so the file backend writes there), clears
// the keychain kill-switch, and installs an in-memory mock keychain so tests
// never touch the developer's real OS keychain.
func isolate(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("M3C_TOKEN_STORE", "") // keychain-first (mock provider)
	keyring.MockInit()
}

func TestSaveLoad_RoundTripViaKeychain(t *testing.T) {
	isolate(t)

	if err := Save(sampleToken()); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// The keychain holds it; the legacy file must NOT have been written.
	if (fileStore{}).Has() {
		t.Errorf("file backend should be empty after a keychain Save")
	}
	if name := ActiveStoreName(); name != "keychain" {
		t.Errorf("ActiveStoreName = %q, want keychain", name)
	}

	got, err := Load("test-host", "107677460544181387647")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got == nil || got.Token != "bearer-abc123" {
		t.Fatalf("Load returned %+v, want token bearer-abc123", got)
	}
}

func TestLoad_MigratesLegacyFileIntoKeychain(t *testing.T) {
	isolate(t)

	// Seed the legacy encrypted file directly via the file backend.
	if err := (fileStore{}).Save(sampleToken()); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if !(fileStore{}).Has() {
		t.Fatalf("precondition: file should exist")
	}

	// Load should return the token AND migrate it into the keychain.
	got, err := Load("test-host", "107677460544181387647")
	if err != nil || got == nil {
		t.Fatalf("Load after seed: got=%+v err=%v", got, err)
	}
	if (fileStore{}).Has() {
		t.Errorf("legacy file should be removed after migration")
	}
	if !(keyringStore{}).Has() {
		t.Errorf("token should now live in the keychain")
	}
}

func TestForceFileBackend_KillSwitch(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	keyring.MockInit()
	t.Setenv("M3C_TOKEN_STORE", "file") // force file backend

	if err := Save(sampleToken()); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if !(fileStore{}).Has() {
		t.Errorf("file backend should hold the token when forced")
	}
	// The (mock) keychain must remain untouched.
	if (keyringStore{}).Has() {
		t.Errorf("keychain should be empty when M3C_TOKEN_STORE=file")
	}
	if name := ActiveStoreName(); name != "file" {
		t.Errorf("ActiveStoreName = %q, want file", name)
	}

	got, err := Load("test-host", "107677460544181387647")
	if err != nil || got == nil || got.Token != "bearer-abc123" {
		t.Fatalf("Load (file mode): got=%+v err=%v", got, err)
	}
}

func TestClear_RemovesFromBothBackends(t *testing.T) {
	isolate(t)

	if err := Save(sampleToken()); err != nil { // -> keychain
		t.Fatalf("Save: %v", err)
	}
	// Also drop a stale file to prove Clear wipes both.
	if err := (fileStore{}).Save(sampleToken()); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	if err := Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if HasStoredToken() {
		t.Errorf("HasStoredToken should be false after Clear")
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("HOME"), ".m3c-tools", "device-token.enc")); err == nil {
		t.Errorf("device-token.enc should be gone after Clear")
	}
}

// Regression (security review, MEDIUM): a token saved to the keychain must not
// shadow a newer token written to the file backend while the kill-switch was on.
// After re-enabling the keychain, Load must return the newer (file) token.
func TestSave_FileBackendClearsStaleKeychainEntry(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	keyring.MockInit()

	// 1) Normal save -> keychain holds the OLD token.
	old := sampleToken()
	old.Token = "OLD-keychain-token"
	t.Setenv("M3C_TOKEN_STORE", "") // keychain-first
	if err := Save(old); err != nil {
		t.Fatalf("save old: %v", err)
	}
	if !(keyringStore{}).Has() {
		t.Fatalf("precondition: keychain should hold the old token")
	}

	// 2) Re-login while forced to the file backend -> writes NEW token to file
	//    and must drop the stale keychain entry.
	fresh := sampleToken()
	fresh.Token = "NEW-file-token"
	t.Setenv("M3C_TOKEN_STORE", "file")
	if err := Save(fresh); err != nil {
		t.Fatalf("save fresh: %v", err)
	}
	if (keyringStore{}).Has() {
		t.Errorf("stale keychain entry must be cleared after a file-backend save")
	}

	// 3) Keychain re-enabled: Load must NOT return the stale keychain token.
	t.Setenv("M3C_TOKEN_STORE", "")
	got, err := Load("test-host", "107677460544181387647")
	if err != nil || got == nil {
		t.Fatalf("load after re-enable: got=%+v err=%v", got, err)
	}
	if got.Token != "NEW-file-token" {
		t.Errorf("Load returned %q, want NEW-file-token (stale keychain shadowed the file)", got.Token)
	}
}

func TestLoad_NoTokenAnywhere(t *testing.T) {
	isolate(t)
	got, err := Load("test-host", "107677460544181387647")
	if err != nil {
		t.Fatalf("Load on empty stores should not error: %v", err)
	}
	if got != nil {
		t.Errorf("Load = %+v, want nil", got)
	}
	if HasStoredToken() {
		t.Errorf("HasStoredToken should be false on empty stores")
	}
}
