package auth

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	keyring "github.com/zalando/go-keyring"
)

// Establish an in-memory provider before every package test, including tests
// whose explicit file backend still reaches the legacy direct keyring Clear.
func TestMain(m *testing.M) {
	keyring.MockInit()
	os.Exit(m.Run())
}

func TestFileSaveDeletesOnlyMockKeyringEntry(t *testing.T) {
	keyring.MockInit() // Independently isolate this test before any Set.
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("M3C_TOKEN_STORE", "file")
	// These service/account coordinates exercise the actual legacy Save -> Clear
	// route, after TestMain has replaced the provider with in-memory storage.
	if err := keyring.Set(keyringService, keyringAccount, "synthetic-stale-entry"); err != nil {
		t.Fatal(err)
	}
	if err := Save(&DeviceToken{Token: "synthetic-new-token", DeviceID: "synthetic-device", UserID: "synthetic-user"}); err != nil {
		t.Fatal(err)
	}
	if _, err := keyring.Get(keyringService, keyringAccount); !errors.Is(err, keyring.ErrNotFound) {
		t.Fatal("legacy Clear did not remove mock entry")
	}
	if _, err := os.Stat(filepath.Join(home, ".m3c-tools", "device-token.enc")); err != nil {
		t.Fatal("synthetic file token not saved")
	}
}
