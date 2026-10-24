package auth

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	keyring "github.com/zalando/go-keyring"
)

// Establish an in-memory provider before every package test. Production policy
// is native-only; test binaries and child builds also use a private provider trap.
func TestMain(m *testing.M) {
	keyring.MockInit()
	os.Exit(m.Run())
}

func TestNativeSaveClearUsesOnlyMockEntry(t *testing.T) {
	keyring.MockInit() // Independently safe before any operation.
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("M3C_TOKEN_STORE", "keychain")
	if err := Save(sampleToken()); err != nil {
		t.Fatal(err)
	}
	if err := Clear(); err != nil {
		t.Fatal(err)
	}
	if _, err := keyring.Get(keyringService, keyringAccount); !errors.Is(err, keyring.ErrNotFound) {
		t.Fatal("native mock entry remained")
	}
	if _, err := os.Stat(filepath.Join(home, ".m3c-tools")); !os.IsNotExist(err) {
		t.Fatal("native management created filesystem state")
	}
}
