package er1

import (
	"fmt"
	"os"
	"testing"
)

// TestMain keeps the er1 unit tests off the developer's real OS keychain.
// hasDeviceTokenAuth() (via auth.HasStoredToken) now probes the keychain, which
// HOME=t.TempDir() cannot isolate; forcing the file backend restores
// deterministic, HOME-controlled token presence for these tests.
//
// FR-0096 adds a second such probe: LoadConfig falls back to the `aims-core-er1`
// Keychain item when the environment yields no usable key. On the maintainer's
// own Mac that item EXISTS, so without this stub the suite would quietly pass
// against a real credential and fail on any other machine. Tests that want the
// fallback set keychainLookup themselves (and reset keychainOnce).
func TestMain(m *testing.M) {
	home, err := os.MkdirTemp("", "m3c-er1-tests-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for name, value := range map[string]string{"HOME": home, "USERPROFILE": home, "M3C_TOKEN_STORE": "file"} {
		if err := os.Setenv(name, value); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	keychainLookup = func() string { return "" }
	code := m.Run()
	if err := os.RemoveAll(home); err != nil {
		fmt.Fprintln(os.Stderr, err)
		code = 1
	}
	os.Exit(code)
}
