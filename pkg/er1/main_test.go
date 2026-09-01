package er1

import (
	"os"
	"testing"
)

// TestMain keeps the er1 unit tests off the developer's real OS keychain.
// hasDeviceTokenAuth() (via auth.HasStoredToken) now probes the keychain, which
// HOME=t.TempDir() cannot isolate; forcing the file backend restores
// deterministic, HOME-controlled token presence for these tests.
func TestMain(m *testing.M) {
	os.Setenv("M3C_TOKEN_STORE", "file")
	os.Exit(m.Run())
}
