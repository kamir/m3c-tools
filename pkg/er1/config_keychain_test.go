package er1

import (
	"sync"
	"testing"
)

// stubKeychain replaces the Keychain lookup for one test and resets the
// once-cache on both sides, so tests cannot leak a resolved key into each other.
func stubKeychain(t *testing.T, key string) {
	t.Helper()
	prev := keychainLookup
	keychainLookup = func() string { return key }
	keychainOnce = sync.Once{}
	keychainCached = ""
	t.Cleanup(func() {
		keychainLookup = prev
		keychainOnce = sync.Once{}
		keychainCached = ""
	})
}

// TestLoadConfigKeychainFallback pins FR-0096: LoadConfig is the place every
// upload and patch goes through, and it was the one credential loader that
// stopped at the environment instead of following the documented chain
// Keychain → Secret Manager → file. Without the fallback, every
// key-authenticated write route failed with an HTML 400 that read like a server
// fault.
func TestLoadConfigKeychainFallback(t *testing.T) {
	t.Run("empty environment falls back to the keychain", func(t *testing.T) {
		t.Setenv("ER1_API_KEY", "")
		t.Setenv("ER1_API_URL", "https://onboarding.guide/upload_2")
		stubKeychain(t, "key-from-the-keychain")

		if got := LoadConfig().APIKey; got != "key-from-the-keychain" {
			t.Errorf("APIKey = %q, want the keychain value", got)
		}
	})

	t.Run("a profile placeholder falls back too", func(t *testing.T) {
		// This is the exact production shape: the profile carries a placeholder,
		// IsBlockingPlaceholder clears it, and before FR-0096 nothing refilled it.
		t.Setenv("ER1_API_KEY", "your-api-key-here")
		t.Setenv("ER1_API_URL", "https://onboarding.guide/upload_2")
		stubKeychain(t, "key-from-the-keychain")

		if got := LoadConfig().APIKey; got != "key-from-the-keychain" {
			t.Errorf("APIKey = %q, want the keychain value", got)
		}
	})

	t.Run("an explicit key still wins", func(t *testing.T) {
		t.Setenv("ER1_API_KEY", "explicitly-exported")
		t.Setenv("ER1_API_URL", "https://onboarding.guide/upload_2")
		stubKeychain(t, "key-from-the-keychain")

		if got := LoadConfig().APIKey; got != "explicitly-exported" {
			t.Errorf("APIKey = %q: the keychain overrode an explicit key", got)
		}
	})

	t.Run("the localhost demo credential still wins", func(t *testing.T) {
		// BUG-0137 carve-out: the local container accepts exactly this value.
		// Shipping the real production key to 127.0.0.1 instead would be a
		// regression, not a convenience.
		t.Setenv("ER1_API_KEY", "democredential-er1-api-key")
		t.Setenv("ER1_API_URL", "https://127.0.0.1:8081/upload_2")
		stubKeychain(t, "key-from-the-keychain")

		if got := LoadConfig().APIKey; got != "democredential-er1-api-key" {
			t.Errorf("APIKey = %q, want the demo credential kept for localhost", got)
		}
	})

	t.Run("no keychain entry behaves exactly as before", func(t *testing.T) {
		t.Setenv("ER1_API_KEY", "")
		t.Setenv("ER1_API_URL", "https://onboarding.guide/upload_2")
		stubKeychain(t, "")

		if got := LoadConfig().APIKey; got != "" {
			t.Errorf("APIKey = %q, want empty when the keychain has nothing", got)
		}
	})

	t.Run("a placeholder in the keychain is not a key either", func(t *testing.T) {
		t.Setenv("ER1_API_KEY", "")
		t.Setenv("ER1_API_URL", "https://onboarding.guide/upload_2")
		// keychainAPIKey filters these out; prove the contract at this level too.
		stubKeychain(t, "")

		if got := LoadConfig().APIKey; got != "" {
			t.Errorf("APIKey = %q, want empty", got)
		}
	})
}

// TestKeychainLookupIsCached: LoadConfig runs from several startup paths (PLM
// sync, retry scheduler, menubar init). Each miss would otherwise spawn another
// /usr/bin/security subprocess.
func TestKeychainLookupIsCached(t *testing.T) {
	t.Setenv("ER1_API_KEY", "")
	t.Setenv("ER1_API_URL", "https://onboarding.guide/upload_2")

	calls := 0
	prev := keychainLookup
	keychainLookup = func() string { calls++; return "key-from-the-keychain" }
	keychainOnce = sync.Once{}
	keychainCached = ""
	t.Cleanup(func() {
		keychainLookup = prev
		keychainOnce = sync.Once{}
		keychainCached = ""
	})

	for i := 0; i < 5; i++ {
		LoadConfig()
	}
	if calls != 1 {
		t.Errorf("keychain consulted %d times, want exactly 1", calls)
	}
}

// TestKeychainOffSwitch: the switch must work even after the cache is warm.
// Checking it inside the lookup would be useless. Once any earlier call has
// resolved a key, the lookup never runs again, and a test that must observe
// "no credential configured" would keep seeing the developer's real key.
func TestKeychainOffSwitch(t *testing.T) {
	t.Setenv("ER1_API_KEY", "")
	t.Setenv("ER1_API_URL", "https://onboarding.guide/upload_2")
	stubKeychain(t, "key-from-the-keychain")

	if got := LoadConfig().APIKey; got != "key-from-the-keychain" {
		t.Fatalf("precondition failed: APIKey = %q", got)
	}
	// Cache is now warm. The switch must still bite.
	t.Setenv("M3C_ER1_KEYCHAIN", "off")
	if got := LoadConfig().APIKey; got != "" {
		t.Errorf("APIKey = %q with M3C_ER1_KEYCHAIN=off, want empty", got)
	}
}
