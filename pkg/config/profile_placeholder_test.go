package config

import (
	"os"
	"testing"
)

// TestApplyProfilePlaceholderDoesNotClobber pins FR-0096: a profile entry that is
// a PLACEHOLDER must not overwrite a value someone deliberately exported. A
// placeholder is the profile saying "nothing stored here" — usually on purpose,
// because the real key belongs in the Keychain — and letting it win replaced a
// working credential with one the very next function recognises as unusable.
func TestApplyProfilePlaceholderDoesNotClobber(t *testing.T) {
	pm := NewProfileManager()

	t.Run("placeholder loses against a set variable", func(t *testing.T) {
		t.Setenv("ER1_API_KEY", "a-real-looking-key")
		if err := pm.ApplyProfile(&Profile{Name: "cloud", Vars: map[string]string{
			"ER1_API_KEY": "your-api-key-here",
		}}); err != nil {
			t.Fatalf("ApplyProfile: %v", err)
		}
		if got := os.Getenv("ER1_API_KEY"); got != "a-real-looking-key" {
			t.Errorf("exported key was replaced by the placeholder: got %q", got)
		}
	})

	t.Run("the empty string is a placeholder too", func(t *testing.T) {
		t.Setenv("ER1_API_KEY", "a-real-looking-key")
		if err := pm.ApplyProfile(&Profile{Name: "cloud", Vars: map[string]string{
			"ER1_API_KEY": "",
		}}); err != nil {
			t.Fatalf("ApplyProfile: %v", err)
		}
		if got := os.Getenv("ER1_API_KEY"); got != "a-real-looking-key" {
			t.Errorf("exported key was cleared by an empty profile value: got %q", got)
		}
	})

	// The other half of the rule, unchanged: the profile is the TARGET SELECTOR.
	// A stale ER1_API_URL in someone's shell must not defeat a profile switch.
	t.Run("a real profile value still wins", func(t *testing.T) {
		t.Setenv("ER1_API_KEY", "stale-key-from-an-old-shell")
		t.Setenv("ER1_API_URL", "https://127.0.0.1:8081/upload_2")
		if err := pm.ApplyProfile(&Profile{Name: "cloud", Vars: map[string]string{
			"ER1_API_KEY": "the-profiles-own-key",
			"ER1_API_URL": "https://onboarding.guide/upload_2",
		}}); err != nil {
			t.Fatalf("ApplyProfile: %v", err)
		}
		if got := os.Getenv("ER1_API_KEY"); got != "the-profiles-own-key" {
			t.Errorf("profile key did not win: got %q", got)
		}
		if got := os.Getenv("ER1_API_URL"); got != "https://onboarding.guide/upload_2" {
			t.Errorf("profile switch was defeated by a stale env var: got %q", got)
		}
	})

	t.Run("placeholder still applies when nothing is set", func(t *testing.T) {
		os.Unsetenv("ER1_API_KEY")
		t.Cleanup(func() { os.Unsetenv("ER1_API_KEY") })
		if err := pm.ApplyProfile(&Profile{Name: "cloud", Vars: map[string]string{
			"ER1_API_KEY": "changeme",
		}}); err != nil {
			t.Fatalf("ApplyProfile: %v", err)
		}
		// Nothing was displaced, so the profile value lands as before — doctor
		// still gets to see and report the placeholder.
		if got := os.Getenv("ER1_API_KEY"); got != "changeme" {
			t.Errorf("profile value did not land on an unset variable: got %q", got)
		}
	})
}
