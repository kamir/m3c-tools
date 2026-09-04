package main

import (
	"os"
	"runtime"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/homeroot"
)

// TestUserHome_HonorsSharedDecision, WIN-T8 (WIN-09) parity: the cmd/skillctl
// userHome must apply the SINGLE shared $HOME-on-Windows decision
// (homeroot.OverrideAllowed), the same one the verify and registry packages use.
// This closes the former footgun where the CLI copy honored $HOME on ALL
// platforms with no Windows guard, and, together with the identical per-site
// tests in verify and registry, guards against any one site drifting back into a
// second policy. No runtime.GOOS skip → windows/linux executed-test parity stays
// even for the windows-gate drift-guard.
func TestUserHome_HonorsSharedDecision(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	got, err := userHome()
	if err != nil {
		t.Fatalf("userHome() error: %v", err)
	}
	if homeroot.OverrideAllowed(runtime.GOOS, homeroot.CompiledIn) {
		if got != tmp {
			t.Errorf("userHome() = %q, want %q (override allowed on %s)", got, tmp, runtime.GOOS)
		}
	} else {
		want, _ := os.UserHomeDir()
		if got != want {
			t.Errorf("userHome() = %q, want %q (override NOT allowed on %s)", got, want, runtime.GOOS)
		}
	}
}
