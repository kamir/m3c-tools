package homeroot

import (
	"os"
	"runtime"
	"testing"
)

// TestOverrideAllowed_DecisionMatrix pins the canonical, single-sourced WIN-T8
// decision that verify, registry and the cmd/skillctl binary all now delegate to
// (WIN-09). It is a pure function of (goos, compiledIn), so it runs identically
// on every host, no runtime.GOOS skip, which keeps the windows/linux
// executed-test parity even for the windows-gate drift-guard.
func TestOverrideAllowed_DecisionMatrix(t *testing.T) {
	// Non-Windows: always honor $HOME, regardless of the compiled-in flag.
	for _, goos := range []string{"darwin", "linux"} {
		if !OverrideAllowed(goos, false) {
			t.Errorf("%s: $HOME must be honored (compiledIn=false)", goos)
		}
		if !OverrideAllowed(goos, true) {
			t.Errorf("%s: $HOME must be honored (compiledIn=true)", goos)
		}
	}
	// Windows: honor $HOME ONLY when the override is compiled in (dev/test tag);
	// a normal shipping build compiles CompiledIn=false → $HOME ignored.
	if OverrideAllowed("windows", false) {
		t.Error("windows: $HOME must be IGNORED when the override is not compiled in (no env escape hatch)")
	}
	if !OverrideAllowed("windows", true) {
		t.Error("windows: $HOME must be honored when the override is compiled in (allow_home_override_test tag)")
	}
}

// TestUserHome_HonorsSharedDecision proves UserHome() actually applies the
// OverrideAllowed decision for THIS build (goos = runtime.GOOS, compiledIn =
// CompiledIn). The three call sites (verify.userHome, registry.userHome,
// cmd/skillctl.userHome) each carry the identical per-site test, so a drift back
// to a second policy at any one site is caught behaviorally.
func TestUserHome_HonorsSharedDecision(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	got, err := UserHome()
	if err != nil {
		t.Fatalf("UserHome() error: %v", err)
	}
	if OverrideAllowed(runtime.GOOS, CompiledIn) {
		if got != tmp {
			t.Errorf("UserHome() = %q, want %q (override allowed on %s)", got, tmp, runtime.GOOS)
		}
	} else {
		want, _ := os.UserHomeDir()
		if got != want {
			t.Errorf("UserHome() = %q, want %q (override NOT allowed on %s)", got, want, runtime.GOOS)
		}
	}
}
