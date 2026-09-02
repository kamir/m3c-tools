package verify

import "testing"

// TestHomeOverrideAllowed — WIN-T8 (WIN-09): on Windows an explicit $HOME may only
// override the trust-root security root when the override was COMPILED IN (the
// `allow_home_override_test` build tag) — there is no ambient-env escape hatch. On
// every other OS $HOME is always honored. The decision is a pure function of
// (goos, compiledIn), so this runs identically on all platforms — no runtime.GOOS
// skip, which keeps the windows/linux executed-test parity even for the
// windows-gate drift-guard.
func TestHomeOverrideAllowed(t *testing.T) {
	// Non-Windows: always honor $HOME, regardless of the compiled-in flag.
	for _, goos := range []string{"darwin", "linux"} {
		if !homeOverrideAllowed(goos, false) {
			t.Errorf("%s: $HOME must be honored (compiledIn=false)", goos)
		}
		if !homeOverrideAllowed(goos, true) {
			t.Errorf("%s: $HOME must be honored (compiledIn=true)", goos)
		}
	}
	// Windows: honor $HOME ONLY when the override is compiled in (dev/test tag);
	// a normal shipping build compiles homeOverrideCompiledIn=false → ignored.
	if homeOverrideAllowed("windows", false) {
		t.Error("windows: $HOME must be IGNORED when the override is not compiled in (no env escape hatch)")
	}
	if !homeOverrideAllowed("windows", true) {
		t.Error("windows: $HOME must be honored when the override is compiled in (allow_home_override_test tag)")
	}
}
