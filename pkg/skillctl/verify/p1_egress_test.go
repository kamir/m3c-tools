package verify

import "testing"

// TestHomeOverrideAllowed — WIN-T8 (WIN-09): on Windows an explicit $HOME may only
// override the trust-root security root when M3C_ALLOW_HOME_OVERRIDE=1; on every
// other OS $HOME is always honored. The decision is a pure function of (goos,
// flag), so this runs identically on all platforms — no runtime.GOOS skip, which
// keeps the windows/linux executed-test parity even for the windows-gate
// drift-guard.
func TestHomeOverrideAllowed(t *testing.T) {
	for _, goos := range []string{"darwin", "linux"} {
		if !homeOverrideAllowed(goos, "") {
			t.Errorf("%s: $HOME must be honored with no flag", goos)
		}
		if !homeOverrideAllowed(goos, "1") {
			t.Errorf("%s: $HOME must be honored with the flag", goos)
		}
	}
	if homeOverrideAllowed("windows", "") {
		t.Error("windows: $HOME must be IGNORED without M3C_ALLOW_HOME_OVERRIDE")
	}
	if homeOverrideAllowed("windows", "0") {
		t.Error("windows: $HOME must be IGNORED when the flag is not exactly 1")
	}
	if !homeOverrideAllowed("windows", "1") {
		t.Error("windows: $HOME must be honored with M3C_ALLOW_HOME_OVERRIDE=1")
	}
	if !homeOverrideAllowed("windows", " 1 ") {
		t.Error("windows: a whitespace-padded flag value of 1 must still honor $HOME")
	}
}
