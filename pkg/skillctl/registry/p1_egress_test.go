package registry

import "testing"

// TestER1TLSGuardNonLoopback — CD-T10 (CD-11): the registry ER1 client must
// refuse to disable TLS verification (VerifySSL=false) against a non-loopback
// host, as defense-in-depth behind the er1.Config LoadConfig-time sanitizer (a
// programmatically-built Config can carry VerifySSL=false + a public APIURL and
// would otherwise slip an InsecureSkipVerify transport straight onto the wire).
// Verification stays enabled (guard returns nil, nothing skipped) or is refused
// (error) — it is never silently bypassed for a public host.
func TestER1TLSGuardNonLoopback(t *testing.T) {
	// VerifySSL on → never refused, whatever the host.
	if err := er1TLSGuard("https://onboarding.guide/upload_2", true); err != nil {
		t.Errorf("VerifySSL=true must never be refused: %v", err)
	}

	// VerifySSL off against a PUBLIC host → refused (fail closed).
	if err := er1TLSGuard("https://onboarding.guide/upload_2", false); err == nil {
		t.Error("VerifySSL=false against a public host must be refused")
	}

	// VerifySSL off against loopback / localhost / RFC1918 → allowed (local dev
	// with a self-signed cert). Mirrors netguard.IsLoopbackOrPrivate.
	for _, base := range []string{
		"https://127.0.0.1:8081/upload_2",
		"https://localhost:8081",
		"https://192.168.1.10:8081",
		"https://[::1]:8081",
	} {
		if err := er1TLSGuard(base, false); err != nil {
			t.Errorf("VerifySSL=false against local target %q must proceed: %v", base, err)
		}
	}
}

// TestHomeOverrideAllowed — WIN-T8 (WIN-09): on Windows an explicit $HOME may only
// override the per-user security root (token key, trust roots) when
// M3C_ALLOW_HOME_OVERRIDE=1; on every other OS $HOME is always honored. The
// decision is a pure function of (goos, flag), so this runs identically on all
// platforms — no runtime.GOOS skip, which keeps the windows/linux executed-test
// parity even for the windows-gate drift-guard.
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
