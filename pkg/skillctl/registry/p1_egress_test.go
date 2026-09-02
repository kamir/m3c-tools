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

	// VerifySSL off against a non-loopback host → refused (fail closed). This is
	// LOOPBACK-ONLY, matching pkg/er1.applyTLSVerificationPolicy: an RFC1918 LAN
	// host (192.168.x) is refused here too, because the core ER1 client already
	// forces verification back on for it. A public host is likewise refused.
	for _, base := range []string{
		"https://onboarding.guide/upload_2", // public
		"https://192.168.1.10:8081",         // RFC1918 — no longer permitted (FIX 2)
		"https://10.0.0.5:8081",             // RFC1918
	} {
		if err := er1TLSGuard(base, false); err == nil {
			t.Errorf("VerifySSL=false against non-loopback host %q must be refused", base)
		}
	}

	// VerifySSL off against loopback / localhost only → allowed (local dev with a
	// self-signed cert). Mirrors netguard.IsLoopback.
	for _, base := range []string{
		"https://127.0.0.1:8081/upload_2",
		"https://localhost:8081",
		"https://[::1]:8081",
	} {
		if err := er1TLSGuard(base, false); err != nil {
			t.Errorf("VerifySSL=false against loopback target %q must proceed: %v", base, err)
		}
	}
}

// TestHomeOverrideAllowed — WIN-T8 (WIN-09): on Windows an explicit $HOME may only
// override the per-user security root (token key, trust roots) when the override
// was COMPILED IN (the `allow_home_override_test` build tag) — there is no
// ambient-env escape hatch. On every other OS $HOME is always honored. The
// decision is a pure function of (goos, compiledIn), so this runs identically on
// all platforms — no runtime.GOOS skip, which keeps the windows/linux
// executed-test parity even for the windows-gate drift-guard.
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
