package registry

import (
	"os"
	"runtime"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/homeroot"
)

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

// TestUserHome_HonorsSharedDecision — WIN-T8 (WIN-09) parity: registry.userHome
// must apply the SINGLE shared $HOME-on-Windows decision
// (homeroot.OverrideAllowed) — the same one the verify package and the
// cmd/skillctl binary use — so the three former copies can no longer drift into
// separate policies. The pure (goos, compiledIn) matrix is pinned in the homeroot
// package's own test; this proves THIS site delegates to it behaviorally. No
// runtime.GOOS skip → the windows/linux executed-test parity stays even for the
// windows-gate drift-guard.
func TestUserHome_HonorsSharedDecision(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	got := userHome()
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
