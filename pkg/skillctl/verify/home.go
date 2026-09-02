package verify

import (
	"os"
	"runtime"
	"strings"
)

// userHome resolves the user's home directory for the trust-root security paths.
//
// On non-Windows it honors an explicit $HOME before falling back to
// os.UserHomeDir() (the conventional POSIX precedence). On Windows $HOME is
// ignored for these security paths by default (WIN-09 / WIN-T8): %USERPROFILE% is
// the real per-user, ACL'd root that Windows binds to, whereas $HOME is not a
// security boundary — any process, a Git-Bash session, or an attacker who can set
// an environment variable could point the trust roots at a directory they
// control. Ignoring $HOME on Windows means the trust roots always resolve under
// %USERPROFILE% (via os.UserHomeDir()), fail-closed.
//
// The dev/quickstart/CI escape hatch is M3C_ALLOW_HOME_OVERRIDE=1: with it set,
// $HOME is honored on Windows too (this is what preserves the sandboxed quickstart
// and lets the verify-package tests inject a temp HOME on the windows-latest
// runner). See homeOverrideAllowed for the pure decision.
func userHome() (string, error) {
	if h := strings.TrimSpace(os.Getenv("HOME")); h != "" &&
		homeOverrideAllowed(runtime.GOOS, os.Getenv("M3C_ALLOW_HOME_OVERRIDE")) {
		return h, nil
	}
	return os.UserHomeDir()
}

// homeOverrideAllowed is the pure, platform-parameterized decision behind
// userHome: may an explicit $HOME override the per-user security root on goos?
// Non-Windows always allows it; Windows allows it ONLY when the operator opts in
// with M3C_ALLOW_HOME_OVERRIDE=1. Kept pure (goos + flag as arguments, no OS
// reads) so it can be unit-tested for BOTH platforms from any host — which also
// keeps the windows/linux executed-test parity even (windows-gate drift-guard).
func homeOverrideAllowed(goos, allowOverride string) bool {
	if goos != "windows" {
		return true
	}
	return strings.TrimSpace(allowOverride) == "1"
}
