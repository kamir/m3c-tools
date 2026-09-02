package registry

import (
	"os"
	"runtime"
	"strings"
)

// userHome resolves the user's home directory for the registry package's per-user
// security state: the self-trust-roots file, the install-token HMAC key, the
// skill-bundle cache, the skills dir, the peers file.
//
// On non-Windows it honors an explicit $HOME before falling back to
// os.UserHomeDir() (conventional POSIX precedence). On Windows $HOME is ignored
// for these paths by default (WIN-09 / WIN-T8): %USERPROFILE% is the real
// per-user, ACL'd root, whereas $HOME is not a security boundary — any process or
// Git-Bash session could set it and redirect the token key / trust roots to a
// directory an attacker controls. Ignoring $HOME on Windows keeps this per-user
// state under %USERPROFILE% (via os.UserHomeDir()), fail-closed.
//
// The dev/quickstart/CI escape hatch is M3C_ALLOW_HOME_OVERRIDE=1: with it set,
// $HOME is honored on Windows too. This preserves the sandboxed quickstart and
// the SEC-L6 isolation tests (which set HOME to a fresh temp dir to force the
// install-token mint path) on the windows-latest runner. See homeOverrideAllowed.
func userHome() string {
	if h := strings.TrimSpace(os.Getenv("HOME")); h != "" &&
		homeOverrideAllowed(runtime.GOOS, os.Getenv("M3C_ALLOW_HOME_OVERRIDE")) {
		return h
	}
	h, _ := os.UserHomeDir()
	return h
}

// homeOverrideAllowed is the pure, platform-parameterized decision behind
// userHome: may an explicit $HOME override the per-user security root on goos?
// Non-Windows always allows it; Windows allows it ONLY when the operator opts in
// with M3C_ALLOW_HOME_OVERRIDE=1. Kept pure (goos + flag as arguments, no OS
// reads) so it can be unit-tested for BOTH platforms from any host — which also
// keeps windows/linux executed-test parity even (windows-gate drift-guard).
func homeOverrideAllowed(goos, allowOverride string) bool {
	if goos != "windows" {
		return true
	}
	return strings.TrimSpace(allowOverride) == "1"
}
