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
// The Windows override is NOT re-openable from the ambient environment — an
// env-var escape hatch (the earlier M3C_ALLOW_HOME_OVERRIDE) would be settable by
// the very attacker/child-process WIN-09 models, re-opening the vector for the
// cost of one extra variable. Instead the override is a COMPILE-TIME decision:
// homeOverrideCompiledIn is true only in a build made with `-tags
// allow_home_override_test` (and, trivially, on every non-Windows build, where the
// goos short-circuit governs). Shipping Windows releases carry no such tag, so
// $HOME is unconditionally ignored there. The dev/quickstart sandbox and the
// windows-latest test surface build WITH the tag, which is what keeps them
// working. See homeOverrideAllowed for the pure decision.
func userHome() (string, error) {
	if h := strings.TrimSpace(os.Getenv("HOME")); h != "" &&
		homeOverrideAllowed(runtime.GOOS, homeOverrideCompiledIn) {
		return h, nil
	}
	return os.UserHomeDir()
}

// homeOverrideAllowed is the pure, platform-parameterized decision behind
// userHome: may an explicit $HOME override the per-user security root on goos?
// Non-Windows always allows it; Windows allows it ONLY when the override was
// compiled in (the `allow_home_override_test` build tag). Kept pure (goos +
// compiled-in flag as arguments, no OS/env reads) so it can be unit-tested for
// BOTH platforms from any host — which also keeps the windows/linux executed-test
// parity even (windows-gate drift-guard).
func homeOverrideAllowed(goos string, compiledIn bool) bool {
	if goos != "windows" {
		return true
	}
	return compiledIn
}
