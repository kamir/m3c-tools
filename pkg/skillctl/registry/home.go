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
// The Windows override is NOT re-openable from the ambient environment — an
// env-var escape hatch (the earlier M3C_ALLOW_HOME_OVERRIDE) would be settable by
// the very attacker/child-process WIN-09 models, re-opening the vector for the
// cost of one extra variable. Instead the override is a COMPILE-TIME decision:
// homeOverrideCompiledIn is true only in a build made with `-tags
// allow_home_override_test`. Shipping Windows releases carry no such tag, so
// $HOME is unconditionally ignored there; the dev/quickstart sandbox and the
// windows-latest test surface (including the SEC-L6 isolation tests that force
// the install-token mint path via a temp HOME) build WITH the tag. See
// homeOverrideAllowed.
func userHome() string {
	if h := strings.TrimSpace(os.Getenv("HOME")); h != "" &&
		homeOverrideAllowed(runtime.GOOS, homeOverrideCompiledIn) {
		return h
	}
	h, _ := os.UserHomeDir()
	return h
}

// homeOverrideAllowed is the pure, platform-parameterized decision behind
// userHome: may an explicit $HOME override the per-user security root on goos?
// Non-Windows always allows it; Windows allows it ONLY when the override was
// compiled in (the `allow_home_override_test` build tag). Kept pure (goos +
// compiled-in flag as arguments, no OS/env reads) so it can be unit-tested for
// BOTH platforms from any host — which also keeps windows/linux executed-test
// parity even (windows-gate drift-guard).
func homeOverrideAllowed(goos string, compiledIn bool) bool {
	if goos != "windows" {
		return true
	}
	return compiledIn
}
