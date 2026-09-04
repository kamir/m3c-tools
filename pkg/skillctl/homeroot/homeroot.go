// Package homeroot is the ONE place that decides how skillctl resolves the
// per-user home directory that anchors every per-user trust/security path
// (trust roots, the install-token HMAC key, the skill-bundle cache, the skills
// dir, the peers file). It exists to kill a drift hazard: three separate
// userHome() helpers (pkg/skillctl/verify, pkg/skillctl/registry, and the
// cmd/skillctl binary) used to each re-implement this, and they had already
// diverged into TWO different $HOME policies: the two library copies gated
// $HOME on Windows (WIN-T8), while the CLI copy honored $HOME on every platform
// with no Windows guard (a footgun). Now all three import this package, so the
// policy is single-sourced and cannot drift again.
//
// THE POLICY (WIN-09 / WIN-T8):
//
// On non-Windows it honors an explicit $HOME before falling back to
// os.UserHomeDir() (the conventional POSIX precedence). On Windows $HOME is
// ignored for these security paths by default: %USERPROFILE% is the real
// per-user, ACL'd root that Windows binds to, whereas $HOME is not a security
// boundary, any process, a Git-Bash session, or an attacker who can set an
// environment variable could point the trust roots / token key at a directory
// they control. Ignoring $HOME on Windows means these paths always resolve under
// %USERPROFILE% (via os.UserHomeDir()), fail-closed.
//
// The Windows override is NOT re-openable from the ambient environment: an
// env-var escape hatch (the earlier M3C_ALLOW_HOME_OVERRIDE) would be settable
// by the very attacker/child-process WIN-09 models, re-opening the vector for
// the cost of one extra variable. Instead the override is a COMPILE-TIME
// decision: CompiledIn is true only in a build made with `-tags
// allow_home_override_test` (and, trivially, on every non-Windows build, where
// the goos short-circuit governs). Shipping Windows releases carry no such tag,
// so $HOME is unconditionally ignored there. The dev/quickstart sandbox and the
// windows-latest test surface build WITH the tag, which is what keeps them
// working. See OverrideAllowed for the pure decision.
package homeroot

import (
	"os"
	"runtime"
	"strings"
)

// UserHome resolves the per-user home directory under the WIN-T8 policy: honor an
// explicit $HOME only when OverrideAllowed(runtime.GOOS, CompiledIn) says so
// (always on non-Windows; on Windows only under the `allow_home_override_test`
// build tag), otherwise fall back to os.UserHomeDir() (%USERPROFILE% on Windows).
func UserHome() (string, error) {
	if h := strings.TrimSpace(os.Getenv("HOME")); h != "" &&
		OverrideAllowed(runtime.GOOS, CompiledIn) {
		return h, nil
	}
	return os.UserHomeDir()
}

// OverrideAllowed is the pure, platform-parameterized decision behind UserHome:
// may an explicit $HOME override the per-user security root on goos? Non-Windows
// always allows it; Windows allows it ONLY when the override was compiled in (the
// `allow_home_override_test` build tag). Kept pure (goos + compiled-in flag as
// arguments, no OS/env reads) so it can be unit-tested for BOTH platforms from
// any host, which also keeps the windows/linux executed-test parity even
// (windows-gate drift-guard).
func OverrideAllowed(goos string, compiledIn bool) bool {
	if goos != "windows" {
		return true
	}
	return compiledIn
}
