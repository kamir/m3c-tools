package registry

import (
	"os"
	"strings"
)

// userHome resolves the user's home directory, honoring an explicit $HOME on
// ALL platforms before falling back to os.UserHomeDir().
//
// Why: on Windows os.UserHomeDir() reads %USERPROFILE% and ignores $HOME, so a
// caller (or a test, or a Git-Bash session) that sets HOME would be silently
// ignored — and the registry package's per-user state (the self-trust-roots
// file, the install-token HMAC key, the skill-bundle cache, the skills dir)
// would resolve to %USERPROFILE% instead of the requested HOME. Routing all of
// those through here makes the resolution uniform and test-injectable
// cross-platform, matching the resolvers already used in cmd/skillctl and the
// verify package.
//
// In production on Windows, real users normally have HOME unset → os.UserHomeDir()
// → %USERPROFILE%, so behaviour is unchanged. HOME is only honored when it is
// explicitly set, which is the correct, conventional precedence. This also
// matters for SEC-L6 isolation: a test that sets HOME to a fresh temp dir to
// force the install-token mint path through the (failing) CSPRNG can only do so
// if HOME actually redirects the key-file lookup.
func userHome() string {
	if h := strings.TrimSpace(os.Getenv("HOME")); h != "" {
		return h
	}
	h, _ := os.UserHomeDir()
	return h
}
