package verify

import (
	"os"
	"strings"
)

// userHome resolves the user's home directory, honoring an explicit $HOME on
// ALL platforms before falling back to os.UserHomeDir().
//
// Why: on Windows os.UserHomeDir() reads %USERPROFILE% and ignores $HOME, so a
// caller (or a test, or a Git-Bash session) that sets HOME would be silently
// ignored. Routing the trust-roots home resolution through here makes it uniform
// and test-injectable cross-platform — it is what lets the verify-package tests
// (and the SPEC-0247 gate) run on the windows-latest CI runner without per-test
// %USERPROFILE% plumbing.
//
// In production on Windows, real users normally have HOME unset → os.UserHomeDir()
// → %USERPROFILE%, so behaviour is unchanged. HOME is only honored when it is
// explicitly set, which is the correct, conventional precedence and matches the
// resolver already used in cmd/skillctl (home.go). This is a correctness
// improvement, not a test crutch.
func userHome() (string, error) {
	if h := strings.TrimSpace(os.Getenv("HOME")); h != "" {
		return h, nil
	}
	return os.UserHomeDir()
}
