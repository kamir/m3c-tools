package main

import (
	"os"
	"strings"
)

// userHome resolves the user's home directory, honoring an explicit $HOME on
// ALL platforms before falling back to os.UserHomeDir().
//
// Why: on Windows os.UserHomeDir() reads %USERPROFILE% and ignores $HOME, so a
// test (or a Git-Bash session) that sets HOME would be silently ignored. The
// SPEC-0247 gate's home resolution goes through here so it is uniform and
// test-injectable cross-platform — this is what lets the gate tests run on the
// windows-latest CI runner (SPEC-0128 / Gap B) without per-test USERPROFILE
// plumbing. In production on Windows, HOME is normally unset → os.UserHomeDir()
// → %USERPROFILE%, so behaviour is unchanged for real users.
func userHome() (string, error) {
	if h := strings.TrimSpace(os.Getenv("HOME")); h != "" {
		return h, nil
	}
	return os.UserHomeDir()
}
