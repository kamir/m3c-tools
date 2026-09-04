package main

import "github.com/kamir/m3c-tools/pkg/skillctl/homeroot"

// userHome resolves the user's home directory for skillctl's per-user trust
// paths. It now uses the SAME WIN-T8 tag-gated $HOME policy as the verify and
// registry packages (single-sourced in pkg/skillctl/homeroot): closing a
// footgun where this copy honored $HOME on ALL platforms with no Windows guard,
// so a shipping Windows binary would trust a $HOME an attacker or Git-Bash
// session could set. A shipping Windows build (no `allow_home_override_test` tag)
// now ignores $HOME here too and resolves %USERPROFILE% via os.UserHomeDir();
// dev/test builds and every non-Windows build still honor $HOME. The e2e/
// lifecycle tests inject USERPROFILE alongside HOME (WIN-T8), so a shipping
// cmd binary stays scoped to the temp home via %USERPROFILE%.
func userHome() (string, error) {
	return homeroot.UserHome()
}
