package verify

import "github.com/kamir/m3c-tools/pkg/skillctl/homeroot"

// userHome resolves the user's home directory for the trust-root security paths.
// The WIN-T8 / WIN-09 $HOME-on-Windows policy and its full rationale live in ONE
// place, pkg/skillctl/homeroot, which the registry package and the cmd/skillctl
// binary also delegate to, so the three sites can no longer drift into different
// policies (they once had). See homeroot.OverrideAllowed for the pure decision.
func userHome() (string, error) {
	return homeroot.UserHome()
}
