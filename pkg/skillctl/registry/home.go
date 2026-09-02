package registry

import "github.com/kamir/m3c-tools/pkg/skillctl/homeroot"

// userHome resolves the user's home directory for the registry package's per-user
// security state: the self-trust-roots file, the install-token HMAC key, the
// skill-bundle cache, the skills dir, the peers file. The WIN-T8 / WIN-09
// $HOME-on-Windows policy and rationale are single-sourced in
// pkg/skillctl/homeroot (shared with verify and the cmd/skillctl binary). This
// wrapper preserves the package's historical string-only signature.
func userHome() string {
	h, _ := homeroot.UserHome()
	return h
}
