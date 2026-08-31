// Package artifactauth resolves per-backend credentials for the SPEC-0356
// artifact backends (D5). It is READ-ONLY: it never writes or deletes a
// credential store, so it structurally cannot reintroduce the
// ADR-auth-coexistence `config switch` delete bug.
//
// Precedence per (scheme, host): env override → macOS Keychain. When nothing is
// found it returns an anonymous (empty-token) credential with a nil error, so a
// public repo or ambient git credentials still work.
package artifactauth

import (
	"context"
	"os"
	"os/exec"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
)

// Resolver implements artifact.CredentialSource over env + macOS Keychain.
type Resolver struct{}

// New returns a credential resolver.
func New() *Resolver { return &Resolver{} }

var _ artifact.CredentialSource = (*Resolver)(nil)

// backendCred maps a scheme to its env var + Keychain service + git username.
// The token is a WRITE-capable credential (Publishing pushes): for gitlab that
// is a Project Access Token or PAT — NOT a Deploy Token (read-only). The git
// username "oauth2" works for both GitLab project/personal tokens.
var backendCred = map[string]struct{ env, kcService, user string }{
	"gitlab": {"M3C_GITLAB_TOKEN", "m3c-skillctl-gitlab", "oauth2"},
	"github": {"M3C_GITHUB_TOKEN", "m3c-skillctl-github", "oauth2"},
}

// Credential resolves the token for (scheme, host). host lets one machine hold
// distinct tokens for distinct instances (e.g. a lab GitLab vs KuP on-prem).
func (r *Resolver) Credential(ctx context.Context, scheme, host string) (artifact.Credential, error) {
	m, ok := backendCred[scheme]
	if !ok {
		return artifact.Credential{}, nil // anonymous for schemes we don't manage
	}
	if v := strings.TrimSpace(os.Getenv(m.env)); v != "" {
		return artifact.Credential{Scheme: scheme, Token: v, User: m.user}, nil
	}
	if v := keychain(m.kcService, host); v != "" {
		return artifact.Credential{Scheme: scheme, Token: v, User: m.user}, nil
	}
	return artifact.Credential{}, nil // anonymous
}

// keychain reads a generic-password from the macOS Keychain (read-only). Returns
// empty on any error or on non-macOS platforms. Store one with:
//
//	security add-generic-password -s m3c-skillctl-gitlab -a <host> -w '<PAT>' -U
func keychain(service, account string) string {
	if account == "" {
		return ""
	}
	out, err := exec.Command("security", "find-generic-password", "-s", service, "-a", account, "-w").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
