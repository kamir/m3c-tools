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
	"runtime"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
)

// Resolver implements artifact.CredentialSource over env + macOS Keychain.
type Resolver struct{}

// New returns a credential resolver.
func New() *Resolver { return &Resolver{} }

var _ artifact.CredentialSource = (*Resolver)(nil)

// backendCred maps a scheme to its credential sources + git username. Two token
// tiers (CD-13, least-privilege split):
//
//   - WRITE tier (env / kcService): a write-capable credential (Publishing
//     pushes) — for gitlab a Project Access Token or PAT (NOT a read-only Deploy
//     Token), for github a PAT with repo write. This is the historical default.
//   - READ tier (roEnv / roKcService): an OPTIONAL read-only credential the
//     operator MAY provision so a verifying PULL (Fetch/List/Resolve/Events)
//     never transmits the write token. When absent, ModeRead transparently falls
//     back to the write tier, so a single-token setup keeps working unchanged.
//
// The git username "oauth2" works for both GitLab project/personal tokens and a
// read-only Deploy Token.
var backendCred = map[string]struct{ env, roEnv, kcService, roKcService, user string }{
	"gitlab": {"M3C_GITLAB_TOKEN", "M3C_GITLAB_RO_TOKEN", "m3c-skillctl-gitlab", "m3c-skillctl-gitlab-ro", "oauth2"},
	"github": {"M3C_GITHUB_TOKEN", "M3C_GITHUB_RO_TOKEN", "m3c-skillctl-github", "m3c-skillctl-github-ro", "oauth2"},
}

// Credential resolves the token for (scheme, host, mode). host lets one machine
// hold distinct tokens for distinct instances (e.g. a lab GitLab vs KuP on-prem).
//
// CD-13: for ModeRead we consult the OPTIONAL read-only credential sources FIRST
// (roEnv → ro Keychain → ro OS store); only if none is provisioned do we fall
// back to the write tier — so an operator who provisioned a read-only Deploy
// Token gets least privilege on pulls, while a single-write-token setup is
// unchanged. ModeWrite always resolves the write tier.
func (r *Resolver) Credential(ctx context.Context, scheme, host string, mode artifact.AccessMode) (artifact.Credential, error) {
	m, ok := backendCred[scheme]
	if !ok {
		return artifact.Credential{}, nil // anonymous for schemes we don't manage
	}
	// Read path: prefer a provisioned read-only credential; fall through to the
	// write tier when none exists (backward-compatible single-token operators).
	if mode == artifact.ModeRead {
		if v := r.lookup(scheme, m.roEnv, m.roKcService, host); v != "" {
			return artifact.Credential{Scheme: scheme, Token: v, User: m.user}, nil
		}
	}
	if v := r.lookup(scheme, m.env, m.kcService, host); v != "" {
		return artifact.Credential{Scheme: scheme, Token: v, User: m.user}, nil
	}
	return artifact.Credential{}, nil // anonymous
}

// lookup resolves a single credential tier: env override → macOS Keychain →
// per-OS credential store. Empty tier names (an operator who provisioned no
// read-only token) are skipped, so a missing RO tier simply yields "".
func (r *Resolver) lookup(scheme, env, kcService, host string) string {
	if env != "" {
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			return v
		}
	}
	if kcService == "" {
		return ""
	}
	// macOS Keychain — only on darwin. keychain() shells out to `security`, which
	// exists only on macOS; guarding the call keeps a Windows/Linux box from
	// spawning (or, worse, PATH-resolving) a non-existent `security` binary.
	if runtime.GOOS == "darwin" {
		if v := keychain(kcService, host); v != "" {
			return v
		}
	}
	// Per-OS credential store (Windows DPAPI in creds_windows.go; no-op elsewhere).
	// Lets a Windows user keep a write-capable PAT out of a plaintext env var.
	if v := osCredStore(kcService, host); v != "" {
		return v
	}
	return ""
}

// keychain reads a generic-password from the macOS Keychain (read-only). It is
// only ever CALLED on darwin (see Credential). Returns empty on any error. Store
// one with:
//
//	security add-generic-password -s m3c-skillctl-gitlab -a <host> -w '<PAT>' -U
//
// The binary is the absolute /usr/bin/security (macOS ships it there) rather than
// a bare-name PATH lookup, so a `security` planted on PATH cannot be run instead.
func keychain(service, account string) string {
	if account == "" {
		return ""
	}
	out, err := exec.Command("/usr/bin/security", "find-generic-password", "-s", service, "-a", account, "-w").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
