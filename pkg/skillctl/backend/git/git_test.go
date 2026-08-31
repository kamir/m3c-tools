package git

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
	"github.com/kamir/m3c-tools/pkg/skillctl/artifact/conformance"
)

// TestGitBackendConformance runs the shared SPEC-0356 backend conformance suite
// (D8) against a bare-repo git backend — the SAME assertions run against ER1.
func TestGitBackendConformance(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	conformance.Run(t, newGitBackend(bareRepo(t), "gitlab"))
}

type fakeCreds struct{ user, token string }

func (f fakeCreds) Credential(ctx context.Context, scheme, host string) (artifact.Credential, error) {
	return artifact.Credential{User: f.user, Token: f.token, Scheme: scheme}, nil
}

func mustGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// bareRepo creates an empty bare repo with default branch main and returns its path.
func bareRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	mustGit(t, "", "-c", "init.defaultBranch=main", "init", "--bare", dir)
	return dir
}

func admitEvent(name, ver, dig string) artifact.PublishRequest {
	return artifact.PublishRequest{
		Kind: artifact.KindAdmit,
		Event: map[string]any{
			"kind": "admitted", "skill": name, "version": ver, "bundle_digest": dig,
			"schema_version": "1.0.0",
		},
		Meta: artifact.ArtifactMeta{Name: name, Version: ver, Digest: dig, GovernanceLevel: "green"},
		Blob: []byte("SKB:" + name + "@" + ver),
	}
}

func dig(seed byte) string { return "sha256:" + strings.Repeat(string(rune('a'+seed)), 64) }

func TestGitBackendLifecycle(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	ctx := context.Background()
	b := newGitBackend(bareRepo(t), "gitlab")
	defer b.Close()

	digPdf1 := dig(0) // pdf@1.0.0
	digPdf2 := dig(1) // pdf@1.2.0
	digBrowse := dig(2)

	for _, r := range []artifact.PublishRequest{
		admitEvent("pdf", "1.0.0", digPdf1),
		admitEvent("pdf", "1.2.0", digPdf2),
		admitEvent("browse", "0.1.0", digBrowse),
	} {
		if _, err := b.Publish(ctx, r); err != nil {
			t.Fatalf("Publish %s@%s: %v", r.Meta.Name, r.Meta.Version, err)
		}
	}

	// --- List: complete, sorted, correct latest ---
	lst, err := b.List(ctx, artifact.ListFilter{}, artifact.Page{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if lst.NextCursor != "" {
		t.Errorf("git listings are complete; NextCursor = %q, want empty", lst.NextCursor)
	}
	if len(lst.Skills) != 2 {
		t.Fatalf("List returned %d skills, want 2 (browse, pdf): %+v", len(lst.Skills), lst.Skills)
	}
	if lst.Skills[0].Name != "browse" || lst.Skills[1].Name != "pdf" {
		t.Errorf("skills not sorted: %s, %s", lst.Skills[0].Name, lst.Skills[1].Name)
	}
	pdf := lst.Skills[1]
	if len(pdf.Versions) != 2 {
		t.Errorf("pdf has %d versions, want 2", len(pdf.Versions))
	}
	if pdf.LatestVersion != "1.2.0" {
		t.Errorf("pdf LatestVersion = %q, want 1.2.0 (semver-max)", pdf.LatestVersion)
	}
	if pdf.LatestDigest != digPdf2 {
		t.Errorf("pdf LatestDigest = %q, want %q", pdf.LatestDigest, digPdf2)
	}

	// --- Resolve latest ---
	ref, err := b.Resolve(ctx, artifact.RefQuery{Name: "pdf"})
	if err != nil {
		t.Fatalf("Resolve pdf: %v", err)
	}
	if ref.Version != "1.2.0" || ref.Digest != digPdf2 {
		t.Errorf("Resolve pdf = %s/%s, want 1.2.0/%s", ref.Version, ref.Digest, digPdf2)
	}
	if ref.Locator != "pdf/v1.2.0" {
		t.Errorf("Locator = %q, want pdf/v1.2.0", ref.Locator)
	}

	// --- Fetch by ref (digest round-trips) ---
	blob, err := b.Fetch(ctx, *ref)
	if err != nil {
		t.Fatalf("Fetch by ref: %v", err)
	}
	if string(blob) != "SKB:pdf@1.2.0" {
		t.Errorf("Fetch = %q", blob)
	}

	// --- Fetch by digest only (content-address an older version) ---
	blob1, err := b.Fetch(ctx, artifact.ArtifactRef{Digest: digPdf1})
	if err != nil {
		t.Fatalf("Fetch by digest: %v", err)
	}
	if string(blob1) != "SKB:pdf@1.0.0" {
		t.Errorf("Fetch by digest = %q, want SKB:pdf@1.0.0", blob1)
	}

	// --- Idempotency: re-admit is a no-op ---
	res, err := b.Publish(ctx, admitEvent("pdf", "1.0.0", digPdf1))
	if err != nil {
		t.Fatalf("re-Publish: %v", err)
	}
	if !res.AlreadyExists {
		t.Error("re-admit should report AlreadyExists")
	}

	// --- Revoke the latest → latest falls back to the non-revoked version ---
	_, err = b.Publish(ctx, artifact.PublishRequest{
		Kind:  artifact.KindRevoke,
		Event: map[string]any{"kind": "revoked", "bundle_digest": digPdf2},
		Meta:  artifact.ArtifactMeta{Name: "pdf", Version: "1.2.0", Digest: digPdf2},
	})
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	ref2, err := b.Resolve(ctx, artifact.RefQuery{Name: "pdf"})
	if err != nil {
		t.Fatalf("Resolve after revoke: %v", err)
	}
	if ref2.Version != "1.0.0" {
		t.Errorf("after revoking 1.2.0, latest non-revoked = %q, want 1.0.0", ref2.Version)
	}
	lst2, _ := b.List(ctx, artifact.ListFilter{Name: "pdf"}, artifact.Page{})
	if r, ok := rowFor(lst2.Skills[0].Versions, "1.2.0"); !ok || r.Status != "revoked" {
		t.Errorf("pdf@1.2.0 row = %+v, want status revoked", r)
	}
}

func TestGitOpenSchemeMapping(t *testing.T) {
	b, err := openGitLab("gitlab://gitlab.example.com/grp/skills@main", artifact.OpenOptions{})
	if err != nil {
		t.Fatalf("openGitLab: %v", err)
	}
	if got := b.Describe().Scheme; got != "gitlab" {
		t.Errorf("scheme = %q, want gitlab", got)
	}
	gb := b.(*gitBackend)
	if gb.remote != "https://gitlab.example.com/grp/skills.git" {
		t.Errorf("remote = %q", gb.remote)
	}
	gh, _ := openGitHub("github://kamir/skill-registry", artifact.OpenOptions{})
	if gh.(*gitBackend).remote != "https://github.com/kamir/skill-registry.git" {
		t.Errorf("github remote = %q", gh.(*gitBackend).remote)
	}
}

func TestGitCredNoLeak(t *testing.T) {
	const tok = "s3cr3t-TOKEN"
	b, err := openGitLab("gitlab://192.168.0.131:8929/grp/skills",
		artifact.OpenOptions{Creds: fakeCreds{user: "deployer", token: tok}})
	if err != nil {
		t.Fatal(err)
	}
	gb := b.(*gitBackend)
	// The token must NEVER appear in Describe() or the stored remote (which IS
	// the clone/push argv — no userinfo, no '@').
	if strings.Contains(gb.Describe().Display, tok) || strings.Contains(gb.remote, tok) || strings.Contains(gb.remote, "@") {
		t.Fatalf("token leaked: display=%q remote=%q", gb.Describe().Display, gb.remote)
	}
	// It rides in an env http.extraHeader instead.
	want := "Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("deployer:"+tok))
	if !strings.Contains(strings.Join(gb.authEnv(), "\n"), want) {
		t.Errorf("authEnv missing header: %q", gb.authEnv())
	}
	// redact() scrubs the token (raw + base64) and URL userinfo from error text.
	leaky := "git clone https://oauth2:" + tok + "@host failed; " + want
	if r := gb.redact(leaky); strings.Contains(r, tok) || strings.Contains(r, "oauth2:s") {
		t.Errorf("redact leaked: %q", r)
	}
}

func TestGitDefaultUserOauth2(t *testing.T) {
	b, _ := openGitLab("gitlab://host/g/p", artifact.OpenOptions{Creds: fakeCreds{token: "T"}})
	if u := b.(*gitBackend).authUser(); u != "oauth2" {
		t.Errorf("default user = %q, want oauth2", u)
	}
}

// TestGitTokenNotInError — regression for the challenge-gate CRITICAL: a failing
// git operation must never return the token in its error string.
func TestGitTokenNotInError(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	const tok = "TOP-SECRET-PAT-123"
	b := &gitBackend{remote: "https://127.0.0.1:1/nope.git", scheme: "gitlab", token: tok, tokenUser: "deployer"}
	_, err := b.List(context.Background(), artifact.ListFilter{}, artifact.Page{})
	if err == nil {
		t.Fatal("expected the clone to fail")
	}
	if strings.Contains(err.Error(), tok) {
		t.Fatalf("TOKEN LEAKED in error: %v", err)
	}
}

// TestGitPathTraversalRejected — regression for the challenge-gate CRITICAL: a
// malicious name/version/digest is rejected before any filesystem write.
func TestGitPathTraversalRejected(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	ctx := context.Background()
	b := newGitBackend(bareRepo(t), "gitlab")
	defer b.Close()
	good := dig(3)
	for _, bad := range []artifact.ArtifactMeta{
		{Name: "../../../../tmp/pwn", Version: "1.0.0", Digest: good},
		{Name: "ok", Version: "../../etc", Digest: good},
		{Name: "-danger", Version: "1.0.0", Digest: good},
		{Name: "a/b", Version: "1.0.0", Digest: good},
		{Name: "ok", Version: "1.0.0", Digest: "not-a-digest"},
	} {
		if _, err := b.Publish(ctx, artifact.PublishRequest{
			Kind: artifact.KindAdmit, Blob: []byte("x"),
			Event: map[string]any{"kind": "admitted"}, Meta: bad,
		}); err == nil {
			t.Errorf("Publish accepted malicious meta %+v", bad)
		}
	}
	if _, statErr := os.Stat("/tmp/pwn/1.0.0/bundle.skb"); statErr == nil {
		t.Fatal("path traversal wrote /tmp/pwn — SEC-M9 breach")
	}
}

// TestGitBackendAgainstRemote runs the full lifecycle against a LIVE git remote
// (e.g. the Demo-Lab GitLab on master2). Gated on M3C_TEST_GIT_REMOTE so CI's
// default offline `test-unit` skips it; the bare-repo test above is the
// always-on cover.
//
// The credential must be a PROJECT ACCESS TOKEN, not a Deploy Token: GitLab
// rejects write_repository as a deploy-token scope, and Publish pushes.
//
//	M3C_TEST_GIT_REMOTE="http://oauth2:<project-access-token>@192.168.0.135:8929/m3c/skills.git" \
//	  go test -run TestGitBackendAgainstRemote ./pkg/skillctl/backend/git/
func TestGitBackendAgainstRemote(t *testing.T) {
	remote := os.Getenv("M3C_TEST_GIT_REMOTE")
	if remote == "" {
		t.Skip("set M3C_TEST_GIT_REMOTE=<authenticated git remote URL> to run (needs a live remote)")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	ctx := context.Background()
	b := newGitBackend(remote, "gitlab") // remote already carries auth
	defer b.Close()

	// Unique name+digest per run so re-runs don't collide on a persistent remote.
	name := fmt.Sprintf("itest-%d", time.Now().UnixNano())
	d := fmt.Sprintf("sha256:%064x", time.Now().UnixNano())
	if _, err := b.Publish(ctx, artifact.PublishRequest{
		Kind:  artifact.KindAdmit,
		Event: map[string]any{"kind": "admitted", "skill": name, "version": "1.0.0", "bundle_digest": d},
		Meta:  artifact.ArtifactMeta{Name: name, Version: "1.0.0", Digest: d, GovernanceLevel: "green"},
		Blob:  []byte("SKB-integration"),
	}); err != nil {
		t.Fatalf("Publish to remote: %v", err)
	}
	lst, err := b.List(ctx, artifact.ListFilter{Name: name}, artifact.Page{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(lst.Skills) != 1 || lst.Skills[0].LatestVersion != "1.0.0" {
		t.Fatalf("List returned %+v, want one skill @1.0.0", lst.Skills)
	}
	ref, err := b.Resolve(ctx, artifact.RefQuery{Name: name})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	blob, err := b.Fetch(ctx, *ref)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(blob) != "SKB-integration" {
		t.Errorf("Fetch = %q, want SKB-integration", blob)
	}
	// Log host only (never the token-in-URL).
	host := remote
	if i := strings.LastIndex(remote, "@"); i >= 0 {
		host = remote[i+1:]
	}
	t.Logf("integration OK against %s (skill %s)", host, name)
}

// TestGitBackendHeaderAuthRemote validates the REAL CLI credential path against a
// live GitLab: openGitLab (clean remote, no token-in-URL) + a Creds source →
// env http.extraHeader (authEnv). This confirms GitLab accepts
// Authorization: Basic base64(oauth2:PAT), which D3 (CLI wiring) will rely on.
// Gated on M3C_TEST_GITLAB_SPEC (e.g. gitlab://192.168.0.135:8929/m3c/skills) +
// M3C_TEST_GITLAB_TOKEN. For an http-only lab GitLab, also set M3C_GIT_HTTP=1.
func TestGitBackendHeaderAuthRemote(t *testing.T) {
	spec := os.Getenv("M3C_TEST_GITLAB_SPEC")
	tok := os.Getenv("M3C_TEST_GITLAB_TOKEN")
	if spec == "" || tok == "" {
		t.Skip("set M3C_TEST_GITLAB_SPEC + M3C_TEST_GITLAB_TOKEN to run")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	ctx := context.Background()
	b, err := openGitLab(spec, artifact.OpenOptions{Creds: fakeCreds{user: "oauth2", token: tok}})
	if err != nil {
		t.Fatalf("openGitLab: %v", err)
	}
	defer b.Close()
	gb := b.(*gitBackend)
	// The remote used for clone/push must be token-free (auth rides in the header).
	if strings.Contains(gb.remote, "@") || strings.Contains(gb.remote, tok) {
		t.Fatalf("token leaked into remote: %q", gb.remote)
	}

	name := fmt.Sprintf("itest-hdr-%d", time.Now().UnixNano())
	d := fmt.Sprintf("sha256:%064x", time.Now().UnixNano())
	if _, err := b.Publish(ctx, admitEvent(name, "1.0.0", d)); err != nil {
		t.Fatalf("publish via header-auth: %v", err)
	}
	ref, err := b.Resolve(ctx, artifact.RefQuery{Name: name})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	blob, err := b.Fetch(ctx, *ref)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(blob) != "SKB:"+name+"@1.0.0" {
		t.Errorf("Fetch = %q", blob)
	}
	t.Logf("header-auth OK: clean remote=%s, published+fetched %s", gb.remote, name)
}
