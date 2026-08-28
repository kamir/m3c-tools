package git

import (
	"context"
	"os/exec"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
)

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
