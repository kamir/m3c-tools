package git

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
)

func TestResolveLocalPath(t *testing.T) {
	home, _ := os.UserHomeDir()
	// Expected values are computed via filepath.Abs so they match resolveLocalPath
	// on every OS (on Windows "/abs/reg.git" absolutizes to a drive-lettered path).
	absSlash, _ := filepath.Abs("/abs/reg.git")
	cases := []struct {
		spec, want string
		err        bool
	}{
		{"local:///abs/reg.git", absSlash, false},
		{"local://~/reg.git", filepath.Join(home, "reg.git"), false},
		{"local://-oops", "", true},  // leading '-' rejected (git-flag injection)
		{"local://", "", true},       // empty
		{"gitlab://h/g/p", "", true}, // wrong scheme
	}
	for _, c := range cases {
		got, err := resolveLocalPath(c.spec)
		if c.err {
			if err == nil {
				t.Errorf("resolveLocalPath(%q) = %q, want error", c.spec, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("resolveLocalPath(%q) = %q / %v, want %q", c.spec, got, err, c.want)
		}
	}
}

// TestInitLocalRegistryGuards: init must refuse to scatter bare-repo plumbing over
// a non-empty non-repo directory (the local://~ / local://. typo footgun), while
// still allowing an absent path, an empty dir, and idempotent re-init of a repo.
func TestInitLocalRegistryGuards(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	// Non-empty NON-repo dir → REFUSE (the footgun).
	danger := t.TempDir()
	if err := os.WriteFile(filepath.Join(danger, "my-important.txt"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := InitLocalRegistry("local://" + danger); err == nil {
		t.Errorf("init over a non-empty non-repo dir must be refused")
	}
	if _, err := os.Stat(filepath.Join(danger, "HEAD")); err == nil {
		t.Errorf("init wrote bare-repo plumbing into a user directory — footgun not guarded")
	}

	// Empty dir → OK.
	empty := t.TempDir()
	if _, err := InitLocalRegistry("local://" + empty); err != nil {
		t.Errorf("init over an empty dir should succeed: %v", err)
	}
	// Idempotent re-init of the now-bare repo → OK.
	if _, err := InitLocalRegistry("local://" + empty); err != nil {
		t.Errorf("re-init of an existing bare repo should be idempotent: %v", err)
	}

	// Absent path → OK (git creates it).
	absent := filepath.Join(t.TempDir(), "new", "reg.git")
	if _, err := InitLocalRegistry("local://" + absent); err != nil {
		t.Errorf("init over an absent path should succeed: %v", err)
	}
}

// TestLocalRegistryEndToEnd: init a bare local registry, publish + read through
// artifact.Open("local://…"), export a git-bundle snapshot, and prove a peer can
// list+fetch from the READ-ONLY bundle — the offline handoff flow, no remote.
func TestLocalRegistryEndToEnd(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	ctx := context.Background()
	regPath := filepath.Join(t.TempDir(), "reg.git")
	spec := "local://" + regPath

	// init → bare repo exists.
	if _, err := InitLocalRegistry(spec); err != nil {
		t.Fatalf("InitLocalRegistry: %v", err)
	}
	if _, err := os.Stat(filepath.Join(regPath, "HEAD")); err != nil {
		t.Fatalf("init did not create a bare repo (no HEAD): %v", err)
	}

	// Open via the factory (proves the local:// scheme is registered) + publish.
	be, err := artifact.Open(spec, artifact.OpenOptions{})
	if err != nil {
		t.Fatalf("Open(%q): %v", spec, err)
	}
	defer be.Close()
	if be.Describe().Scheme != "local" {
		t.Errorf("scheme = %q, want local", be.Describe().Scheme)
	}
	d := fdig('a')
	if _, err := be.Publish(ctx, admitEvent("localskill", "1.0.0", d)); err != nil {
		t.Fatalf("publish to local registry: %v", err)
	}

	// Read back through the local registry.
	lst, err := be.List(ctx, artifact.ListFilter{}, artifact.Page{})
	if err != nil || len(lst.Skills) != 1 || lst.Skills[0].Name != "localskill" {
		t.Fatalf("List local = %+v / %v", lst, err)
	}
	ref, err := be.Resolve(ctx, artifact.RefQuery{Name: "localskill"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	blob, err := be.Fetch(ctx, *ref)
	if err != nil || string(blob) != "SKB:localskill@1.0.0" {
		t.Fatalf("Fetch local = %q / %v", blob, err)
	}

	// export → a portable read-only bundle snapshot (the offline "request").
	bundlePath := filepath.Join(t.TempDir(), "skills.bundle")
	if err := ExportBundle(spec, bundlePath); err != nil {
		t.Fatalf("ExportBundle: %v", err)
	}
	if fi, err := os.Stat(bundlePath); err != nil || fi.Size() == 0 {
		t.Fatalf("bundle not written: %v", err)
	}

	// A PEER opens the bundle as a read-only registry and lists + fetches from it.
	bspec := "local://" + bundlePath
	pbe, err := artifact.Open(bspec, artifact.OpenOptions{})
	if err != nil {
		t.Fatalf("Open bundle %q: %v", bspec, err)
	}
	defer pbe.Close()
	plst, err := pbe.List(ctx, artifact.ListFilter{}, artifact.Page{})
	if err != nil || len(plst.Skills) != 1 || plst.Skills[0].Name != "localskill" {
		t.Fatalf("List from bundle = %+v / %v", plst, err)
	}
	pblob, err := pbe.Fetch(ctx, artifact.ArtifactRef{Name: "localskill", Version: "1.0.0", Digest: d})
	if err != nil || string(pblob) != "SKB:localskill@1.0.0" {
		t.Fatalf("Fetch from bundle = %q / %v", pblob, err)
	}
}
