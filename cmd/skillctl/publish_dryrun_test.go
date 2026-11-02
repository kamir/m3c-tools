package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// BUG-0464: `publish --dry-run` loaded the signing key AFTER packing and BEFORE
// its own dry-run branch. On a machine without a key a dry run therefore failed
// with exit 1, never showed the plan, and still left the bundle it had packed.
// Its help also promised "do not POST or pack", which it never kept.
//
// Fixed along the report's second option: a dry run still packs
// ./<name>@<version>.skb (the e2e tests for agent bundles rely on that file, and
// the plan shows the real digest), but it signs nothing, loads no key, and the
// help says what it does.

// dryRunSkill makes a minimal skill dir under a temp HOME and chdirs into an
// empty working directory, so anything written to "." is visible.
func dryRunSkill(t *testing.T, name string) (workDir string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("SIGNING_KEY_LOCATION", "")
	skillDir := filepath.Join(home, ".claude", "skills", name)
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "---\nname: " + name + "\ndescription: dry run probe\n---\n\n# " + name + "\n\nSays hello.\n"
	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	workDir = t.TempDir()
	t.Chdir(workDir)
	return workDir
}

func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range es {
		names = append(names, e.Name())
	}
	return names
}

func TestPublishDryRunNeedsNoKeyAndShowsThePlan(t *testing.T) {
	work := dryRunSkill(t, "dryprobe")
	missingKey := filepath.Join(t.TempDir(), "does-not-exist.priv")

	var out, errBuf bytes.Buffer
	code := runPublish([]string{"dryprobe", "--version", "1.0.0",
		"--identity", "id:probe@test", "--key", missingKey, "--dry-run"}, &out, &errBuf)
	all := out.String() + errBuf.String()

	if code != 0 {
		t.Fatalf("dry run exited %d, want 0 (a dry run must not need the signing key)\n%s", code, all)
	}
	if strings.Contains(all, "load key") {
		t.Errorf("dry run tried to load the signing key:\n%s", all)
	}
	for _, want := range []string{"==> publish (admit) dryprobe@1.0.0", "digest:    sha256:", "(dry-run; skipping POST)"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("plan output lacks %q:\n%s", want, all)
		}
	}
	// The one file a dry run may leave is the documented pack, and the plan's
	// digest is that file's digest. No signature or anything else beside it.
	if got := dirEntries(t, work); len(got) != 1 || got[0] != "dryprobe@1.0.0.skb" {
		t.Fatalf("working directory after dry run = %v, want exactly [dryprobe@1.0.0.skb]", got)
	}
	raw, err := os.ReadFile(filepath.Join(work, "dryprobe@1.0.0.skb"))
	if err != nil {
		t.Fatal(err)
	}
	d, _ := sha256Hex(raw)
	if !strings.Contains(out.String(), "sha256:"+d) {
		t.Errorf("plan digest is not the digest of the packed bundle (sha256:%s):\n%s", d, out.String())
	}
}

// A pre-built --bundle is reused as is: nothing new is written, and the
// plan's digest is the given bundle's digest.
func TestPublishDryRunReusesGivenBundleUntouched(t *testing.T) {
	work := dryRunSkill(t, "dryprobe2")
	if _, _, err := ensureBundle(publishAdmitArgs{name: "dryprobe2", version: "2.0.0"}, &bytes.Buffer{}); err != nil {
		t.Fatalf("setup pack: %v", err)
	}
	bundle := filepath.Join(work, "dryprobe2@2.0.0.skb")
	raw, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest, _ := sha256Hex(raw)

	var out, errBuf bytes.Buffer
	code := runPublish([]string{"dryprobe2", "--bundle", bundle,
		"--identity", "id:probe@test", "--key", filepath.Join(t.TempDir(), "none.priv"), "--dry-run"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("dry run with --bundle exited %d\n%s%s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(out.String(), "sha256:"+wantDigest) {
		t.Errorf("plan digest is not the bundle digest %s:\n%s", wantDigest, out.String())
	}
	after, err := os.ReadFile(bundle)
	if err != nil || !bytes.Equal(after, raw) {
		t.Errorf("the given bundle changed or vanished during a dry run (err=%v)", err)
	}
	if got := dirEntries(t, work); len(got) != 1 {
		t.Errorf("want exactly the given bundle in the working directory, got %v", got)
	}
}

// The help must not promise what the command does not do: the old text said
// "do not POST or pack" while the dry run packed.
func TestPublishDryRunHelpSaysItPacks(t *testing.T) {
	var out, errBuf bytes.Buffer
	_ = runPublish([]string{"--help"}, &out, &errBuf)
	help := out.String() + errBuf.String()
	i := strings.Index(help, "-dry-run")
	if i < 0 {
		t.Fatalf("no -dry-run in help:\n%s", help)
	}
	line := help[i:]
	if j := strings.Index(line, "\n  -"); j > 0 {
		line = line[:j]
	}
	if strings.Contains(line, "do not POST or pack") || !strings.Contains(line, "packs") || !strings.Contains(line, "no signing key") {
		t.Errorf("dry-run help does not describe what it does:\n%s", line)
	}
}
