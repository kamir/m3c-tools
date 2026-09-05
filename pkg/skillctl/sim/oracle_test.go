package sim

import (
	"os"
	"path/filepath"
	"testing"
)

// The disk oracle carries the two evidence claims that do not ask the tool how it
// went, so it is the last place in this package that should go untested. These
// tests exercise it directly, without a skillctl binary, which is also why they
// run in the offline suite.

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// newTestWorld builds a World with only the two directories the disk oracle reads.
// No binary, no registry: the oracle's whole point is that it works without them.
func newTestWorld(t *testing.T) *World {
	t.Helper()
	root := t.TempDir()
	return &World{
		Root:         root,
		consumerHome: filepath.Join(root, "consumer"),
		bundles:      map[string]*bundleState{},
	}
}

func TestSnapshotAbsentRootIsEmptyNotAnError(t *testing.T) {
	w := newTestWorld(t)
	s := w.SnapshotInstall()
	if s.Err != "" {
		t.Errorf("an install target that does not exist yet is a normal state, got Err=%q", s.Err)
	}
	if len(s.Files) != 0 {
		t.Errorf("expected the empty snapshot, got %d files", len(s.Files))
	}
}

// TestSnapshotFailureIsNeverEqual is the one that matters. Two failed readings
// must not compare equal, or INV-6 concludes "nothing changed" from having
// measured nothing twice.
func TestSnapshotFailureIsNeverEqual(t *testing.T) {
	a := InstallSnapshot{Files: map[string]string{}, Err: "boom"}
	b := InstallSnapshot{Files: map[string]string{}, Err: "boom"}
	if a.Equal(b) {
		t.Error("two unevaluable snapshots compared equal; that is a pass built on two failures to look")
	}
	clean := InstallSnapshot{Files: map[string]string{}}
	if a.Equal(clean) || clean.Equal(a) {
		t.Error("an unevaluable snapshot compared equal to a clean one")
	}
	if !clean.Equal(InstallSnapshot{Files: map[string]string{}}) {
		t.Error("two clean empty snapshots should be equal")
	}
}

func TestSnapshotSeesAdditionsAndChanges(t *testing.T) {
	w := newTestWorld(t)
	skills := filepath.Join(w.consumerHome, ".claude", "skills")
	writeFile(t, filepath.Join(skills, "s", "SKILL.md"), "one")
	before := w.SnapshotInstall()

	writeFile(t, filepath.Join(skills, "s", "SKILL.md"), "two")
	writeFile(t, filepath.Join(skills, "s", "extra.txt"), "x")
	after := w.SnapshotInstall()

	if before.Equal(after) {
		t.Fatal("a changed file and an added file went unnoticed")
	}
	d := before.Describe(after)
	if d == "no change" {
		t.Fatalf("Describe reported no change: %q", d)
	}
}

// TestSnapshotRecordsSymlinkWithoutFollowing pins the defence gosec asked for:
// the directory under measurement is written by the binary under test, so a
// planted symlink must not carry the read out of the tree.
func TestSnapshotRecordsSymlinkWithoutFollowing(t *testing.T) {
	w := newTestWorld(t)
	skills := filepath.Join(w.consumerHome, ".claude", "skills", "s")
	writeFile(t, filepath.Join(skills, "SKILL.md"), "one")
	outside := filepath.Join(w.Root, "outside.txt")
	writeFile(t, outside, "secret")
	if err := os.Symlink(outside, filepath.Join(skills, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	s := w.SnapshotInstall()
	if s.Err != "" {
		t.Fatalf("unexpected Err: %s", s.Err)
	}
	if got := s.Files["s/link"]; got != "symlink" {
		t.Errorf("the link was followed or hashed: %q; a swapped target would then look unchanged", got)
	}
}

func TestInstalledManifestDetectsMissingWrongAndExtra(t *testing.T) {
	w := newTestWorld(t)
	src := filepath.Join(w.Root, "src", "simskill")
	writeFile(t, filepath.Join(src, "SKILL.md"), "content")
	writeFile(t, filepath.Join(src, "scripts", "run.sh"), "echo hi")
	dst := filepath.Join(w.consumerHome, ".claude", "skills", "simskill")

	// Nothing installed at all.
	if ok, why := w.InstalledDigestMatches("simskill"); ok {
		t.Errorf("an empty install target reported as delivered: %q", why)
	}

	// One file missing.
	writeFile(t, filepath.Join(dst, "SKILL.md"), "content")
	if ok, why := w.InstalledDigestMatches("simskill"); ok {
		t.Error("a missing file passed; the old single-file check is what this replaces")
	} else if why == "" {
		t.Error("no reason given for the mismatch")
	}

	// Complete, with a legitimate install sidecar alongside.
	writeFile(t, filepath.Join(dst, "scripts", "run.sh"), "echo hi")
	writeFile(t, filepath.Join(dst, "bundle.json"), "{}")
	if ok, why := w.InstalledDigestMatches("simskill"); !ok {
		t.Errorf("a correct install with a named sidecar was rejected: %s", why)
	}

	// Wrong bytes.
	writeFile(t, filepath.Join(dst, "SKILL.md"), "tampered")
	if ok, _ := w.InstalledDigestMatches("simskill"); ok {
		t.Error("altered installed bytes passed")
	}
	writeFile(t, filepath.Join(dst, "SKILL.md"), "content")

	// A file nobody signed.
	writeFile(t, filepath.Join(dst, "backdoor.sh"), "curl evil")
	if ok, why := w.InstalledDigestMatches("simskill"); ok {
		t.Error("an unexpected file passed; that is the direction a single-file check cannot see")
	} else if why == "" {
		t.Error("no reason given for the unexpected file")
	}
}

func TestSourceManifestMissingTreeIsAnError(t *testing.T) {
	w := newTestWorld(t)
	if _, err := w.SourceManifest("nosuch"); err == nil {
		t.Error("a missing source tree must be an error, not an empty manifest that matches nothing")
	}
}
