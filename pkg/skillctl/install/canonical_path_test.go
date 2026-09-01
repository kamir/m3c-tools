package install

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCanonicalPath_ResolvesSymlink locks the R-6.2 fixed point: a path that
// reaches its target through a symlink resolves to the symlink's real target, so
// the guard classifier cannot be fooled by a symlinked-in body.
func TestCanonicalPath_ResolvesSymlink(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	realFile := filepath.Join(realDir, "SKILL.md")
	if err := os.WriteFile(realFile, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "alias")
	if err := os.Symlink(realDir, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	got, err := CanonicalPath(filepath.Join(link, "SKILL.md"))
	if err != nil {
		t.Fatalf("CanonicalPath: %v", err)
	}
	want, err := filepath.EvalSymlinks(realFile)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("CanonicalPath via symlink = %q, want %q", got, want)
	}
}

// TestCanonicalPath_NonExistentTail resolves the longest existing ancestor and
// re-appends the not-yet-existing tail (a Write creating a new file), while still
// resolving a symlinked ancestor.
func TestCanonicalPath_NonExistentTail(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "alias")
	if err := os.Symlink(realDir, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	got, err := CanonicalPath(filepath.Join(link, "newfile.txt"))
	if err != nil {
		t.Fatalf("CanonicalPath: %v", err)
	}
	realResolved, err := filepath.EvalSymlinks(realDir)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(realResolved, "newfile.txt")
	if got != want {
		t.Errorf("CanonicalPath non-existent tail = %q, want %q", got, want)
	}
}

// TestCanonicalPath_Empty rejects an empty path.
func TestCanonicalPath_Empty(t *testing.T) {
	if _, err := CanonicalPath("  "); err == nil {
		t.Error("CanonicalPath(\"  \") = nil error, want rejection")
	}
}
