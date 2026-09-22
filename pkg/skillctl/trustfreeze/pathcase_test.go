package trustfreeze

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// TestDirectoryCaseCollisionRefusedByWriter: two paths whose directories
// differ only by letter case would share one directory on Windows and macOS
// and not on Linux; the writer refuses the second.
func TestDirectoryCaseCollisionRefusedByWriter(t *testing.T) {
	w, err := NewWriter(filepath.Join(t.TempDir(), "b"), WriterOptions{Kind: KindCapture})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Abort()
	if err := w.WriteJSON("state/a.json", StateDoc{Artifacts: []Artifact{}}); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteJSON("State/b.json", StateDoc{Artifacts: []Artifact{}}); !errors.Is(err, ErrBadPath) {
		t.Fatalf("WriteJSON(State/b.json) = %v, want ErrBadPath", err)
	}
	if err := w.WriteJSON("state/c.json", StateDoc{Artifacts: []Artifact{}}); err != nil {
		t.Fatalf("same spelling refused: %v", err)
	}
}

// TestDirectoryCaseCollisionFailsVerify: a manifest listing such a pair fails
// on every OS, so the verdict does not depend on the verifying filesystem.
func TestDirectoryCaseCollisionFailsVerify(t *testing.T) {
	dir, _ := newCapture(t, t.TempDir(), "cap", "common.identity")
	rewriteManifest(t, dir, true, func(m *Manifest) {
		m.Files = append(m.Files, FileEntry{Path: "State/b.json", Size: 1, SHA256: strings.Repeat("0", 64)})
		sortEntries(m.Files)
	})
	res := VerifyDir(dir)
	if res.OK || !res.Has(IntegrityDuplicatePath) {
		t.Fatalf("verify: %s", describeFailures(res))
	}
	found := false
	for _, f := range res.Failures {
		if f.Reason == IntegrityDuplicatePath && strings.Contains(f.Detail, "by letter case") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no directory case collision reported: %s", describeFailures(res))
	}
}
