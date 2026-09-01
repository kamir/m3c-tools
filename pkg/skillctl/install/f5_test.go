package install

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// TestContentBinding_NestedStashName_Flagged proves SEC F5: a NESTED file named
// like a top-level stash file (here .m3c-provenance.json under scripts/) is no
// longer skipped by basename — it is flagged as an unexpected installed file.
func TestContentBinding_NestedStashName_Flagged(t *testing.T) {
	dir := t.TempDir()
	skb := makeSkb(t, dir, map[string]string{"SKILL.md": "# hello"})
	if err := os.MkdirAll(filepath.Join(dir, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "scripts", registry.ProvenanceSidecarName), []byte("planted"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyExtractedMatchesBlob(skb, dir); !errors.Is(err, verify.ErrDigestMismatch) {
		t.Fatalf("nested stash-named file must be flagged (ErrDigestMismatch), got %v", err)
	}
}

// TestContentBinding_NestedSkb_Flagged proves a planted nested *.skb is flagged
// (only the top-level stash .skb is skipped).
func TestContentBinding_NestedSkb_Flagged(t *testing.T) {
	dir := t.TempDir()
	skb := makeSkb(t, dir, map[string]string{"SKILL.md": "# hello"})
	if err := os.MkdirAll(filepath.Join(dir, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "scripts", "payload.skb"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyExtractedMatchesBlob(skb, dir); !errors.Is(err, verify.ErrDigestMismatch) {
		t.Fatalf("nested .skb must be flagged (ErrDigestMismatch), got %v", err)
	}
}

// TestContentBinding_TopLevelDSStore_StillSkipped confirms .DS_Store stays
// benign (skipped anywhere) — the F5 tightening must not flag macOS noise.
func TestContentBinding_NestedDSStore_StillSkipped(t *testing.T) {
	dir := t.TempDir()
	skb := makeSkb(t, dir, map[string]string{"SKILL.md": "# hello", "sub/x.txt": "d"})
	if err := os.WriteFile(filepath.Join(dir, "sub", ".DS_Store"), []byte("junk"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyExtractedMatchesBlob(skb, dir); err != nil {
		t.Fatalf("nested .DS_Store is benign and must NOT be flagged, got %v", err)
	}
}

// TestFindStashedSkb_RefusesMultiple proves the ambiguous-stash guard: two
// top-level .skb files are refused fail-closed rather than picking one.
func TestFindStashedSkb_RefusesMultiple(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.skb"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.skb"), []byte("b"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := findStashedSkb(dir); !errors.Is(err, verify.ErrDigestMismatch) {
		t.Fatalf(">1 top-level .skb must be refused (ErrDigestMismatch), got %v", err)
	}
}
