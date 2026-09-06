package skillbundle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// write lays out a bundle root and returns it. Entries whose content is listed
// in CHECKSUMS are hashed honestly unless the caller overrides the line.
func write(t *testing.T, files map[string]string, checksums string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if checksums != "" {
		if err := os.WriteFile(filepath.Join(dir, "CHECKSUMS"), []byte(checksums), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func hashOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestValidateChecksumsAcceptsAnHonestManifest(t *testing.T) {
	dir := write(t, map[string]string{"SKILL.md": "body"},
		hashOf("body")+"  SKILL.md\n")
	if err := ValidateChecksums(dir); err != nil {
		t.Fatalf("an honest manifest must pass: %v", err)
	}
}

// The case BUG-0217 was about: the bytes are exactly what was signed, and the
// bundle's own manifest no longer describes them.
func TestValidateChecksumsRefusesAStaleManifest(t *testing.T) {
	dir := write(t, map[string]string{"SKILL.md": "edited after the manifest was built"},
		hashOf("body")+"  SKILL.md\n")
	err := ValidateChecksums(dir)
	if err == nil {
		t.Fatal("a stale manifest must be refused")
	}
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("the failure must carry ErrChecksumMismatch so a caller can map the class: %v", err)
	}
}

// Absence is not a failure: the manifest is optional in SPEC §3.1, and refusing
// its absence would reject bundles built before it existed.
func TestValidateChecksumsAcceptsNoManifest(t *testing.T) {
	dir := write(t, map[string]string{"SKILL.md": "body"}, "")
	if err := ValidateChecksums(dir); err != nil {
		t.Fatalf("a bundle without CHECKSUMS must pass: %v", err)
	}
}

// A manifest is attacker-influenced input, so an entry that points outside the
// bundle must be refused rather than followed.
func TestValidateChecksumsRefusesAnEscapingEntry(t *testing.T) {
	dir := write(t, map[string]string{"SKILL.md": "body"},
		hashOf("body")+"  ../../etc/passwd\n")
	err := ValidateChecksums(dir)
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("an escaping entry must be refused: %v", err)
	}
}

// A missing file named by the manifest is a mismatch, not a silent pass. The
// difference matters: skipping it would let a bundle delete its way to green.
func TestValidateChecksumsRefusesAMissingFile(t *testing.T) {
	dir := write(t, map[string]string{"SKILL.md": "body"},
		hashOf("body")+"  SKILL.md\n"+hashOf("gone")+"  gone.md\n")
	if err := ValidateChecksums(dir); !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("a file named by the manifest but absent must be refused: %v", err)
	}
}

// Both producers are accepted: the flat archive Pack emits, and the one wrapped
// in a single <name>-<version>/ directory.
func TestValidateChecksumsHandlesTheWrappedLayout(t *testing.T) {
	outer := t.TempDir()
	inner := filepath.Join(outer, "demo-1.0.0")
	if err := os.MkdirAll(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inner, "SKILL.md"), []byte("body"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inner, "CHECKSUMS"),
		[]byte(hashOf("wrong")+"  SKILL.md\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ValidateChecksums(outer); !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("the wrapped layout must be checked, not skipped: %v", err)
	}
}
