package skillbundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fixedTime keeps the digest reproducible across machines.
var fixedTime = time.Date(2026, 5, 5, 19, 30, 0, 0, time.UTC)

// goldenDigest pins the expected digest for the fixture skill + fixtureManifest +
// fixedTime + BuiltBy="skillctl/test". Recompute by running with
// SKILLBUNDLE_EXPECTED_DIGEST=any once and pasting the actual digest back.
const goldenDigest = "sha256:15fd20c2141d63d218cebe10e768a236f725756b1bc0c56f08eafeecf07882c1"

func fixtureManifest() BundleManifest {
	return BundleManifest{
		Name:                "fetch-contract",
		Version:             "1.0.0",
		Summary:             "Fetch m3c inter-agent contracts from ER1 by tag query.",
		SourceRepo:          "kamir/m3c-tools-maintenance",
		SourceCommit:        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		SourcePath:          ".claude/skills/fetch-contract",
		AuthorGovernanceIntent:    "green",
		AuthorGovernanceRationale: "Read-only ER1 query; no writes; failure non-destructive.",
		DependsOn: []Dependency{
			{Kind: "python", Name: "requests", Constraint: ">=2.31"},
			{Kind: "python", Name: "pyyaml", Constraint: ">=6.0"},
		},
		Compatibility: "Claude Code >= 0.5; Python >= 3.10",
	}
}

// writeFixtureSkill builds a small skill dir. Files are written in non-sorted
// order on purpose so the lex-order assertion in TestCanonicalization is real.
// Includes a top-level dotfile (must be skipped) and a scripts/ file (must
// land at mode 0755).
func writeFixtureSkill(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	mustWrite := func(rel, body string, mode os.FileMode) {
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatalf("mkdir %s: %v", full, err)
		}
		if err := os.WriteFile(full, []byte(body), mode); err != nil {
			t.Fatalf("write %s: %v", full, err)
		}
	}
	mustWrite("scripts/run.py", "print('hello from scripts')\n", 0600)
	mustWrite("references/note.md", "# notes\n", 0644)
	mustWrite("SKILL.md", "---\nname: fixture\n---\n# fixture skill\n", 0644)
	mustWrite(".DS_Store", "junk", 0644)
	return dir
}

// TestDeterminism: identical input → byte-identical output.
func TestDeterminism(t *testing.T) {
	src := writeFixtureSkill(t)
	out := t.TempDir()
	a := filepath.Join(out, "a.skb")
	b := filepath.Join(out, "b.skb")
	opts := PackOptions{Manifest: fixtureManifest(), BuiltAt: fixedTime}

	digA, err := Pack(src, a, opts)
	if err != nil {
		t.Fatalf("pack a: %v", err)
	}
	digB, err := Pack(src, b, opts)
	if err != nil {
		t.Fatalf("pack b: %v", err)
	}
	if digA != digB {
		t.Fatalf("digests differ: %s vs %s", digA, digB)
	}
	bytesA, _ := os.ReadFile(a)
	bytesB, _ := os.ReadFile(b)
	if !bytes.Equal(bytesA, bytesB) {
		t.Fatalf("bundle bytes differ (len a=%d b=%d)", len(bytesA), len(bytesB))
	}
}

// TestCanonicalization: tar entries are lex-sorted, dotfiles are stripped,
// synthesized files are present.
func TestCanonicalization(t *testing.T) {
	src := writeFixtureSkill(t)
	out := filepath.Join(t.TempDir(), "x.skb")
	if _, err := Pack(src, out, PackOptions{Manifest: fixtureManifest(), BuiltAt: fixedTime}); err != nil {
		t.Fatalf("pack: %v", err)
	}
	names := readTarNames(t, out)
	for i := 1; i < len(names); i++ {
		if names[i-1] >= names[i] {
			t.Fatalf("tar entries not in lex order: %v", names)
		}
	}
	want := map[string]bool{"CHECKSUMS": false, "SKILL.md": false, "bundle.json": false, "references/note.md": false, "scripts/run.py": false}
	for _, n := range names {
		if _, ok := want[n]; ok {
			want[n] = true
		}
		if n == ".DS_Store" {
			t.Errorf("top-level dotfile leaked into bundle: %s", n)
		}
	}
	for n, found := range want {
		if !found {
			t.Errorf("missing tar entry: %s", n)
		}
	}
}

// TestMtimesZeroed: every entry has ModTime == Unix epoch and uid/gid 0/0.
func TestMtimesZeroed(t *testing.T) {
	src := writeFixtureSkill(t)
	out := filepath.Join(t.TempDir(), "x.skb")
	if _, err := Pack(src, out, PackOptions{Manifest: fixtureManifest(), BuiltAt: fixedTime}); err != nil {
		t.Fatalf("pack: %v", err)
	}
	zero := time.Unix(0, 0).UTC()
	for _, h := range readTarHeaders(t, out) {
		if !h.ModTime.Equal(zero) {
			t.Errorf("entry %s has ModTime %v, want %v", h.Name, h.ModTime, zero)
		}
		if h.Uid != 0 || h.Gid != 0 || h.Uname != "" || h.Gname != "" {
			t.Errorf("entry %s has owner metadata %d/%d %q/%q", h.Name, h.Uid, h.Gid, h.Uname, h.Gname)
		}
	}
}

// TestModeNormalization: scripts/* → 0755, everything else → 0644.
func TestModeNormalization(t *testing.T) {
	src := writeFixtureSkill(t)
	out := filepath.Join(t.TempDir(), "x.skb")
	if _, err := Pack(src, out, PackOptions{Manifest: fixtureManifest(), BuiltAt: fixedTime}); err != nil {
		t.Fatalf("pack: %v", err)
	}
	got := map[string]int64{}
	for _, h := range readTarHeaders(t, out) {
		got[h.Name] = h.Mode
	}
	cases := []struct {
		name string
		want int64
	}{
		{"SKILL.md", 0644},
		{"references/note.md", 0644},
		{"scripts/run.py", 0755},
		{"CHECKSUMS", 0644},
		{"bundle.json", 0644},
	}
	for _, c := range cases {
		if g, ok := got[c.name]; !ok {
			t.Errorf("missing entry %s", c.name)
		} else if g != c.want {
			t.Errorf("entry %s: mode=%#o, want %#o", c.name, g, c.want)
		}
	}
}

// TestDigestStability: a known fixture produces the goldenDigest.
// Catches any future regression in canonicalization.
func TestDigestStability(t *testing.T) {
	src := writeFixtureSkill(t)
	out := filepath.Join(t.TempDir(), "x.skb")
	digest, err := Pack(src, out, PackOptions{Manifest: fixtureManifest(), BuiltAt: fixedTime, BuiltBy: "skillctl/test"})
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	expected := os.Getenv("SKILLBUNDLE_EXPECTED_DIGEST")
	if expected == "" {
		expected = goldenDigest
	}
	if digest != expected {
		t.Fatalf("digest drift:\n  got  %s\n  want %s", digest, expected)
	}
	manifestBytes := readTarFile(t, out, "bundle.json")
	if !bytes.Contains(manifestBytes, []byte(digest)) {
		t.Fatalf("bundle.json does not embed digest %s", digest)
	}
}

// readTarHeaders returns every tar header from a gzipped tar.
func readTarHeaders(t *testing.T, path string) []*tar.Header {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	tr := tar.NewReader(gz)
	var out []*tar.Header
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		out = append(out, h)
		io.Copy(io.Discard, tr)
	}
	return out
}

func readTarNames(t *testing.T, path string) []string {
	headers := readTarHeaders(t, path)
	names := make([]string, len(headers))
	for i, h := range headers {
		names[i] = h.Name
	}
	return names
}

// readTarFile returns the contents of one named entry inside a gzipped tar.
func readTarFile(t *testing.T, path, name string) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	gz, _ := gzip.NewReader(f)
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		if h.Name == name {
			data, _ := io.ReadAll(tr)
			return data
		}
	}
	t.Fatalf("tar entry %s not found", name)
	return nil
}
