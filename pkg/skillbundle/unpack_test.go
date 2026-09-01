package skillbundle

// Characterisation corpus for the converged unpack core (SPEC-0252 §4). These
// tests pin the STRICTEST union of the three originals so the C2–C4 call-site
// migrations are provably behaviour-preserving (or stricter, never weaker).

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type titem struct {
	name string
	typ  byte
	body string
	link string
}

func reg(name, body string) titem  { return titem{name: name, typ: tar.TypeReg, body: body} }
func dir(name string) titem        { return titem{name: name, typ: tar.TypeDir} }
func sym(name, to string) titem    { return titem{name: name, typ: tar.TypeSymlink, link: to} }
func hard(name, to string) titem   { return titem{name: name, typ: tar.TypeLink, link: to} }
func chardev(name string) titem    { return titem{name: name, typ: tar.TypeChar} }

// makeArchive builds a gzip+tar blob from items, verbatim (no sanitisation) so
// tests can inject hostile headers.
func makeArchive(t *testing.T, items []titem) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, it := range items {
		hdr := &tar.Header{Name: it.name, Typeflag: it.typ, Mode: 0o644}
		switch it.typ {
		case tar.TypeReg:
			hdr.Size = int64(len(it.body))
		case tar.TypeSymlink, tar.TypeLink:
			hdr.Linkname = it.link
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header %q: %v", it.name, err)
		}
		if it.typ == tar.TypeReg {
			if _, err := tw.Write([]byte(it.body)); err != nil {
				t.Fatalf("write body %q: %v", it.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func relset(entries []Entry) map[string]Entry {
	m := make(map[string]Entry, len(entries))
	for _, e := range entries {
		m[e.Rel] = e
	}
	return m
}

func TestUnpack_FlatHappyPath_ModesAndContent(t *testing.T) {
	blob := makeArchive(t, []titem{
		reg("SKILL.md", "# skill"),
		reg("scripts/run.sh", "echo hi"),
		reg("references/doc.md", "ref"),
	})
	entries, err := Unpack(blob, UnpackOptions{})
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	m := relset(entries)
	if m["scripts/run.sh"].Mode != 0o755 {
		t.Errorf("scripts/* must be 0755, got %o", m["scripts/run.sh"].Mode)
	}
	if m["SKILL.md"].Mode != 0o644 {
		t.Errorf("SKILL.md must be 0644, got %o", m["SKILL.md"].Mode)
	}
	if string(m["references/doc.md"].Content) != "ref" {
		t.Errorf("content mismatch: %q", m["references/doc.md"].Content)
	}
}

func TestUnpack_RejectsTraversalAbsolute(t *testing.T) {
	// Header names that survive Go's tar.Writer verbatim (NUL/volume are tested
	// at the sanitiser level below, since the writer normalises those).
	cases := map[string][]titem{
		"dotdot":      {reg("../evil", "x")},
		"deep escape": {reg("a/../../b", "x")},
		"absolute":    {reg("/etc/passwd", "x")},
		"bare dotdot": {reg("..", "x")},
		"backslash":   {reg(`a\..\..\evil`, "x")},
	}
	for name, items := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Unpack(makeArchive(t, items), UnpackOptions{}); err == nil {
				t.Fatalf("expected rejection of %s, got nil (must REJECT, not rewrite)", name)
			}
		})
	}
}

// sanitizeArchivePath is the guard; test every rejection class directly (the
// high-level tar.Writer normalises NUL/volume names, so they can't be injected
// through makeArchive — but a hand-rolled or foreign tar can carry them).
func TestSanitizeArchivePath(t *testing.T) {
	reject := []string{"../evil", "a/../../b", "/etc/passwd", "..", `a\b`, "a\x00b"}
	for _, name := range reject {
		if _, err := sanitizeArchivePath(name); err == nil {
			t.Errorf("sanitizeArchivePath(%q) must reject", name)
		}
	}
	ok := map[string]string{"SKILL.md": "SKILL.md", "a/../b": "b", "./x": "x", "scripts/run.sh": "scripts/run.sh"}
	for in, want := range ok {
		got, err := sanitizeArchivePath(in)
		if err != nil || got != want {
			t.Errorf("sanitizeArchivePath(%q) = (%q,%v), want (%q,nil)", in, got, err, want)
		}
	}
	// "" and "." carry nothing → ("", nil), skipped by Unpack.
	for _, empty := range []string{"", "."} {
		if got, err := sanitizeArchivePath(empty); err != nil || got != "" {
			t.Errorf("sanitizeArchivePath(%q) = (%q,%v), want (\"\",nil)", empty, got, err)
		}
	}
}

func TestUnpack_ContainedDotDotIsNormalised(t *testing.T) {
	// a/../b stays inside the root → legitimate, normalised to "b".
	entries, err := Unpack(makeArchive(t, []titem{reg("a/../b", "x")}), UnpackOptions{})
	if err != nil {
		t.Fatalf("contained .. must normalise, got err: %v", err)
	}
	if len(entries) != 1 || entries[0].Rel != "b" {
		t.Fatalf("want rel=b, got %+v", entries)
	}
}

func TestUnpack_RefusesSymlinkHardlinkDevice(t *testing.T) {
	for name, it := range map[string]titem{
		"symlink":  sym("link", "/etc/passwd"),
		"hardlink": hard("hl", "SKILL.md"),
		"device":   chardev("dev"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Unpack(makeArchive(t, []titem{it}), UnpackOptions{}); err == nil {
				t.Fatalf("%s must be refused", name)
			}
		})
	}
}

func TestUnpack_ByteCeiling(t *testing.T) {
	blob := makeArchive(t, []titem{reg("big", strings.Repeat("A", 1000))})
	if _, err := Unpack(blob, UnpackOptions{MaxBytes: 100}); err == nil {
		t.Fatal("a file over the byte ceiling must error (gzip-bomb guard)")
	}
	if _, err := Unpack(blob, UnpackOptions{MaxBytes: 2000}); err != nil {
		t.Fatalf("within the ceiling must pass: %v", err)
	}
}

func TestUnpack_FileCountCap(t *testing.T) {
	blob := makeArchive(t, []titem{reg("a", "1"), reg("b", "2"), reg("c", "3")})
	if _, err := Unpack(blob, UnpackOptions{MaxFiles: 2}); err == nil {
		t.Fatal("exceeding the file-count cap must error (tar-bomb guard)")
	}
}

func TestUnpack_WrapperStrip_RecomputesScriptMode(t *testing.T) {
	// Everything under one wrapper dir; scripts/* must be 0755 AFTER strip — the
	// regression the separate helpers risked.
	blob := makeArchive(t, []titem{
		reg("mybundle/SKILL.md", "# s"),
		reg("mybundle/scripts/run.sh", "echo"),
	})
	entries, err := Unpack(blob, UnpackOptions{StripWrapper: true})
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	m := relset(entries)
	if _, ok := m["SKILL.md"]; !ok {
		t.Fatalf("wrapper not stripped: %v", entries)
	}
	if m["scripts/run.sh"].Mode != 0o755 {
		t.Errorf("scripts/* must be 0755 after wrapper strip, got %o", m["scripts/run.sh"].Mode)
	}
}

func TestUnpack_NoWrapperStripWhenRootFileOrMultiTop(t *testing.T) {
	// A root-level file ⇒ flat ⇒ no strip.
	flat := makeArchive(t, []titem{reg("SKILL.md", "s"), reg("a/x", "1")})
	e1, _ := Unpack(flat, UnpackOptions{StripWrapper: true})
	if _, ok := relset(e1)["SKILL.md"]; !ok {
		t.Fatalf("flat bundle must not be stripped: %v", e1)
	}
	// Two distinct top-level dirs ⇒ no common wrapper ⇒ no strip.
	multi := makeArchive(t, []titem{reg("one/a", "1"), reg("two/b", "2")})
	e2, _ := Unpack(multi, UnpackOptions{StripWrapper: true})
	if _, ok := relset(e2)["one/a"]; !ok {
		t.Fatalf("multi-top must not be stripped: %v", e2)
	}
}

func TestUnpack_CanonicalizeSkillMD(t *testing.T) {
	blob := makeArchive(t, []titem{reg("mybundle/Skill.md", "# s")})
	entries, err := Unpack(blob, UnpackOptions{StripWrapper: true, CanonicalizeMD: true})
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if entries[0].Rel != "SKILL.md" {
		t.Fatalf("skill anchor must canonicalise to SKILL.md, got %q", entries[0].Rel)
	}
}

func TestExtractTo_WritesAndRefusesCollision(t *testing.T) {
	dest := t.TempDir()
	blob := makeArchive(t, []titem{reg("SKILL.md", "# s"), reg("scripts/run.sh", "echo")})
	entries, err := Unpack(blob, UnpackOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := ExtractTo(entries, dest); err != nil {
		t.Fatalf("extract: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dest, "SKILL.md")); string(b) != "# s" {
		t.Errorf("SKILL.md content wrong: %q", b)
	}
	// O_EXCL: extracting the same entry twice into a populated dir must fail closed.
	if err := ExtractTo(entries, dest); err == nil {
		t.Fatal("re-extracting onto existing files must fail (O_EXCL), not silently overwrite")
	}
}

func TestExtractTo_DuplicateEntryFailsClosed(t *testing.T) {
	// Two entries with the same rel in ONE archive → the second write collides.
	blob := makeArchive(t, []titem{reg("dup", "first"), reg("dup", "second")})
	entries, err := Unpack(blob, UnpackOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := ExtractTo(entries, t.TempDir()); err == nil {
		t.Fatal("a duplicate/colliding entry must fail closed under O_EXCL")
	}
}

func TestSafeJoin(t *testing.T) {
	dest := t.TempDir()
	if _, err := SafeJoin(dest, "a/b.md"); err != nil {
		t.Errorf("contained path must join: %v", err)
	}
	for _, bad := range []string{"../x", "../../etc/passwd"} {
		if _, err := SafeJoin(dest, bad); err == nil {
			t.Errorf("SafeJoin must reject escaping path %q", bad)
		}
	}
}

func TestUnpack_EmptyAndDotNamesSkipped(t *testing.T) {
	blob := makeArchive(t, []titem{reg("SKILL.md", "s"), dir("."), reg("", "ignored")})
	entries, err := Unpack(blob, UnpackOptions{})
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if len(entries) != 1 || entries[0].Rel != "SKILL.md" {
		t.Fatalf("empty/'.' entries must be skipped, got %+v", entries)
	}
}

// The strongest equivalence test: a bundle from the REAL producer (Pack) must
// round-trip through Unpack to the same files with the same modes.
func TestUnpack_RoundTripsRealPackOutput(t *testing.T) {
	skillDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte("# real skill"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(skillDir, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillDir, "scripts", "go.sh"), []byte("echo go"), 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "b.skb")
	if _, err := Pack(skillDir, out, PackOptions{}); err != nil {
		t.Fatalf("pack: %v", err)
	}
	blob, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := Unpack(blob, UnpackOptions{StripWrapper: true, CanonicalizeMD: true})
	if err != nil {
		t.Fatalf("unpack real bundle: %v", err)
	}
	m := relset(entries)
	for _, want := range []string{"SKILL.md", "scripts/go.sh", "bundle.json", "CHECKSUMS"} {
		if _, ok := m[want]; !ok {
			t.Errorf("packed bundle missing %q after round-trip; got %v", want, keys(m))
		}
	}
	if m["SKILL.md"].Content == nil || string(m["SKILL.md"].Content) != "# real skill" {
		t.Errorf("SKILL.md content not preserved: %q", m["SKILL.md"].Content)
	}
	if m["scripts/go.sh"].Mode != 0o755 {
		t.Errorf("scripts/go.sh must be 0755, got %o", m["scripts/go.sh"].Mode)
	}
}

func keys(m map[string]Entry) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
