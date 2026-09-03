package skillbundle

// Native Go fuzz targets for the skill-bundle archive readers (SPEC-0252). Both
// surfaces take fully untrusted input — a downloaded/pulled bundle blob and the
// per-entry relative paths derived from it — so the invariant we care about is
// containment: nothing a hostile archive says may ever escape the archive root
// (Unpack) or the destination directory (ExtractTo). The oracle is the escape
// itself: any returned entry / on-disk write outside the sandbox is a t.Fatal,
// so the fuzzer treats a containment break as a crash.
//
// titem/reg/dir/sym/hard/chardev live in unpack_test.go (same package); the
// gzip+tar seed blobs here are built with buildFuzzTGZ so no *testing.T is
// needed at f.Add time.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildFuzzTGZ assembles a gzip+tar blob from items verbatim (no sanitisation)
// so seeds can carry hostile headers. It panics on the (impossible for static
// seeds) writer error — it is only ever called with the constant corpora below.
func buildFuzzTGZ(items []titem) []byte {
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
			panic(err)
		}
		if it.typ == tar.TypeReg {
			if _, err := tw.Write([]byte(it.body)); err != nil {
				panic(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		panic(err)
	}
	if err := gz.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// FuzzUnpack drives Unpack with untrusted archive bytes and a fuzzed options
// byte. Oracles: Unpack never panics, and on success NO returned entry escapes
// the archive root (never absolute, "", ".", "..", "../…"; SafeJoin under a
// throwaway dest always stays contained).
func FuzzUnpack(f *testing.F) {
	// valid + adversarial archive seeds (reuse the traversal/symlink/hardlink/
	// device/oversized/too-many-files classes exercised in unpack_test.go).
	seeds := [][]titem{
		{reg("SKILL.md", "# s"), reg("scripts/run.sh", "echo hi"), reg("references/doc.md", "ref")},
		{dir("bundle"), reg("bundle/SKILL.md", "# s"), reg("bundle/scripts/run.sh", "x")}, // wrapped
		{reg("mybundle/Skill.md", "# s")},                                                 // canonicalize
		{reg("../evil", "x")},                                                             // traversal
		{reg("a/../../b", "x")},                                                           // deep escape
		{reg("/etc/passwd", "x")},                                                         // absolute
		{reg("..", "x")},                                                                  // bare dotdot
		{reg(`a\..\..\evil`, "x")},                                                        // backslash
		{sym("link", "/etc/passwd")},                                                      // symlink refused
		{hard("hl", "/etc/passwd")},                                                       // hardlink refused
		{chardev("dev")},                                                                  // device refused
		{reg("big", strings.Repeat("A", 4096))},                                           // exercises the byte ceiling when opt bit set
		{reg("a", "1"), reg("b", "2"), reg("c", "3")},                                     // exercises the file-count cap when opt bit set
	}
	// optBits: bit0 StripWrapper, bit1 CanonicalizeMD, bit2 tiny MaxBytes, bit3 tiny MaxFiles.
	optCombos := []uint8{0, 1, 2, 3, 4, 8, 12}
	for _, s := range seeds {
		blob := buildFuzzTGZ(s)
		for _, o := range optCombos {
			f.Add(blob, o)
		}
	}
	// Non-archive / degenerate byte seeds.
	f.Add([]byte("not a gzip at all"), uint8(0))
	f.Add([]byte{}, uint8(0))
	f.Add([]byte{0x1f, 0x8b}, uint8(0)) // gzip magic, truncated

	f.Fuzz(func(t *testing.T, data []byte, optBits uint8) {
		opts := UnpackOptions{
			StripWrapper:   optBits&1 != 0,
			CanonicalizeMD: optBits&2 != 0,
		}
		if optBits&4 != 0 {
			opts.MaxBytes = 512 // small ceiling → exercise gzip-bomb branch
		}
		if optBits&8 != 0 {
			opts.MaxFiles = 2 // small cap → exercise tar-bomb branch
		}

		entries, err := Unpack(data, opts) // must never panic
		if err != nil {
			return
		}
		dest := t.TempDir()
		absDest, aerr := filepath.Abs(dest)
		if aerr != nil {
			t.Fatalf("abs(dest): %v", aerr)
		}
		for _, e := range entries {
			if e.Rel == "" || e.Rel == "." || e.Rel == ".." ||
				strings.HasPrefix(e.Rel, "../") || strings.HasPrefix(e.Rel, "/") ||
				filepath.IsAbs(filepath.FromSlash(e.Rel)) {
				t.Fatalf("Unpack returned an escaping entry rel=%q", e.Rel)
			}
			full, jerr := SafeJoin(dest, e.Rel)
			if jerr != nil {
				t.Fatalf("Unpack returned rel=%q that SafeJoin rejects: %v", e.Rel, jerr)
			}
			if full != absDest && !strings.HasPrefix(full, absDest+string(filepath.Separator)) {
				t.Fatalf("Unpack entry rel=%q resolves outside dest: full=%q dest=%q", e.Rel, full, absDest)
			}
		}
	})
}

// FuzzExtractTo drives ExtractTo directly with an Entry whose Rel is fully
// fuzzed (bypassing Unpack's sanitiser) to exercise the SafeJoin write guard in
// isolation. Oracle: whatever ExtractTo does, no filesystem entry is ever
// created OUTSIDE destDir — checked after the fact by walking the sandbox root.
func FuzzExtractTo(f *testing.F) {
	seeds := []struct {
		rel     string
		content []byte
		isDir   bool
	}{
		{"SKILL.md", []byte("# s"), false},
		{"scripts/run.sh", []byte("echo"), false},
		{"nested/deeper/dir", nil, true},
		{"../escape", []byte("x"), false},
		{"../../etc/passwd", []byte("x"), false},
		{"/abs/path", []byte("x"), false},
		{"a/../../b", []byte("x"), false},
		{"..", []byte("x"), false},
		{`a\..\..\evil`, []byte("x"), false},
		{"name:ads", []byte("x"), false},
		{"", []byte("x"), false},
	}
	for _, s := range seeds {
		f.Add(s.rel, s.content, s.isDir)
	}

	f.Fuzz(func(t *testing.T, rel string, content []byte, isDir bool) {
		root := t.TempDir()
		dest := filepath.Join(root, "dest")
		if err := os.MkdirAll(dest, 0o755); err != nil {
			t.Fatalf("mkdir dest: %v", err)
		}
		absRoot, _ := filepath.Abs(root)
		absDest, _ := filepath.Abs(dest)

		entries := []Entry{{Rel: rel, Content: content, IsDir: isDir, Mode: 0o644}}
		_ = ExtractTo(entries, dest) // must never panic; an error is a fine outcome

		// Oracle: nothing was written outside dest. The only pre-existing entry
		// under root is dest itself; anything else is a containment breach.
		_ = filepath.WalkDir(absRoot, func(p string, _ fs.DirEntry, werr error) error {
			if werr != nil {
				return nil
			}
			if p == absRoot || p == absDest || strings.HasPrefix(p, absDest+string(filepath.Separator)) {
				return nil
			}
			t.Fatalf("ExtractTo wrote outside destDir: rel=%q created %q (dest=%q)", rel, p, absDest)
			return nil
		})
	})
}
