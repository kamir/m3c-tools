package skillbundle

// unpack.go — the ONE hardened gzip+tar reader for skill bundles (SPEC-0252).
//
// Before this, three call sites each walked a SPEC-0188 §3.1 archive with their
// own path-sanitiser, wrapper-strip, cap mechanism, and mode logic:
//
//   - pkg/skillctl/install.extractTGZ            (HTTP install)
//   - pkg/skillctl/registry.extractSkb           (self/ER1 install)
//   - pkg/skillctl/install.verifyExtractedMatchesBlob (the hot gate comparator)
//
// They had drifted (two separate wrapper-strip helpers that must agree but were
// separate code; two duplicated cap consts; a sanitiser that *rewrote* traversal
// vs two that *rejected* it). Every tar-hardening fix had to be applied 2–3×.
//
// Unpack is the single tar reader. It NEVER touches the filesystem — it returns
// a validated, bounded, in-memory entry list. ExtractTo writes that list with
// O_EXCL. SafeJoin is the one path-containment guard both ExtractTo and the
// comparator use. The package owns the canonical cap constants. New hardening
// now lands once, here, and drift is impossible by construction.
//
// Equivalence discipline (SPEC-0252 §4): this encodes the STRICTEST union of the
// three originals — traversal/absolute/volume names are REJECTED (not silently
// rewritten), symlinks/hardlinks/devices refused, byte ceiling + file-count cap
// enforced per-entry, O_EXCL on write. unpack_test.go pins every input class.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Canonical caps — the single source of truth (SPEC-0252 §3.3). The duplicated
// install.MaxExtractedBytes / registry.MaxExtractedBytes consts collapse onto
// these during the C2–C4 migration.
const (
	// DefaultMaxExtractedBytes bounds total uncompressed output (gzip-bomb guard).
	DefaultMaxExtractedBytes int64 = 100 << 20 // 100 MiB
	// DefaultMaxExtractedFiles bounds the tar entry count (tar-bomb guard).
	DefaultMaxExtractedFiles = 10000
)

// Entry is one validated, in-memory archive member. By the time Unpack returns
// it, Rel is clean, relative, forward-slash, and proven not to escape the
// archive root (never "", ".", "..", absolute, or volume-prefixed); Content is
// bounded by the byte ceiling.
type Entry struct {
	Rel     string      // clean relative forward-slash path
	IsDir   bool        // directory entry
	Mode    fs.FileMode // 0755 for dirs and scripts/*, else 0644 (one policy)
	Content []byte      // file body; nil for dirs
}

// UnpackOptions tunes the shared reader for each call site.
type UnpackOptions struct {
	MaxBytes       int64 // uncompressed ceiling; <=0 → DefaultMaxExtractedBytes
	MaxFiles       int   // entry-count cap;        <=0 → DefaultMaxExtractedFiles
	StripWrapper   bool  // collapse one common top-level dir (SPEC-0188 §3.1 wrapped bundles)
	CanonicalizeMD bool  // rename a root-level skill.md/Skill.md → SKILL.md
}

// Unpack decompresses + walks the gzip+tar archive exactly ONCE and returns the
// validated entry list. It enforces the byte ceiling and file-count cap, refuses
// absolute / `..`-escaping / volume-prefixed / backslash / NUL paths, refuses
// symlinks, hardlinks, devices and fifos, and (when asked) strips a single
// common top-level wrapper dir and canonicalises the skill anchor. It does not
// write anything — callers decide (ExtractTo writes; the comparator hashes).
func Unpack(archive []byte, opts UnpackOptions) ([]Entry, error) {
	maxBytes := opts.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxExtractedBytes
	}
	maxFiles := opts.MaxFiles
	if maxFiles <= 0 {
		maxFiles = DefaultMaxExtractedFiles
	}

	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("skillbundle: gzip reader: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	var entries []Entry
	var written int64
	var count int
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("skillbundle: read tar header: %w", err)
		}
		count++
		if count > maxFiles {
			return nil, fmt.Errorf("skillbundle: tar entry count exceeds %d (likely a tar bomb)", maxFiles)
		}

		rel, err := sanitizeArchivePath(hdr.Name)
		if err != nil {
			return nil, err
		}
		if rel == "" { // empty / "." entries carry nothing
			continue
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			entries = append(entries, Entry{Rel: rel, IsDir: true})
		case tar.TypeReg, tar.TypeRegA:
			// Cap this entry against the remaining global budget. LimitReader to
			// remaining+1 so a lying header (n > remaining) is detected.
			remaining := maxBytes - written
			if remaining <= 0 {
				return nil, fmt.Errorf("skillbundle: extracted size exceeds %d bytes (likely a gzip bomb)", maxBytes)
			}
			var buf bytes.Buffer
			n, err := io.Copy(&buf, io.LimitReader(tr, remaining+1))
			if err != nil {
				return nil, fmt.Errorf("skillbundle: read entry %q: %w", rel, err)
			}
			if n > remaining {
				return nil, fmt.Errorf("skillbundle: extracted size exceeds %d bytes (likely a gzip bomb)", maxBytes)
			}
			written += n
			entries = append(entries, Entry{Rel: rel, Content: buf.Bytes()})
		case tar.TypeSymlink, tar.TypeLink:
			// SPEC-0188 v1: symlinks/hardlinks point into / out of the install
			// dir post-rename — refused.
			return nil, fmt.Errorf("skillbundle: tar entry %q is a symlink/hardlink (refused)", hdr.Name)
		default:
			// Devices, fifos, etc. — refused.
			return nil, fmt.Errorf("skillbundle: tar entry %q has unsupported type 0x%x", hdr.Name, hdr.Typeflag)
		}
	}

	if opts.StripWrapper {
		entries = stripWrapper(entries)
	}
	if opts.CanonicalizeMD {
		for i := range entries {
			if strings.EqualFold(entries[i].Rel, "skill.md") {
				entries[i].Rel = "SKILL.md"
			}
		}
	}

	// One mode policy, applied AFTER strip so a wrapped scripts/* path is scored
	// on its final (stripped) name (matches pack.canonicalMode).
	for i := range entries {
		entries[i].Mode = modeFor(entries[i].Rel, entries[i].IsDir)
	}
	return entries, nil
}

// ExtractTo writes a validated entry list into destDir. Parents are created;
// files use O_EXCL so a duplicate/colliding entry fails closed instead of
// silently truncating a prior write; Entry.Mode is applied. destDir containment
// is re-checked per entry via SafeJoin (defence in depth over Unpack's proof).
func ExtractTo(entries []Entry, destDir string) error {
	for _, e := range entries {
		full, err := SafeJoin(destDir, e.Rel)
		if err != nil {
			return err
		}
		if e.IsDir {
			if err := os.MkdirAll(full, 0o755); err != nil {
				return fmt.Errorf("skillbundle: mkdir %s: %w", full, err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return fmt.Errorf("skillbundle: mkdir parent %s: %w", full, err)
		}
		mode := e.Mode
		if mode == 0 {
			mode = 0o644
		}
		f, err := os.OpenFile(full, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			return fmt.Errorf("skillbundle: open %s: %w", full, err)
		}
		if _, err := f.Write(e.Content); err != nil {
			_ = f.Close()
			_ = os.Remove(full)
			return fmt.Errorf("skillbundle: write %s: %w", full, err)
		}
		// Chmod explicitly so the result is umask-independent (matches the
		// original extractTGZ behaviour).
		if err := f.Chmod(mode); err != nil {
			_ = f.Close()
			_ = os.Remove(full)
			return fmt.Errorf("skillbundle: chmod %s: %w", full, err)
		}
		if err := f.Close(); err != nil {
			_ = os.Remove(full)
			return fmt.Errorf("skillbundle: close %s: %w", full, err)
		}
	}
	return nil
}

// SafeJoin resolves rel under destDir and proves the result stays inside it on a
// path-component boundary (the trailing-separator trick stops /tmp/foo matching
// /tmp/foobar). It is the single containment guard for both ExtractTo and the
// gate comparator's on-disk reads.
func SafeJoin(destDir, rel string) (string, error) {
	absDest, err := filepath.Abs(destDir)
	if err != nil {
		return "", fmt.Errorf("skillbundle: abs(destDir): %w", err)
	}
	full := filepath.Join(absDest, filepath.FromSlash(rel))
	absFull, err := filepath.Abs(full)
	if err != nil {
		return "", fmt.Errorf("skillbundle: abs(%s): %w", full, err)
	}
	if absFull != absDest && !strings.HasPrefix(absFull+string(filepath.Separator), absDest+string(filepath.Separator)) {
		return "", fmt.Errorf("skillbundle: entry %q resolves outside destination (%s)", rel, absFull)
	}
	return absFull, nil
}

// WrapperDir returns the single common top-level directory shared by EVERY
// regular-file entry, or "" when there is none (a flat bundle, or files spread
// across multiple top-level dirs). This is the ONE wrapper helper that replaces
// registry.wrapperPrefixFromEntries and install.commonTopLevelDir.
func WrapperDir(entries []Entry) string {
	seg := ""
	any := false
	for _, e := range entries {
		if e.IsDir {
			continue
		}
		i := strings.IndexByte(e.Rel, '/')
		if i < 0 {
			return "" // a file at the root → flat
		}
		first := e.Rel[:i]
		if !any {
			seg, any = first, true
		} else if first != seg {
			return "" // more than one top-level segment → flat
		}
	}
	if any {
		return seg
	}
	return ""
}

func stripWrapper(entries []Entry) []Entry {
	w := WrapperDir(entries)
	if w == "" {
		return entries
	}
	prefix := w + "/"
	out := entries[:0]
	for _, e := range entries {
		if e.Rel == w { // the bare wrapper dir entry itself disappears
			continue
		}
		rel := strings.TrimPrefix(e.Rel, prefix)
		if rel == e.Rel { // not under the wrapper (only possible for a sibling dir entry)
			continue
		}
		if rel == "" || rel == "." {
			continue
		}
		e.Rel = rel
		out = append(out, e)
	}
	return out
}

func modeFor(rel string, isDir bool) fs.FileMode {
	if isDir {
		return 0o755
	}
	if strings.HasPrefix(rel, "scripts/") {
		return 0o755
	}
	return 0o644
}

// sanitizeArchivePath turns a raw tar header name into a clean relative
// forward-slash path, or rejects it. Returns ("", nil) for entries that carry
// nothing ("" / "."). REJECTS (does not silently rewrite) anything that escapes
// the archive root — the strictest of the three original sanitisers.
func sanitizeArchivePath(name string) (string, error) {
	if name == "" {
		return "", nil
	}
	if strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("skillbundle: tar entry name contains NUL")
	}
	// POSIX tar names use forward slashes. A backslash is a Windows traversal
	// vector and the producer never emits one — reject rather than guess.
	if strings.ContainsRune(name, '\\') {
		return "", fmt.Errorf("skillbundle: tar entry %q contains a backslash", name)
	}
	if path.IsAbs(name) {
		return "", fmt.Errorf("skillbundle: tar entry %q is absolute", name)
	}
	clean := path.Clean(name)
	if clean == "." {
		return "", nil
	}
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("skillbundle: tar entry %q escapes the archive root", name)
	}
	// A Windows volume prefix (C:) in the first segment is a drive-absolute
	// escape that path.IsAbs does not catch.
	if vol := filepath.VolumeName(filepath.FromSlash(clean)); vol != "" {
		return "", fmt.Errorf("skillbundle: tar entry %q has a volume name", name)
	}
	return clean, nil
}
