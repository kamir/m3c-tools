package trustfreeze

import (
	"errors"
	"fmt"
	"path"
	"strings"
)

// ErrBadPath is wrapped by every CanonicalPath rejection.
var ErrBadPath = errors.New("trustfreeze: bad bundle path")

// maxSegmentLen is the longest segment accepted (a common file-name limit on
// all three platforms).
const maxSegmentLen = 255

// CanonicalPath returns the canonical bundle-relative form of p (SPEC-0466
// TF01-AC5): "\" becomes "/", and the result equals path.Clean of
// itself.
//
// Rejected: empty paths, NUL, absolute paths ("/x"), UNC paths ("//x" or
// "\\x"), drive letters ("C:"), any "." or ".." segment, empty segments
// ("a//b"), and a trailing slash.
//
// Also rejected, so that a bundle means the same thing on Linux, macOS and
// Windows: any character outside ASCII letters, digits and "._-+@=," (this
// excludes ":" for NTFS alternate data streams, "~" for 8.3 short-name
// aliases, spaces, and every non-ASCII character, which avoids Unicode
// normalization and case-folding differences between file systems), segments
// that end in "." (Windows strips trailing dots), Windows device names such as
// "CON" or "nul.txt", and segments longer than 255 bytes.
func CanonicalPath(p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("%w: empty path", ErrBadPath)
	}
	if strings.ContainsRune(p, 0) {
		return "", fmt.Errorf("%w: %q contains NUL", ErrBadPath, p)
	}
	s := strings.ReplaceAll(p, `\`, "/")
	switch {
	case strings.HasPrefix(s, "//"):
		return "", fmt.Errorf("%w: %q is a UNC path", ErrBadPath, p)
	case strings.HasPrefix(s, "/"):
		return "", fmt.Errorf("%w: %q is absolute", ErrBadPath, p)
	case len(s) >= 2 && isASCIILetter(s[0]) && s[1] == ':':
		return "", fmt.Errorf("%w: %q has a drive letter", ErrBadPath, p)
	case strings.HasSuffix(s, "/"):
		return "", fmt.Errorf("%w: %q has a trailing slash", ErrBadPath, p)
	}
	for _, seg := range strings.Split(s, "/") {
		if err := checkSegment(seg); err != nil {
			return "", fmt.Errorf("%w: %q: %s", ErrBadPath, p, err.Error())
		}
	}
	if path.Clean(s) != s {
		return "", fmt.Errorf("%w: %q is not clean", ErrBadPath, p)
	}
	return s, nil
}

// PathFoldKey returns the key under which two canonical paths collide on a
// case-insensitive file system (Windows, default macOS). Canonical paths are
// ASCII, so ASCII lowercasing is the complete fold.
func PathFoldKey(p string) string {
	b := []byte(p)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

func checkSegment(seg string) error {
	switch seg {
	case "":
		return errors.New("empty segment")
	case ".", "..":
		return fmt.Errorf("%q segment", seg)
	}
	if len(seg) > maxSegmentLen {
		return fmt.Errorf("segment longer than %d bytes", maxSegmentLen)
	}
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		if !isPathChar(c) {
			if c == ':' {
				return errors.New("contains ':'")
			}
			return fmt.Errorf("character %q is not allowed", c)
		}
	}
	if strings.HasSuffix(seg, ".") {
		return fmt.Errorf("segment %q ends in '.'", seg)
	}
	if isWindowsDeviceName(seg) {
		return fmt.Errorf("segment %q is a Windows device name", seg)
	}
	return nil
}

func isASCIILetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

func isPathChar(c byte) bool {
	switch {
	case isASCIILetter(c), c >= '0' && c <= '9':
		return true
	}
	switch c {
	case '.', '_', '-', '+', '@', '=', ',':
		return true
	}
	return false
}

// isDriveSegment reports whether seg starts with a drive letter and a colon.
func isDriveSegment(seg string) bool {
	return len(seg) >= 2 && isASCIILetter(seg[0]) && seg[1] == ':'
}

func isWindowsDeviceName(seg string) bool {
	base, _, _ := strings.Cut(seg, ".")
	switch PathFoldKey(base) {
	case "con", "prn", "aux", "nul":
		return true
	}
	if len(base) == 4 {
		prefix := PathFoldKey(base[:3])
		if (prefix == "com" || prefix == "lpt") && base[3] >= '0' && base[3] <= '9' {
			return true
		}
	}
	return false
}

// dirCaseConflict records the directory prefixes of the canonical path p in
// seen (keyed by PathFoldKey) and reports a prefix that folds equal to one
// recorded earlier but differs in bytes. "state/a.json" and "State/b.json"
// land in one directory on a case-insensitive filesystem (Windows, macOS)
// and in two on Linux, so a verdict over such a bundle would depend on the
// verifying OS.
func dirCaseConflict(seen map[string]string, p string) (prev, dir string, conflict bool) {
	for i := 0; i < len(p); i++ {
		if p[i] != '/' {
			continue
		}
		d := p[:i]
		k := PathFoldKey(d)
		if old, ok := seen[k]; ok {
			if old != d {
				return old, d, true
			}
			continue
		}
		seen[k] = d
	}
	return "", "", false
}
