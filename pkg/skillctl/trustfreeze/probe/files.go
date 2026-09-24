package probe

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

// FileReader reads host files for probes. Implementations restrict what can
// be read (SPEC-0467 R7, TF02-AC6).
type FileReader interface {
	ReadFile(name string) ([]byte, error)
}

// File reader errors. Errors also wrap fs.ErrNotExist or fs.ErrPermission
// when the OS reported those, so probes can classify them.
var (
	ErrOutsideRoots   = errors.New("probe: path is outside the allowed roots")
	ErrNotRegularFile = errors.New("probe: not a regular file")
)

// RootedFileReader reads only files at or below its allowed roots. The
// requested path must be absolute and lie under a root; after resolving
// symlinks the target must still lie under a root, so a symlink cannot lead
// out of the allowed set. Files larger than MaxBytes are refused (not
// truncated).
type RootedFileReader struct {
	roots    []string
	maxBytes int64
}

// NewRootedFileReader returns a reader for roots (absolute paths of files or
// directories; others are ignored). maxBytes <= 0 means DefaultMaxFileBytes.
func NewRootedFileReader(roots []string, maxBytes int64) *RootedFileReader {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxFileBytes
	}
	r := &RootedFileReader{maxBytes: maxBytes}
	seen := map[string]bool{}
	add := func(p string) {
		if p != "" && !seen[p] {
			seen[p] = true
			r.roots = append(r.roots, p)
		}
	}
	for _, root := range roots {
		if !filepath.IsAbs(root) {
			continue
		}
		clean := filepath.Clean(root)
		add(clean)
		// Accept the resolved form of a root too: on macOS /etc is a
		// symlink to /private/etc.
		if resolved, err := filepath.EvalSymlinks(clean); err == nil {
			add(resolved)
		}
	}
	return r
}

// Roots returns the allowed roots, resolved forms included.
func (r *RootedFileReader) Roots() []string { return append([]string(nil), r.roots...) }

// ReadFile reads name. See RootedFileReader.
func (r *RootedFileReader) ReadFile(name string) ([]byte, error) {
	if !filepath.IsAbs(name) || strings.ContainsRune(name, 0) {
		return nil, fmt.Errorf("%w: %q is not an absolute path", ErrOutsideRoots, name)
	}
	clean := filepath.Clean(name)
	if !r.allowed(clean) {
		return nil, fmt.Errorf("%w: %q", ErrOutsideRoots, name)
	}
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return nil, err
	}
	if !r.allowed(resolved) {
		return nil, fmt.Errorf("%w: %q resolves outside the allowed roots", ErrOutsideRoots, name)
	}
	// openRegularFile refuses a FIFO or device without blocking on it, and a
	// final symlink swapped in since EvalSymlinks.
	f, err := openRegularFile(resolved)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, r.maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > r.maxBytes {
		return nil, fmt.Errorf("%w: %q is larger than %d bytes", ErrLimitExceeded, name, r.maxBytes)
	}
	return b, nil
}

func (r *RootedFileReader) allowed(p string) bool {
	for _, root := range r.roots {
		if p == root {
			return true
		}
		prefix := root
		if !strings.HasSuffix(prefix, string(filepath.Separator)) {
			prefix += string(filepath.Separator)
		}
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}
