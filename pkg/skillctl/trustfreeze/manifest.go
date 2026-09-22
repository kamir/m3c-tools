package trustfreeze

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Manifest is manifest.json (SPEC-0466 R7). Files lists every persisted file of
// the bundle except manifest.json itself and the single signature file
// signatures/manifest.ed25519.json, sorted by path in byte order.
//
// ContentDigest = "sha256:" + hex(sha256(MarshalCanonical(m with
// ContentDigest set to ""))), so every other field of the manifest, the file
// list included, is covered. A signature over the content digest therefore
// covers every manifested byte.
type Manifest struct {
	SchemaVersion string       `json:"schema_version"`
	Kind          Kind         `json:"kind"`
	BundleID      string       `json:"bundle_id"`
	CreatedAt     string       `json:"created_at"`
	Subject       Subject      `json:"subject"`
	BundlePolicy  BundlePolicy `json:"bundle_policy"`
	Files         []FileEntry  `json:"files"`
	ContentDigest string       `json:"content_digest"`
}

// BundlePolicy is recorded in the manifest. Writers of this build always set
// RejectAdditions; VerifyDir reports every unlisted file as "extra" either way
// and leaves any relaxation to the trust policy of the caller.
type BundlePolicy struct {
	RejectAdditions bool `json:"reject_additions"`
}

// FileEntry is one manifested file. SHA256 is lowercase hex without prefix.
type FileEntry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// ManifestHeader carries the manifest fields that are not derived from the
// directory content.
type ManifestHeader struct {
	Kind      Kind
	BundleID  string
	CreatedAt time.Time
	Subject   Subject
}

// Manifest errors.
var (
	ErrManifestInvalid = errors.New("trustfreeze: invalid manifest")
	ErrBundleContent   = errors.New("trustfreeze: bundle directory cannot be manifested")
	errRootSymlink     = errors.New("bundle root is a symlink")
)

// maxManifestBytes caps how much of a manifest.json is read.
const maxManifestBytes = 64 << 20

// ComputeContentDigest returns the content digest of m. The ContentDigest field
// of m is ignored; a nil Files list is treated as empty.
func ComputeContentDigest(m Manifest) (string, error) {
	m.ContentDigest = ""
	if m.Files == nil {
		m.Files = []FileEntry{}
	}
	b, err := MarshalCanonical(m)
	if err != nil {
		return "", err
	}
	return Digest(b), nil
}

// ParseManifest decodes manifest.json strictly: canonical file form, known
// schema id, known kind, a files list present. It does not look at the disk;
// VerifyDir does.
func ParseManifest(b []byte) (Manifest, error) {
	var env struct {
		SchemaVersion string `json:"schema_version"`
		Kind          string `json:"kind"`
	}
	if err := json.Unmarshal(b, &env); err != nil {
		return Manifest{}, fmt.Errorf("%w: %w", ErrManifestInvalid, err)
	}
	if err := CheckSchema(env.SchemaVersion, SchemaManifest); err != nil {
		return Manifest{}, err
	}
	if _, err := ParseKind(env.Kind); err != nil {
		return Manifest{}, err
	}
	var m Manifest
	if err := UnmarshalCanonicalFile(b, &m); err != nil {
		return Manifest{}, fmt.Errorf("%w: %w", ErrManifestInvalid, err)
	}
	if m.Files == nil {
		return Manifest{}, fmt.Errorf("%w: files list missing", ErrManifestInvalid)
	}
	return m, nil
}

// BuildManifest walks dir without following symlinks and returns the manifest
// for its content under header h, content digest included. manifest.json and
// signatures/manifest.ed25519.json are skipped if present. A symlink, a
// non-regular file, a non-canonical name, a case-only duplicate or any other
// file under signatures/ (which is never manifested, SPEC-0470 section 4.4)
// is an error.
func BuildManifest(dir string, h ManifestHeader) (Manifest, error) {
	if !h.Kind.Valid() {
		return Manifest{}, fmt.Errorf("%w: %q", ErrUnknownKind, string(h.Kind))
	}
	if strings.TrimSpace(h.BundleID) == "" {
		return Manifest{}, fmt.Errorf("%w: empty bundle id", ErrManifestInvalid)
	}
	if h.CreatedAt.IsZero() {
		return Manifest{}, fmt.Errorf("%w: zero created_at", ErrManifestInvalid)
	}
	if h.Subject.ID == "" || h.Subject.OSFamily == "" {
		return Manifest{}, fmt.Errorf("%w: subject id and os_family are required", ErrManifestInvalid)
	}
	w, err := walkBundle(dir)
	if err != nil {
		return Manifest{}, err
	}
	if len(w.failures) > 0 {
		f := w.failures[0]
		return Manifest{}, fmt.Errorf("%w: %s %s: %s", ErrBundleContent, f.Reason, f.Path, f.Detail)
	}
	files := []FileEntry{}
	folded := map[string]string{}
	dirs := map[string]string{}
	for _, df := range w.files {
		if df.rel == ManifestFile || df.rel == SignatureFile {
			continue
		}
		if underSignatures(df.rel) {
			return Manifest{}, fmt.Errorf("%w: %s: only the signature file may lie under %s/, and it is never manifested", ErrBundleContent, df.rel, SignaturesDir)
		}
		if prev, dup := folded[PathFoldKey(df.rel)]; dup {
			return Manifest{}, fmt.Errorf("%w: %q and %q differ only by case", ErrBundleContent, prev, df.rel)
		}
		if prev, dir, bad := dirCaseConflict(dirs, df.rel); bad {
			return Manifest{}, fmt.Errorf("%w: directory %q collides with %q by letter case", ErrBundleContent, dir, prev)
		}
		folded[PathFoldKey(df.rel)] = df.rel
		size, sum, err := hashFile(dir, df)
		if err != nil {
			return Manifest{}, fmt.Errorf("%w: %w", ErrBundleContent, err)
		}
		files = append(files, FileEntry{Path: df.rel, Size: size, SHA256: sum})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	m := Manifest{
		SchemaVersion: SchemaManifest,
		Kind:          h.Kind,
		BundleID:      h.BundleID,
		CreatedAt:     FormatTime(h.CreatedAt),
		Subject:       h.Subject,
		BundlePolicy:  BundlePolicy{RejectAdditions: true},
		Files:         files,
	}
	d, err := ComputeContentDigest(m)
	if err != nil {
		return Manifest{}, err
	}
	m.ContentDigest = d
	return m, nil
}

// diskFile is one regular file found by walkBundle.
type diskFile struct {
	rel  string
	info fs.FileInfo
}

type walkResult struct {
	files    []diskFile
	dirs     []string
	failures []IntegrityFailure
}

// walkBundle lists dir without following symlinks. Symlinks, non-regular
// entries (devices, pipes, sockets, Windows reparse points reported as
// irregular) and non-canonical names become failures; a badly named or
// irregular directory is not descended into. The root itself must be a real
// directory; otherwise an error is returned.
func walkBundle(root string) (walkResult, error) {
	var res walkResult
	fi, err := os.Lstat(root)
	if err != nil {
		return res, err
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return res, fmt.Errorf("%w: %w: %q", ErrBundleContent, errRootSymlink, root)
	}
	if !fi.IsDir() {
		return res, fmt.Errorf("%w: bundle root %q is not a directory", ErrBundleContent, root)
	}
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
		if p == root {
			return walkErr
		}
		relOS, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel := filepath.ToSlash(relOS)
		if walkErr != nil {
			res.failures = append(res.failures, IntegrityFailure{Reason: IntegrityUnreadable, Path: rel, Detail: walkErr.Error()})
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		typ := d.Type()
		if typ&fs.ModeSymlink != 0 {
			res.failures = append(res.failures, IntegrityFailure{Reason: IntegritySymlink, Path: rel, Detail: "symlinks are not allowed in a bundle"})
			return nil
		}
		if typ&^fs.ModeDir != 0 {
			detail := "not a regular file or directory: " + typ.String()
			if typ&fs.ModeIrregular != 0 {
				// On Windows, reparse points other than symlinks and mount
				// points (cloud-sync placeholders among them) read as
				// irregular; reading one can trigger a download.
				detail += " (on Windows for example a reparse point such as a cloud-sync placeholder: copy the bundle to a local folder)"
			}
			res.failures = append(res.failures, IntegrityFailure{Reason: IntegrityNotRegular, Path: rel, Detail: detail})
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if c, err := CanonicalPath(rel); err != nil || c != rel {
			detail := "name is not canonical"
			if err != nil {
				detail = err.Error()
			}
			res.failures = append(res.failures, IntegrityFailure{Reason: IntegrityBadPath, Path: rel, Detail: detail})
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			res.dirs = append(res.dirs, rel)
			return nil
		}
		info, err := d.Info()
		if err != nil {
			res.failures = append(res.failures, IntegrityFailure{Reason: IntegrityUnreadable, Path: rel, Detail: err.Error()})
			return nil
		}
		res.files = append(res.files, diskFile{rel: rel, info: info})
		return nil
	})
	return res, err
}

// openRegular opens dir/rel and checks that the opened file is the same
// regular file the walk saw, which closes the window for swapping in a symlink
// between walk and open.
func openRegular(dir string, df diskFile) (*os.File, error) {
	f, err := os.Open(filepath.Join(dir, filepath.FromSlash(df.rel)))
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		return nil, errors.Join(err, f.Close())
	}
	if !fi.Mode().IsRegular() || (df.info != nil && !os.SameFile(fi, df.info)) {
		return nil, errors.Join(fmt.Errorf("%s changed while reading", df.rel), f.Close())
	}
	return f, nil
}

// hashFile returns the byte count and lowercase hex SHA-256 of dir/rel.
func hashFile(dir string, df diskFile) (int64, string, error) {
	f, err := openRegular(dir, df)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return 0, "", err
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

// lstatRegular returns the diskFile for dir/rel when it is a regular file and
// not a symlink.
func lstatRegular(dir, rel string) (diskFile, error) {
	fi, err := os.Lstat(filepath.Join(dir, filepath.FromSlash(rel)))
	if err != nil {
		return diskFile{}, err
	}
	if !fi.Mode().IsRegular() {
		return diskFile{}, fmt.Errorf("%w: %s is not a regular file (%s)", ErrBundleContent, rel, fi.Mode().Type())
	}
	return diskFile{rel: rel, info: fi}, nil
}

// readRegularCapped reads dir/rel (no symlink, regular file) up to limit bytes.
func readRegularCapped(dir, rel string, limit int64) ([]byte, error) {
	df, err := lstatRegular(dir, rel)
	if err != nil {
		return nil, err
	}
	f, err := openRegular(dir, df)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%w: %s is larger than %d bytes", ErrBundleContent, rel, limit)
	}
	return b, nil
}

func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
