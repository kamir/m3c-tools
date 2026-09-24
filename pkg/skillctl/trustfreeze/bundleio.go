package trustfreeze

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/redact"
)

// Writer errors.
var (
	ErrTargetNotEmpty = errors.New("trustfreeze: output target exists and is not empty")
	ErrUnsafeTarget   = errors.New("trustfreeze: output target is not allowed")
	ErrReservedPath   = errors.New("trustfreeze: path is reserved or not writable through this method")
	ErrWriterClosed   = errors.New("trustfreeze: writer already finalized or aborted")
	ErrBadCapture     = errors.New("trustfreeze: capture.json is not valid")
	// ErrInconsistentCapture: capture.json, probes/<probe-id>.json and
	// state/device.json of one bundle contradict each other.
	ErrInconsistentCapture = errors.New("trustfreeze: capture documents contradict each other")
)

// WriterOptions configures NewWriter.
type WriterOptions struct {
	// Kind of the bundle being written.
	Kind Kind
	// Force allows replacing an existing bundle directory, but only one that
	// passes VerifyDir as a trust-freeze bundle of the same kind (every file
	// manifested and intact), and never a baseline (a baseline is never
	// overwritten, SPEC-0470 TF05-R6).
	Force bool
	// HomeRoot is the user home directory (see pkg/skillctl/homeroot). The
	// home root and every ancestor of it are refused as targets. Empty skips
	// that check; filesystem and volume roots are always refused.
	HomeRoot string
}

// Writer writes one bundle. Files go into a sibling staging directory of the
// target; Finalize writes manifest.json last, verifies the staged bundle with
// VerifyDir and renames it into place. Until then the target is untouched.
// A process that dies before Finalize leaves only a ".tf-staging-*" sibling.
//
// Raw evidence can only be written as redact.Redacted (WriteEvidence). JSON
// documents go through MarshalFile (WriteJSON). Paths must already be
// canonical; the writer never rewrites a path. manifest.json and everything
// under signatures/ are reserved; approval.json is writable only for a
// baseline.
type Writer struct {
	target  string
	parent  string
	staging string
	opts    WriterOptions
	written map[string]string
	dirs    map[string]string
	closed  bool
}

type targetState int

const (
	targetAbsent targetState = iota
	targetEmpty
	targetReplaceable
)

// NewWriter validates the target and creates the staging directory next to
// it. The parent directory of target must exist.
func NewWriter(target string, opts WriterOptions) (*Writer, error) {
	if !opts.Kind.Valid() {
		return nil, fmt.Errorf("%w: %q", ErrUnknownKind, string(opts.Kind))
	}
	if strings.TrimSpace(target) == "" {
		return nil, fmt.Errorf("%w: empty target", ErrUnsafeTarget)
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		return nil, err
	}
	abs = filepath.Clean(abs)
	if err := checkTargetLocation(abs, opts.HomeRoot); err != nil {
		return nil, err
	}
	if err := checkNotInsideBundle(abs); err != nil {
		return nil, err
	}
	if _, err := inspectTarget(abs, opts); err != nil {
		return nil, err
	}
	parent := filepath.Dir(abs)
	pi, err := os.Stat(parent)
	if err != nil {
		return nil, fmt.Errorf("output parent directory: %w", err)
	}
	if !pi.IsDir() {
		return nil, fmt.Errorf("%w: parent %q is not a directory", ErrUnsafeTarget, parent)
	}
	staging, err := os.MkdirTemp(parent, ".tf-staging-")
	if err != nil {
		return nil, err
	}
	return &Writer{
		target:  abs,
		parent:  parent,
		staging: staging,
		opts:    opts,
		written: map[string]string{},
		dirs:    map[string]string{},
	}, nil
}

// Kind returns the kind of the bundle being written.
func (w *Writer) Kind() Kind { return w.opts.Kind }

// Target returns the absolute target directory.
func (w *Writer) Target() string { return w.target }

// WriteJSON writes v in canonical file form (MarshalFile) at rel.
func (w *Writer) WriteJSON(rel string, v any) error {
	if err := w.checkWritePath(rel, false); err != nil {
		return err
	}
	b, err := MarshalFile(v)
	if err != nil {
		return fmt.Errorf("%s: %w", rel, err)
	}
	return w.writeStaged(rel, b)
}

// WriteEvidence writes redacted raw evidence at rel, which must have the form
// evidence/<probe-id>/<name>. It returns the reference to record in the
// probe result.
func (w *Writer) WriteEvidence(rel string, ev redact.Redacted) (EvidenceRef, error) {
	if err := w.checkWritePath(rel, true); err != nil {
		return EvidenceRef{}, err
	}
	b := ev.Bytes()
	if err := w.writeStaged(rel, b); err != nil {
		return EvidenceRef{}, err
	}
	return EvidenceRef{Path: rel, Size: int64(len(b)), SHA256: SHA256Hex(b)}, nil
}

// CopyManifestedFile copies the manifested file rel of the bundle at srcDir
// byte for byte into this bundle at the same path. The bytes are checked
// against src (size and SHA-256) while copying, so only content that another
// bundle already persisted and manifested can enter this way. It exists for
// the baseline path (SPEC-0470 TF05-R2); evidence files may be copied because they
// were written as redact.Redacted in the source bundle.
func (w *Writer) CopyManifestedFile(srcDir string, src Manifest, rel string) error {
	if err := w.checkWritePath(rel, strings.HasPrefix(rel, EvidenceDir+"/")); err != nil {
		return err
	}
	b, err := ReadManifestedFile(srcDir, src, rel)
	if err != nil {
		return err
	}
	return w.writeStaged(rel, b)
}

// Finalize builds the manifest from the staged files, writes manifest.json
// last, verifies the staged bundle and renames it into place. A baseline
// cannot be finalized this way; it needs FinalizeSigned.
func (w *Writer) Finalize(h ManifestHeader) (Manifest, error) {
	if w.opts.Kind == KindBaseline {
		return Manifest{}, fmt.Errorf("%w: a baseline must be finalized with FinalizeSigned", ErrReservedPath)
	}
	return w.finalize(h, nil)
}

// FinalizeSigned is Finalize for a baseline: after manifest.json it calls sign
// with the final manifest and writes the returned document in canonical file
// form at signatures/manifest.ed25519.json, then verifies and renames. Only
// the seal package is expected to call it.
func (w *Writer) FinalizeSigned(h ManifestHeader, sign func(Manifest) (any, error)) (Manifest, error) {
	if w.opts.Kind != KindBaseline {
		return Manifest{}, fmt.Errorf("%w: only a baseline carries a signature", ErrReservedPath)
	}
	if sign == nil {
		return Manifest{}, errors.New("trustfreeze: FinalizeSigned needs a sign function")
	}
	return w.finalize(h, sign)
}

// Abort removes the staging directory. It is safe to call more than once and
// after Finalize.
func (w *Writer) Abort() error {
	if w.closed {
		return nil
	}
	w.closed = true
	return os.RemoveAll(w.staging)
}

func (w *Writer) finalize(h ManifestHeader, sign func(Manifest) (any, error)) (m Manifest, err error) {
	if w.closed {
		return Manifest{}, ErrWriterClosed
	}
	defer func() {
		if err != nil {
			if rmErr := os.RemoveAll(w.staging); rmErr != nil {
				err = errors.Join(err, rmErr)
			}
		}
		w.closed = true
	}()
	if h.Kind == "" {
		h.Kind = w.opts.Kind
	}
	if h.Kind != w.opts.Kind {
		return Manifest{}, fmt.Errorf("%w: header kind %q, writer kind %q", ErrManifestInvalid, h.Kind, w.opts.Kind)
	}
	m, err = BuildManifest(w.staging, h)
	if err != nil {
		return Manifest{}, err
	}
	if w.opts.Kind == KindCapture || w.opts.Kind == KindBaseline {
		b, err := ReadManifestedFile(w.staging, m, CaptureFile)
		if err != nil {
			return Manifest{}, fmt.Errorf("%w: %w", ErrBadCapture, err)
		}
		if _, err := ParseCaptureDoc(b, m); err != nil {
			return Manifest{}, err
		}
	}
	mb, err := MarshalFile(m)
	if err != nil {
		return Manifest{}, err
	}
	if err := writeFileExcl(w.staging, ManifestFile, mb); err != nil {
		return Manifest{}, err
	}
	if sign != nil {
		doc, err := sign(m)
		if err != nil {
			return Manifest{}, fmt.Errorf("sign: %w", err)
		}
		sb, err := MarshalFile(doc)
		if err != nil {
			return Manifest{}, fmt.Errorf("signature document: %w", err)
		}
		if err := writeFileExcl(w.staging, SignatureFile, sb); err != nil {
			return Manifest{}, err
		}
	}
	if res := VerifyDir(w.staging); !res.OK {
		return Manifest{}, fmt.Errorf("staged bundle failed verification: %w", res.Err())
	}
	if err := w.commit(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// commit renames the staging directory into place, re-checking the target.
func (w *Writer) commit() error {
	// The target may have changed since NewWriter: check its location again
	// right before anything is renamed or removed.
	if err := checkTargetLocation(w.target, w.opts.HomeRoot); err != nil {
		return err
	}
	if err := checkNotInsideBundle(w.target); err != nil {
		return err
	}
	state, err := inspectTarget(w.target, w.opts)
	if err != nil {
		return err
	}
	switch state {
	case targetAbsent:
		return os.Rename(w.staging, w.target)
	case targetEmpty:
		// os.Remove only removes an empty directory, so this cannot delete content.
		if err := os.Remove(w.target); err != nil {
			return err
		}
		return os.Rename(w.staging, w.target)
	case targetReplaceable:
		old, err := os.MkdirTemp(w.parent, ".tf-replaced-")
		if err != nil {
			return err
		}
		if err := os.Remove(old); err != nil {
			return err
		}
		if err := os.Rename(w.target, old); err != nil {
			return err
		}
		if err := os.Rename(w.staging, w.target); err != nil {
			if back := os.Rename(old, w.target); back != nil {
				return errors.Join(err, fmt.Errorf("restore previous bundle from %s: %w", old, back))
			}
			return err
		}
		return os.RemoveAll(old)
	}
	return fmt.Errorf("%w: unexpected target state", ErrUnsafeTarget)
}

func (w *Writer) checkWritePath(rel string, evidence bool) error {
	if w.closed {
		return ErrWriterClosed
	}
	c, err := CanonicalPath(rel)
	if err != nil {
		return err
	}
	if c != rel {
		return fmt.Errorf("%w: %q is not canonical (want %q)", ErrBadPath, rel, c)
	}
	switch {
	case rel == ManifestFile, rel == SignaturesDir, strings.HasPrefix(rel, SignaturesDir+"/"):
		return fmt.Errorf("%w: %s", ErrReservedPath, rel)
	case rel == ApprovalFile && w.opts.Kind != KindBaseline:
		return fmt.Errorf("%w: a %s bundle must not contain %s", ErrReservedPath, w.opts.Kind, rel)
	}
	isEvidence := rel == EvidenceDir || strings.HasPrefix(rel, EvidenceDir+"/")
	if evidence {
		segs := strings.Split(rel, "/")
		if len(segs) != 3 || segs[0] != EvidenceDir {
			return fmt.Errorf("%w: evidence path %q must be %s/<probe-id>/<name>", ErrReservedPath, rel, EvidenceDir)
		}
		if err := ValidateProbeID(segs[1]); err != nil {
			return err
		}
	} else if isEvidence {
		return fmt.Errorf("%w: %s is writable only as redacted evidence", ErrReservedPath, rel)
	}
	return nil
}

func (w *Writer) writeStaged(rel string, b []byte) error {
	key := PathFoldKey(rel)
	if prev, dup := w.written[key]; dup {
		return fmt.Errorf("%w: %q collides with already written %q", ErrBadPath, rel, prev)
	}
	if prev, dir, bad := dirCaseConflict(w.dirs, rel); bad {
		return fmt.Errorf("%w: directory %q of %q collides with %q by letter case", ErrBadPath, dir, rel, prev)
	}
	if err := writeFileExcl(w.staging, rel, b); err != nil {
		return err
	}
	w.written[key] = rel
	return nil
}

// writeFileExcl creates dir/rel (and its parents, 0700) with mode 0600,
// refusing to overwrite, and syncs it.
func writeFileExcl(dir, rel string, b []byte) error {
	full := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		return err
	}
	// #nosec G304 -- rel ist bereits kanonisiert (CanonicalPath: relativ, kein
	// .., keine absoluten Pfade, kein Laufwerk), und O_EXCL verhindert, dass
	// eine vorhandene Datei ueberschrieben wird. Der Baum darunter gehoert dem
	// gerade entstehenden Bundle.
	f, err := os.OpenFile(full, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		return errors.Join(err, f.Close())
	}
	if err := f.Sync(); err != nil {
		return errors.Join(err, f.Close())
	}
	return f.Close()
}

// checkTargetLocation refuses filesystem and volume roots, and the home root
// and its ancestors.
func checkTargetLocation(abs, homeRoot string) error {
	if filepath.Dir(abs) == abs {
		return fmt.Errorf("%w: %q is a filesystem or volume root", ErrUnsafeTarget, abs)
	}
	if v := filepath.VolumeName(abs); v != "" && (abs == v || abs == v+string(filepath.Separator)) {
		return fmt.Errorf("%w: %q is a volume root", ErrUnsafeTarget, abs)
	}
	if homeRoot == "" {
		return checkTargetIdentity(abs, "")
	}
	home, err := filepath.Abs(homeRoot)
	if err != nil {
		return err
	}
	a, h := filepath.Clean(abs), filepath.Clean(home)
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		a, h = strings.ToLower(a), strings.ToLower(h)
	}
	rel, err := filepath.Rel(a, h)
	if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%w: %q is the home root or one of its ancestors", ErrUnsafeTarget, abs)
	}
	return checkTargetIdentity(abs, home)
}

// checkTargetIdentity compares file identity, not spelling: an existing
// target that is the home root or one of its ancestors is refused however it
// is reached (a symlinked parent, the macOS /System/Volumes/Data firmlink, a
// Windows junction, an 8.3 alias or a \\?\ prefix). It also refuses a
// mount point and the platform's extra volume roots (targetguard_*.go). A
// target that does not exist yet cannot be any of these.
func checkTargetIdentity(abs, home string) error {
	ti, err := os.Stat(abs)
	if err != nil {
		return nil
	}
	if home != "" {
		for dir := filepath.Clean(home); ; dir = filepath.Dir(dir) {
			if di, err := os.Stat(dir); err == nil && os.SameFile(ti, di) {
				return fmt.Errorf("%w: %q is the home root or one of its ancestors", ErrUnsafeTarget, abs)
			}
			if filepath.Dir(dir) == dir {
				break
			}
		}
	}
	return checkVolumeTarget(abs, ti)
}

// checkNotInsideBundle refuses a target inside an existing trust-freeze
// bundle (SPEC-0470 TF05-R2): the bundle would then carry unlisted files and
// fail its own verification for good. This covers every writer, so capture,
// diff and baseline approve all refuse it.
func checkNotInsideBundle(abs string) error {
	dir, err := EnclosingBundle(abs)
	if err != nil {
		return fmt.Errorf("%w: cannot check whether %q lies inside a trust-freeze bundle: %w", ErrUnsafeTarget, abs, err)
	}
	if dir != "" {
		return fmt.Errorf("%w: %q lies inside the trust-freeze bundle %q, which would then fail its own verification", ErrUnsafeTarget, abs, dir)
	}
	return nil
}

// EnclosingBundle returns the nearest directory above path (path itself
// excluded) that holds a trust-freeze manifest.json, one whose schema_version
// is trust-freeze/manifest/v1, or "" when there is none. It checks the
// ancestors as spelled and, when the parent exists, the ancestors of the
// resolved parent, so a symlinked parent cannot hide a bundle. An ancestor
// whose manifest.json exists but cannot be inspected is an error (fail
// closed). A manifest.json of another tool does not count.
func EnclosingBundle(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	starts := []string{filepath.Dir(filepath.Clean(abs))}
	if resolved, err := filepath.EvalSymlinks(starts[0]); err == nil && resolved != starts[0] {
		starts = append(starts, resolved)
	}
	for _, start := range starts {
		for dir := start; ; dir = filepath.Dir(dir) {
			ok, err := holdsBundleManifest(dir)
			if err != nil {
				return "", err
			}
			if ok {
				return dir, nil
			}
			if filepath.Dir(dir) == dir {
				break
			}
		}
	}
	return "", nil
}

// holdsBundleManifest reports whether dir holds a regular manifest.json with
// the trust-freeze manifest schema id.
func holdsBundleManifest(dir string) (bool, error) {
	fi, err := os.Lstat(filepath.Join(dir, ManifestFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		if di, derr := os.Stat(dir); derr != nil || !di.IsDir() {
			return false, nil // not a directory (yet): nothing to hold
		}
		return false, err
	}
	if !fi.Mode().IsRegular() {
		return false, nil
	}
	b, err := readRegularCapped(dir, ManifestFile, maxManifestBytes)
	if err != nil {
		return false, err
	}
	var env struct {
		SchemaVersion string `json:"schema_version"`
	}
	if json.Unmarshal(b, &env) != nil {
		return false, nil
	}
	return env.SchemaVersion == SchemaManifest, nil
}

// inspectTarget classifies the target directory.
func inspectTarget(abs string, opts WriterOptions) (targetState, error) {
	fi, err := os.Lstat(abs)
	if errors.Is(err, os.ErrNotExist) {
		return targetAbsent, nil
	}
	if err != nil {
		return 0, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return 0, fmt.Errorf("%w: %q is a symlink", ErrUnsafeTarget, abs)
	}
	if !fi.IsDir() {
		return 0, fmt.Errorf("%w: %q is not a directory", ErrTargetNotEmpty, abs)
	}
	empty, err := dirIsEmpty(abs)
	if err != nil {
		return 0, err
	}
	if empty {
		return targetEmpty, nil
	}
	if !opts.Force {
		return 0, fmt.Errorf("%w: %q", ErrTargetNotEmpty, abs)
	}
	mb, err := readRegularCapped(abs, ManifestFile, maxManifestBytes)
	if err != nil {
		return 0, fmt.Errorf("%w: --force replaces only a trust-freeze bundle; %q has no readable manifest.json", ErrTargetNotEmpty, abs)
	}
	var env struct {
		SchemaVersion string `json:"schema_version"`
		Kind          string `json:"kind"`
	}
	if err := json.Unmarshal(mb, &env); err != nil || env.SchemaVersion != SchemaManifest {
		return 0, fmt.Errorf("%w: --force replaces only a trust-freeze bundle; %q is not one", ErrTargetNotEmpty, abs)
	}
	if Kind(env.Kind) == KindBaseline {
		return 0, fmt.Errorf("%w: a baseline is never overwritten", ErrUnsafeTarget)
	}
	// A manifest.json alone does not make a bundle: it may be copied or
	// planted next to user files. Only a directory whose every file is
	// manifested and intact is replaced (and then removed), so --force can
	// never delete anything a trust-freeze writer did not produce.
	res := VerifyDir(abs)
	if !res.OK || res.Manifest == nil {
		return 0, fmt.Errorf("%w: --force replaces only a trust-freeze bundle that verifies; %q does not: %w", ErrTargetNotEmpty, abs, res.Err())
	}
	if res.Manifest.Kind != opts.Kind {
		return 0, fmt.Errorf("%w: --force replaces only a %s bundle; %q holds kind %q", ErrUnsafeTarget, opts.Kind, abs, res.Manifest.Kind)
	}
	return targetReplaceable, nil
}

func dirIsEmpty(dir string) (bool, error) {
	// #nosec G304 -- dir ist das vom Bediener genannte Ausgabeziel. Es wird
	// hier nur geoeffnet, um festzustellen, ob es leer ist.
	f, err := os.Open(dir)
	if err != nil {
		return false, err
	}
	defer f.Close()
	_, err = f.Readdirnames(1)
	if errors.Is(err, io.EOF) {
		return true, nil
	}
	return false, err
}

// ReadManifestedFile reads the manifested file rel of the bundle at dir and
// checks its size and SHA-256 against m. It never follows a symlink.
func ReadManifestedFile(dir string, m Manifest, rel string) ([]byte, error) {
	var entry *FileEntry
	for i := range m.Files {
		if m.Files[i].Path == rel {
			entry = &m.Files[i]
			break
		}
	}
	if entry == nil {
		return nil, fmt.Errorf("%w: %s is not in the manifest", ErrIntegrity, rel)
	}
	if c, err := CanonicalPath(rel); err != nil || c != rel {
		return nil, fmt.Errorf("%w: %q is not a canonical path", ErrIntegrity, rel)
	}
	b, err := readRegularCapped(dir, rel, entry.Size)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIntegrity, err)
	}
	if int64(len(b)) != entry.Size {
		return nil, fmt.Errorf("%w: %s has size %d, manifest says %d", ErrIntegrity, rel, len(b), entry.Size)
	}
	if SHA256Hex(b) != entry.SHA256 {
		return nil, fmt.Errorf("%w: %s sha256 differs from the manifest", ErrIntegrity, rel)
	}
	return b, nil
}

// maxSignatureBytes caps signatures/manifest.ed25519.json.
const maxSignatureBytes = 1 << 20

// ReadSignatureFile reads signatures/manifest.ed25519.json of the bundle at
// dir. The file signs the manifest and is therefore not listed in it, so no
// manifest entry covers these bytes: the read refuses symlinks and non-regular
// files and caps the size, and the caller must check the content
// cryptographically before trusting any of it.
func ReadSignatureFile(dir string) ([]byte, error) {
	return readRegularCapped(dir, SignatureFile, maxSignatureBytes)
}

// ParseCaptureDoc decodes capture.json in canonical file form and checks it
// against the manifest it came with: schema id, kind "capture", tool, strict
// times, subject equal to the manifest subject, and a declared completeness
// that equals the recomputed one (ErrCompletenessMismatch otherwise).
func ParseCaptureDoc(b []byte, m Manifest) (CaptureDoc, error) {
	var doc CaptureDoc
	if err := UnmarshalCanonicalFile(b, &doc); err != nil {
		return CaptureDoc{}, fmt.Errorf("%w: %w", ErrBadCapture, err)
	}
	if err := CheckSchema(doc.SchemaVersion, SchemaCapture); err != nil {
		return CaptureDoc{}, fmt.Errorf("%w: %w", ErrBadCapture, err)
	}
	if doc.Kind != KindCapture {
		return CaptureDoc{}, fmt.Errorf("%w: kind %q, want %q", ErrBadCapture, doc.Kind, KindCapture)
	}
	if doc.Capture.Tool != CaptureTool {
		return CaptureDoc{}, fmt.Errorf("%w: tool %q, want %q", ErrBadCapture, doc.Capture.Tool, CaptureTool)
	}
	for _, ts := range []string{doc.Capture.StartedAt, doc.Capture.FinishedAt} {
		if _, err := ParseTime(ts); err != nil {
			return CaptureDoc{}, fmt.Errorf("%w: %w", ErrBadCapture, err)
		}
	}
	if doc.Subject != m.Subject {
		return CaptureDoc{}, fmt.Errorf("%w: subject %+v differs from manifest subject %+v", ErrBadCapture, doc.Subject, m.Subject)
	}
	if err := CheckCompleteness(doc); err != nil {
		return CaptureDoc{}, err
	}
	return doc, nil
}

// Bundle is a bundle directory that passed VerifyDir, with capture.json and
// state/device.json decoded. It carries integrity only: whether a baseline
// signature is valid and trusted is decided by the seal package.
type Bundle struct {
	Dir       string
	Manifest  Manifest
	Integrity IntegrityResult
	// Capture is capture.json; nil for a diff bundle.
	Capture *CaptureDoc
	// State is state/device.json; nil when the bundle does not contain it.
	State *StateDoc
	// Capabilities is state/capabilities.json; nil when the bundle does not
	// contain it, which means no resolver ran, not that the host grants
	// nothing (SPEC-0466 section 5.7).
	Capabilities *CapabilitiesDoc
}

// ReadBundle verifies dir with VerifyDir and refuses a bundle that fails
// (the returned Bundle then carries only Dir and Integrity, and the error
// wraps ErrIntegrity). It then decodes capture.json (ParseCaptureDoc, which
// recomputes completeness) and state/device.json when present, and for a
// capture or baseline checks that capture.json, the probe results and the
// device state agree (CheckCaptureConsistency).
func ReadBundle(dir string) (*Bundle, error) {
	res := VerifyDir(dir)
	b := &Bundle{Dir: dir, Integrity: res}
	if !res.OK || res.Manifest == nil {
		return b, res.Err()
	}
	b.Manifest = *res.Manifest
	if b.Manifest.Kind == KindCapture || b.Manifest.Kind == KindBaseline {
		raw, err := b.ReadFile(CaptureFile)
		if err != nil {
			return b, err
		}
		doc, err := ParseCaptureDoc(raw, b.Manifest)
		if err != nil {
			return b, err
		}
		b.Capture = &doc
	}
	if b.Has(StateDeviceFile) {
		var st StateDoc
		if err := b.ReadJSON(StateDeviceFile, &st); err != nil {
			return b, err
		}
		b.State = &st
	}
	if b.Has(StateCapabilitiesFile) {
		var caps CapabilitiesDoc
		if err := b.ReadJSON(StateCapabilitiesFile, &caps); err != nil {
			return b, err
		}
		b.Capabilities = &caps
	}
	if b.Capture != nil {
		if err := b.CheckCaptureConsistency(); err != nil {
			return b, err
		}
	}
	return b, nil
}

// CheckCaptureConsistency checks that the documents of a capture (also the
// copy inside a baseline) tell one story, so no reader trusts a summary that
// the evidence contradicts (SPEC-0466 TF01-AC6, section 5.6):
//
//   - the capture.json probes list equals the summary of the manifested
//     probes/<probe-id>.json results: one result per summary, same status and
//     reason, no result without a summary;
//   - completeness recomputed from those results equals the declared one;
//   - state/device.json equals the sorted union of the results'
//     normalized_state;
//   - every raw evidence reference names a manifested file of that size and
//     SHA-256.
//
// Errors wrap ErrInconsistentCapture (completeness: ErrCompletenessMismatch).
func (b *Bundle) CheckCaptureConsistency() error {
	if b.Capture == nil {
		return fmt.Errorf("%w: capture.json was not read", ErrInconsistentCapture)
	}
	doc := *b.Capture
	results, err := b.ReadProbeResults()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInconsistentCapture, err)
	}
	want := Summarize(results)
	for i := 0; i < len(want) || i < len(doc.Probes); i++ {
		switch {
		case i >= len(doc.Probes):
			return fmt.Errorf("%w: probes/%s.json has no entry in capture.json", ErrInconsistentCapture, want[i].ProbeID)
		case i >= len(want):
			return fmt.Errorf("%w: capture.json lists %s, but probes/%s.json is not in the bundle", ErrInconsistentCapture, doc.Probes[i].ProbeID, doc.Probes[i].ProbeID)
		case want[i] != doc.Probes[i]:
			return fmt.Errorf("%w: capture.json says %s is %s (reason %q), probes/%s.json says %s (reason %q)", ErrInconsistentCapture,
				doc.Probes[i].ProbeID, doc.Probes[i].Status, doc.Probes[i].Reason, want[i].ProbeID, want[i].Status, want[i].Reason)
		}
	}
	got, err := MarshalCanonical(doc.Completeness)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCompletenessMismatch, err)
	}
	recomputed, err := MarshalCanonical(ComputeCompleteness(doc.Completeness.Required, results))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCompletenessMismatch, err)
	}
	if !bytes.Equal(got, recomputed) {
		return fmt.Errorf("%w: %w: declared %s, recomputed from the probe results %s", ErrInconsistentCapture, ErrCompletenessMismatch, got, recomputed)
	}
	union := []Artifact{}
	for _, r := range results {
		union = append(union, r.NormalizedState...)
	}
	SortArtifacts(union)
	state := StateDoc{Artifacts: []Artifact{}}
	if b.State != nil && b.State.Artifacts != nil {
		state = *b.State
	}
	a, err := MarshalCanonical(StateDoc{Artifacts: union})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInconsistentCapture, err)
	}
	c, err := MarshalCanonical(state)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInconsistentCapture, err)
	}
	if !bytes.Equal(a, c) {
		return fmt.Errorf("%w: state/device.json differs from the normalized_state of the probe results", ErrInconsistentCapture)
	}
	entries := make(map[string]FileEntry, len(b.Manifest.Files))
	for _, f := range b.Manifest.Files {
		entries[f.Path] = f
	}
	for _, r := range results {
		for _, ref := range r.RawEvidence {
			e, ok := entries[ref.Path]
			if !ok || e.Size != ref.Size || e.SHA256 != ref.SHA256 {
				return fmt.Errorf("%w: probes/%s.json names evidence %s that is not a manifested file of that size and digest", ErrInconsistentCapture, r.ProbeID, ref.Path)
			}
		}
	}
	return nil
}

// Has reports whether rel is a manifested file of the bundle.
func (b *Bundle) Has(rel string) bool {
	for _, f := range b.Manifest.Files {
		if f.Path == rel {
			return true
		}
	}
	return false
}

// ReadFile reads a manifested file and re-checks it against the manifest, so
// a change after VerifyDir is detected.
func (b *Bundle) ReadFile(rel string) ([]byte, error) {
	return ReadManifestedFile(b.Dir, b.Manifest, rel)
}

// ReadJSON reads a manifested JSON file into v (UnmarshalCanonicalFile).
func (b *Bundle) ReadJSON(rel string, v any) error {
	raw, err := b.ReadFile(rel)
	if err != nil {
		return err
	}
	if err := UnmarshalCanonicalFile(raw, v); err != nil {
		return fmt.Errorf("%s: %w", rel, err)
	}
	return nil
}

// ReadProbeResults reads every manifested probes/<probe-id>.json, sorted by
// probe id, and checks that each file name matches its probe_id.
func (b *Bundle) ReadProbeResults() ([]ProbeResult, error) {
	var paths []string
	for _, f := range b.Manifest.Files {
		if strings.HasPrefix(f.Path, ProbesDir+"/") && strings.HasSuffix(f.Path, ".json") && strings.Count(f.Path, "/") == 1 {
			paths = append(paths, f.Path)
		}
	}
	sort.Strings(paths)
	out := make([]ProbeResult, 0, len(paths))
	for _, p := range paths {
		var r ProbeResult
		if err := b.ReadJSON(p, &r); err != nil {
			return nil, err
		}
		want, err := ProbeResultPath(r.ProbeID)
		if err != nil || want != p {
			return nil, fmt.Errorf("%w: %s holds probe_id %q", ErrIntegrity, p, r.ProbeID)
		}
		out = append(out, r)
	}
	return out, nil
}
