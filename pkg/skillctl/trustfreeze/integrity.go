package trustfreeze

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// IntegrityReason is the typed reason of one integrity failure.
type IntegrityReason string

// Integrity failure reasons.
const (
	// IntegrityMissing: a manifested file is not on disk (or manifest.json is absent).
	IntegrityMissing IntegrityReason = "missing"
	// IntegrityExtra: a file or empty directory on disk is not in the manifest.
	IntegrityExtra IntegrityReason = "extra"
	// IntegritySizeMismatch: a manifested file has a different size.
	IntegritySizeMismatch IntegrityReason = "size_mismatch"
	// IntegrityDigestMismatch: a manifested file has a different SHA-256.
	IntegrityDigestMismatch IntegrityReason = "digest_mismatch"
	// IntegrityDuplicatePath: the manifest lists a path twice, also when the
	// two entries differ only by case.
	IntegrityDuplicatePath IntegrityReason = "duplicate_path"
	// IntegrityBadPath: a manifest entry or an on-disk name is not a canonical
	// bundle path, or a manifest entry names a reserved file.
	IntegrityBadPath IntegrityReason = "bad_path"
	// IntegritySymlink: a symlink inside the bundle (or the root is one).
	IntegritySymlink IntegrityReason = "symlink"
	// IntegrityContentDigestMismatch: the recomputed content digest differs
	// from the declared one.
	IntegrityContentDigestMismatch IntegrityReason = "content_digest_mismatch"
	// IntegrityUnknownKind: the manifest kind is not capture, baseline or diff.
	IntegrityUnknownKind IntegrityReason = "unknown_kind"
	// IntegrityUnknownSchema: the manifest schema id is not known.
	IntegrityUnknownSchema IntegrityReason = "unknown_schema"
	// IntegrityKindLayoutViolation: the files present contradict the kind,
	// for example a capture that contains approval.json or a signature.
	IntegrityKindLayoutViolation IntegrityReason = "kind_layout_violation"
	// IntegrityManifestInvalid: manifest.json is not valid, not in canonical
	// file form, unsorted, or carries malformed sizes or digests.
	IntegrityManifestInvalid IntegrityReason = "manifest_invalid"
	// IntegrityNotRegular: a device, pipe, socket or irregular entry.
	IntegrityNotRegular IntegrityReason = "not_regular"
	// IntegrityUnreadable: an entry (or the root) could not be read.
	IntegrityUnreadable IntegrityReason = "unreadable"
)

// IntegrityFailure is one finding of VerifyDir.
type IntegrityFailure struct {
	Reason IntegrityReason `json:"reason"`
	Path   string          `json:"path,omitempty"`
	Detail string          `json:"detail,omitempty"`
}

// IntegrityResult is the structured outcome of VerifyDir. OK is true exactly
// when Failures is empty. Manifest is set whenever manifest.json could be
// decoded, also when other checks failed; callers must check OK before they
// rely on it.
type IntegrityResult struct {
	OK            bool               `json:"ok"`
	Kind          Kind               `json:"kind,omitempty"`
	BundleID      string             `json:"bundle_id,omitempty"`
	ContentDigest string             `json:"content_digest,omitempty"`
	Failures      []IntegrityFailure `json:"failures"`
	Manifest      *Manifest          `json:"-"`
}

// ErrIntegrity is wrapped by IntegrityResult.Err and by readers that refuse an
// unverified bundle.
var ErrIntegrity = errors.New("trustfreeze: bundle integrity check failed")

// Has reports whether the result contains a failure with the given reason.
func (r IntegrityResult) Has(reason IntegrityReason) bool {
	for _, f := range r.Failures {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

// Err returns nil for an OK result and otherwise an error wrapping
// ErrIntegrity that names the first failure and the failure count.
func (r IntegrityResult) Err() error {
	if r.OK {
		return nil
	}
	if len(r.Failures) == 0 {
		return ErrIntegrity
	}
	f := r.Failures[0]
	return fmt.Errorf("%w: %d failure(s), first: %s %s %s", ErrIntegrity, len(r.Failures), f.Reason, f.Path, f.Detail)
}

// VerifyDir checks a bundle directory against its manifest.json (SPEC-0466
// R7, TF01-AC3, TF01-AC4; SPEC-0470 TF05-R1). It walks the directory without following
// symlinks, recomputes size and SHA-256 of every file, and reports missing,
// extra (including extra files under signatures/), mismatched, duplicate and
// badly named entries, symlinks, kind layout violations, and finally the
// recomputed content digest. Paths from the manifest are never opened
// directly; only names found by the walk are, so a "../" entry cannot escape
// the bundle.
//
// VerifyDir checks integrity only. Whether a baseline signature is valid and
// trusted is decided by the seal package.
func VerifyDir(dir string) (res IntegrityResult) {
	add := func(reason IntegrityReason, path, detail string) {
		res.Failures = append(res.Failures, IntegrityFailure{Reason: reason, Path: path, Detail: detail})
	}
	defer func() {
		sortFailures(res.Failures)
		if res.Failures == nil {
			res.Failures = []IntegrityFailure{}
		}
		res.OK = len(res.Failures) == 0
	}()

	walk, err := walkBundle(dir)
	if err != nil {
		reason := IntegrityUnreadable
		if errors.Is(err, errRootSymlink) {
			reason = IntegritySymlink
		}
		add(reason, ".", err.Error())
		return res
	}
	// Every early return below still reports what the walk found.
	withWalk := func() IntegrityResult {
		res.Failures = append(res.Failures, walk.failures...)
		return res
	}

	present := make(map[string]diskFile, len(walk.files))
	for _, df := range walk.files {
		present[df.rel] = df
	}
	mdf, ok := present[ManifestFile]
	if !ok {
		walkSawIt := false
		for _, f := range walk.failures {
			if f.Path == ManifestFile {
				walkSawIt = true
			}
		}
		if !walkSawIt {
			add(IntegrityMissing, ManifestFile, "manifest.json is missing")
		}
		return withWalk()
	}
	mb, err := readCapped(dir, mdf, maxManifestBytes)
	if err != nil {
		add(IntegrityUnreadable, ManifestFile, err.Error())
		return withWalk()
	}

	var env struct {
		SchemaVersion string `json:"schema_version"`
		Kind          string `json:"kind"`
	}
	if err := json.Unmarshal(mb, &env); err != nil {
		add(IntegrityManifestInvalid, ManifestFile, err.Error())
		return withWalk()
	}
	if env.SchemaVersion != SchemaManifest {
		add(IntegrityUnknownSchema, ManifestFile, fmt.Sprintf("schema_version %q", env.SchemaVersion))
		return withWalk()
	}
	if kind := Kind(env.Kind); !kind.Valid() {
		add(IntegrityUnknownKind, ManifestFile, fmt.Sprintf("kind %q", env.Kind))
		return withWalk()
	}
	var m Manifest
	if err := UnmarshalStrict(mb, &m); err != nil {
		add(IntegrityManifestInvalid, ManifestFile, err.Error())
		return withWalk()
	}
	if m.Files == nil {
		add(IntegrityManifestInvalid, ManifestFile, "files list missing")
		return withWalk()
	}
	if again, err := MarshalFile(m); err != nil || string(again) != string(mb) {
		add(IntegrityManifestInvalid, ManifestFile, "manifest.json is not in canonical file form")
	}
	res.Kind = m.Kind
	res.BundleID = m.BundleID
	res.ContentDigest = m.ContentDigest
	res.Manifest = &m

	// Manifest entries.
	expected := make(map[string]FileEntry, len(m.Files))
	folded := make(map[string]string, len(m.Files))
	dirs := map[string]string{}
	for i, e := range m.Files {
		if c, err := CanonicalPath(e.Path); err != nil || c != e.Path {
			detail := "entry is not a canonical bundle path"
			if err != nil {
				detail = err.Error()
			}
			add(IntegrityBadPath, e.Path, detail)
			continue
		}
		if e.Path == ManifestFile || e.Path == SignatureFile {
			add(IntegrityBadPath, e.Path, "reserved file must not be listed in the manifest")
			continue
		}
		if prev, dup := folded[PathFoldKey(e.Path)]; dup {
			add(IntegrityDuplicatePath, e.Path, fmt.Sprintf("collides with %q", prev))
			continue
		}
		if prev, dir, bad := dirCaseConflict(dirs, e.Path); bad {
			add(IntegrityDuplicatePath, e.Path, fmt.Sprintf("directory %q collides with %q by letter case", dir, prev))
			continue
		}
		if i > 0 && m.Files[i-1].Path >= e.Path {
			add(IntegrityManifestInvalid, e.Path, "files are not sorted by path")
		}
		if e.Size < 0 {
			add(IntegrityManifestInvalid, e.Path, "negative size")
		}
		if !isLowerHex(e.SHA256, 64) {
			add(IntegrityManifestInvalid, e.Path, "sha256 is not 64 lowercase hex characters")
		}
		folded[PathFoldKey(e.Path)] = e.Path
		expected[e.Path] = e
	}

	// Disk content.
	res.Failures = append(res.Failures, walk.failures...)
	seen := make(map[string]bool, len(expected))
	covered := map[string]bool{}
	for _, df := range walk.files {
		for d := parentDir(df.rel); d != ""; d = parentDir(d) {
			covered[d] = true
		}
		if df.rel == ManifestFile || df.rel == SignatureFile {
			continue
		}
		e, ok := expected[df.rel]
		if !ok {
			add(IntegrityExtra, df.rel, "file is not listed in the manifest")
			continue
		}
		seen[df.rel] = true
		size, sum, err := hashFile(dir, df)
		switch {
		case err != nil:
			add(IntegrityUnreadable, df.rel, err.Error())
		case size != e.Size:
			add(IntegritySizeMismatch, df.rel, fmt.Sprintf("size %d, manifest says %d", size, e.Size))
		case sum != e.SHA256:
			add(IntegrityDigestMismatch, df.rel, "sha256 differs from the manifest")
		}
	}
	for _, d := range walk.dirs {
		if !covered[d] {
			add(IntegrityExtra, d+"/", "empty directory is not part of the bundle")
		}
	}
	for p := range expected {
		if !seen[p] {
			add(IntegrityMissing, p, "manifested file is not in the bundle")
		}
	}

	// Kind layout (SPEC-0470 TF05-R1).
	onDisk := make(map[string]bool, len(present))
	for p := range present {
		onDisk[p] = true
	}
	res.Failures = append(res.Failures, layoutFailures(m.Kind, expected, onDisk)...)

	// Content digest last: it covers every manifest field.
	if !strings.HasPrefix(m.ContentDigest, "sha256:") || !isLowerHex(strings.TrimPrefix(m.ContentDigest, "sha256:"), 64) {
		add(IntegrityManifestInvalid, ManifestFile, "content_digest is not sha256:<64 lowercase hex>")
	}
	if d, err := ComputeContentDigest(m); err != nil {
		add(IntegrityManifestInvalid, ManifestFile, err.Error())
	} else if d != m.ContentDigest {
		add(IntegrityContentDigestMismatch, ManifestFile, "recomputed "+d)
	}
	return res
}

// layoutFailures applies the per-kind layout rules (SPEC-0470 TF05-R1): a capture
// or a diff contains neither approval.json nor anything under signatures/; a
// capture and a baseline manifest capture.json; a baseline manifests
// approval.json and carries signatures/manifest.ed25519.json, and nothing
// under signatures/ is ever manifested (SPEC-0470 section 4.4 step 3: the one
// unlisted signature file is all that directory holds; an unlisted second
// file there is "extra"). BuildManifest and VerifyDir share these rules.
func layoutFailures(kind Kind, manifested map[string]FileEntry, onDisk map[string]bool) []IntegrityFailure {
	var out []IntegrityFailure
	violation := func(path, detail string) {
		out = append(out, IntegrityFailure{Reason: IntegrityKindLayoutViolation, Path: path, Detail: detail})
	}
	has := func(p string) bool { _, ok := manifested[p]; return ok }
	all := map[string]bool{}
	for p := range manifested {
		all[p] = true
	}
	for p := range onDisk {
		all[p] = true
	}
	switch kind {
	case KindCapture, KindDiff:
		if all[ApprovalFile] {
			violation(ApprovalFile, fmt.Sprintf("a %s bundle must not contain approval.json", kind))
		}
		for p := range all {
			if underSignatures(p) {
				violation(p, fmt.Sprintf("a %s bundle must not contain signatures", kind))
			}
		}
	case KindBaseline:
		if !has(ApprovalFile) {
			violation(ApprovalFile, "a baseline must manifest approval.json")
		}
		if !onDisk[SignatureFile] {
			violation(SignatureFile, "a baseline must carry its signature file")
		}
		for p := range manifested {
			if underSignatures(p) {
				violation(p, "nothing under signatures/ may be manifested; a baseline carries exactly one, unlisted signature file")
			}
		}
	}
	if (kind == KindCapture || kind == KindBaseline) && !has(CaptureFile) {
		violation(CaptureFile, fmt.Sprintf("a %s bundle must manifest capture.json", kind))
	}
	return out
}

// underSignatures reports whether the bundle path p is signatures/ or lies
// below it.
func underSignatures(p string) bool {
	return p == SignaturesDir || strings.HasPrefix(p, SignaturesDir+"/")
}

func parentDir(p string) string {
	i := strings.LastIndexByte(p, '/')
	if i < 0 {
		return ""
	}
	return p[:i]
}

func sortFailures(fs []IntegrityFailure) {
	sort.Slice(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Reason != b.Reason {
			return a.Reason < b.Reason
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Detail < b.Detail
	})
}

// readCapped reads a file found by the walk, up to limit bytes.
func readCapped(dir string, df diskFile, limit int64) ([]byte, error) {
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
		return nil, fmt.Errorf("%s is larger than %d bytes", df.rel, limit)
	}
	return b, nil
}
