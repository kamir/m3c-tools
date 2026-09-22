package trustfreeze

import (
	"errors"
	"fmt"
)

// MaxIdentifierLen caps a reviewer, change or actor id.
const MaxIdentifierLen = 128

// IdentifierCharset names the characters ValidateIdentifier accepts.
const IdentifierCharset = "ASCII letters, digits and . _ - @ + :"

// ErrInvalidIdentifier is wrapped by ValidateIdentifier.
var ErrInvalidIdentifier = errors.New("trustfreeze: invalid identifier")

// ValidateIdentifier checks a reviewer id, change id or capture actor id
// (SPEC-0470 section 4.2): 1 to MaxIdentifierLen characters, each an ASCII
// letter, a digit or one of . _ - @ + : so an id enters a signed approval
// the same way on every platform and never carries white space, a path, a
// URL, markup or a look-alike Unicode character.
func ValidateIdentifier(s string) error {
	if s == "" {
		return fmt.Errorf("%w: empty", ErrInvalidIdentifier)
	}
	if len(s) > MaxIdentifierLen {
		return fmt.Errorf("%w: longer than %d characters", ErrInvalidIdentifier, MaxIdentifierLen)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '_', c == '-', c == '@', c == '+', c == ':':
		default:
			return fmt.Errorf("%w: only %s are allowed", ErrInvalidIdentifier, IdentifierCharset)
		}
	}
	return nil
}

// DeriveCaptureManifest returns the manifest of the capture a baseline was
// approved from, rebuilt from the baseline alone (SPEC-0470 section 4.4).
// The derivation is pinned; the capture engine writes exactly this manifest:
//
//   - kind capture, schema trust-freeze/manifest/v1, bundle_policy
//     reject_additions true;
//   - created_at is capture.json finished_at, and bundle_id is
//     BundleID(capture, finished_at, subject id);
//   - subject is the baseline subject (a baseline copies it unchanged);
//   - files are the baseline files without approval.json (a baseline copies
//     every capture file byte for byte and adds only approval.json and the
//     unmanifested signature file).
//
// Its ContentDigest is set, so a verifier compares it with the approval's
// capture_digest.
func DeriveCaptureManifest(baseline Manifest, capture CaptureDoc) (Manifest, error) {
	finished, err := ParseTime(capture.Capture.FinishedAt)
	if err != nil {
		return Manifest{}, fmt.Errorf("%w: capture.json finished_at: %w", ErrManifestInvalid, err)
	}
	if finished.IsZero() {
		return Manifest{}, fmt.Errorf("%w: zero capture.json finished_at", ErrManifestInvalid)
	}
	files := make([]FileEntry, 0, len(baseline.Files))
	for _, f := range baseline.Files {
		if f.Path != ApprovalFile {
			files = append(files, f)
		}
	}
	m := Manifest{
		SchemaVersion: SchemaManifest,
		Kind:          KindCapture,
		BundleID:      BundleID(KindCapture, finished, baseline.Subject.ID),
		CreatedAt:     FormatTime(finished),
		Subject:       baseline.Subject,
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
