package seal

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/redact"
)

// Approval is approval.json of a baseline (SPEC-0470 TF05-R3). The five
// mandatory fields reviewer, change_id, reason, approved_at and
// capture_digest are never omitted and never empty after trimming;
// ValidateApproval enforces that before anything is signed (TF05-AC5).
//
// Identities models the parties of TF05-R7 explicitly, so a self-approval
// policy can be evaluated now and by a later, stricter profile.
type Approval struct {
	SchemaVersion string `json:"schema_version"`
	Reviewer      string `json:"reviewer"`
	ChangeID      string `json:"change_id"`
	Reason        string `json:"reason"`
	// ApprovedAt comes from the injected clock (FormatTime form).
	ApprovedAt string `json:"approved_at"`
	// CaptureDigest is the content_digest of the approved capture manifest.
	CaptureDigest string `json:"capture_digest"`
	// ExpiresAt is optional; the baseline is valid up to and including it.
	ExpiresAt  string     `json:"expires_at,omitempty"`
	Identities Identities `json:"identities"`
	PolicyRef  string     `json:"policy_ref,omitempty"`
}

// Identities names who and what took part in capture and approval
// (SPEC-0470 TF05-R7).
type Identities struct {
	// CapturedSubjectID is the subject id of the captured device.
	CapturedSubjectID string `json:"captured_subject_id"`
	// CaptureActor is capture.json capture.actor, when the capture had one.
	CaptureActor string `json:"capture_actor,omitempty"`
	// ReviewerID is the reviewer identity the self-approval check compares.
	// This version sets it to the normalized reviewer; an organisation PKI
	// can later bind it to a certificate subject without a format change.
	ReviewerID string `json:"reviewer_id"`
	// SigningKeyID is the key_id of the signing key (see KeyIDFor).
	SigningKeyID string `json:"signing_key_id"`
	// SigningDeviceID is the subject id of the approving device, derived with
	// trustfreeze.SubjectID like the captured subject.
	SigningDeviceID string `json:"signing_device_id,omitempty"`
}

// ErrApprovalInvalid is wrapped by every approval validation error.
var ErrApprovalInvalid = errors.New("seal: approval is invalid")

// ApprovalError names the offending approval field by its JSON name.
type ApprovalError struct {
	Field   string
	Problem string
}

func (e *ApprovalError) Error() string {
	return "seal: approval field " + e.Field + ": " + e.Problem
}

// Unwrap makes errors.Is(err, ErrApprovalInvalid) true.
func (e *ApprovalError) Unwrap() error { return ErrApprovalInvalid }

func approvalErr(field, problem string) error {
	return &ApprovalError{Field: field, Problem: problem}
}

// Field length caps. They bound what a reviewer can push into a signed
// statement; they are not a format promise.
const (
	maxLineField = 1024
	maxReason    = 64 << 10
)

// ApprovalInput is what a human supplies for an approval.
type ApprovalInput struct {
	Reviewer string
	ChangeID string
	// Reason may span several lines; CRLF and CR become LF.
	Reason string
	// ExpiresAt is optional (zero: no expiry). Any zone; it is stored in UTC.
	ExpiresAt time.Time
	// PolicyRef optionally names the policy the reviewer approved under, by
	// id or digest (never a local path).
	PolicyRef string
	// ApproverSubjectID is the subject id of the approving device
	// (trustfreeze.SubjectID of its OS family and hostname), recorded as
	// identities.signing_device_id. Empty when unknown.
	ApproverSubjectID string
}

// CaptureRef carries the facts about the approved capture that enter the
// approval. They are copied verbatim; Verify compares them with the baseline
// manifest and capture.json.
type CaptureRef struct {
	ContentDigest string
	SubjectID     string
	Actor         string
}

// NormalizeText is the one text normalization of approval input (SPEC-0470
// TF05-R4): CRLF and lone CR become LF, surrounding white space is trimmed.
// Signed bytes therefore do not depend on the line ending of a reason file.
func NormalizeText(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.TrimSpace(s)
}

// Check validates the human-supplied fields alone. Seal calls it before it
// reads the capture, so a missing reviewer, change id or reason fails first,
// and so does free text that carries secret material (checkNoSecret).
func (in ApprovalInput) Check() error {
	if err := checkIdentifier("reviewer", NormalizeText(in.Reviewer), true); err != nil {
		return err
	}
	if err := checkIdentifier("change_id", NormalizeText(in.ChangeID), true); err != nil {
		return err
	}
	if err := checkReason(NormalizeText(in.Reason)); err != nil {
		return err
	}
	if err := checkPolicyRef(NormalizeText(in.PolicyRef)); err != nil {
		return err
	}
	if err := checkOptionalLine("identities.signing_device_id", NormalizeText(in.ApproverSubjectID)); err != nil {
		return err
	}
	return checkNoSecrets([][2]string{
		{"reviewer", NormalizeText(in.Reviewer)},
		{"change_id", NormalizeText(in.ChangeID)},
		{"reason", NormalizeText(in.Reason)},
		{"policy_ref", NormalizeText(in.PolicyRef)},
	})
}

// checkNoSecrets refuses approval text that the default redaction patterns
// (redact.Default: PEM private keys, bearer and authorization values, tokens,
// key/value pairs with a sensitive key, and so on) would change (SPEC-0470
// TF05-R8, section 4.5). The text is signed, so it cannot be
// redacted afterwards without invalidating the baseline: it is refused, never
// silently rewritten. The error names the field and the pattern classes, not
// the text. fields holds (JSON field name, value) pairs.
func checkNoSecrets(fields [][2]string) error {
	for _, f := range fields {
		if f[1] == "" {
			continue
		}
		_, log, err := redact.Default().RedactString(context.Background(), f[1])
		if err != nil {
			return approvalErr(f[0], "could not be screened for secret material")
		}
		if log.Total() > 0 {
			return approvalErr(f[0], "looks like secret material ("+strings.Join(log.Classes(), ", ")+
				"); approval text is signed and could never be removed again, so it is refused")
		}
	}
	return nil
}

// checkPolicyRef: an optional single line that is an identifier or digest,
// not a local path. A path would put host separators and user directories
// into the signed bytes (SPEC-0470 TF05-R4).
func checkPolicyRef(v string) error {
	if err := checkOptionalLine("policy_ref", v); err != nil {
		return err
	}
	if strings.ContainsRune(v, '\\') || strings.HasPrefix(v, "/") ||
		(len(v) >= 2 && v[1] == ':' && ((v[0] >= 'a' && v[0] <= 'z') || (v[0] >= 'A' && v[0] <= 'Z'))) {
		return approvalErr("policy_ref", "must be a policy id or digest, not a local path")
	}
	return nil
}

// NewApproval builds and validates the approval document. approvedAt comes
// from the injected clock; a zero time counts as a missing approved_at.
func NewApproval(in ApprovalInput, approvedAt time.Time, capture CaptureRef, signingKeyID string) (Approval, error) {
	if err := in.Check(); err != nil {
		return Approval{}, err
	}
	if approvedAt.IsZero() {
		return Approval{}, approvalErr("approved_at", "is required")
	}
	reviewer := NormalizeText(in.Reviewer)
	a := Approval{
		SchemaVersion: trustfreeze.SchemaApproval,
		Reviewer:      reviewer,
		ChangeID:      NormalizeText(in.ChangeID),
		Reason:        NormalizeText(in.Reason),
		ApprovedAt:    trustfreeze.FormatTime(approvedAt),
		CaptureDigest: capture.ContentDigest,
		Identities: Identities{
			CapturedSubjectID: capture.SubjectID,
			CaptureActor:      capture.Actor,
			ReviewerID:        reviewer,
			SigningKeyID:      signingKeyID,
			SigningDeviceID:   NormalizeText(in.ApproverSubjectID),
		},
		PolicyRef: NormalizeText(in.PolicyRef),
	}
	if !in.ExpiresAt.IsZero() {
		a.ExpiresAt = trustfreeze.FormatTime(in.ExpiresAt)
	}
	if err := ValidateApproval(a); err != nil {
		return Approval{}, err
	}
	return a, nil
}

// ValidateApproval checks an approval completely: schema id, the mandatory
// fields in the order reviewer, change_id, reason, approved_at,
// capture_digest, then the optional fields and the identities. Text fields
// must already be normalized, times must be in FormatTime form, and
// expires_at must lie after approved_at.
func ValidateApproval(a Approval) error {
	if err := trustfreeze.CheckSchema(a.SchemaVersion, trustfreeze.SchemaApproval); err != nil {
		return approvalErr("schema_version", err.Error())
	}
	if err := checkIdentifier("reviewer", a.Reviewer, true); err != nil {
		return err
	}
	if err := checkIdentifier("change_id", a.ChangeID, true); err != nil {
		return err
	}
	if err := checkReason(a.Reason); err != nil {
		return err
	}
	approved, err := checkTime("approved_at", a.ApprovedAt, true)
	if err != nil {
		return err
	}
	if strings.TrimSpace(a.CaptureDigest) == "" {
		return approvalErr("capture_digest", "is required")
	}
	if !validDigest(a.CaptureDigest) {
		return approvalErr("capture_digest", "must be sha256:<64 lowercase hex>")
	}
	if a.ExpiresAt != "" {
		expires, err := checkTime("expires_at", a.ExpiresAt, false)
		if err != nil {
			return err
		}
		if !expires.After(approved) {
			return approvalErr("expires_at", "must be later than approved_at")
		}
	}
	if err := checkPolicyRef(a.PolicyRef); err != nil {
		return err
	}
	id := a.Identities
	if err := checkRequiredLine("identities.captured_subject_id", id.CapturedSubjectID); err != nil {
		return err
	}
	if err := checkIdentifier("identities.capture_actor", id.CaptureActor, false); err != nil {
		return err
	}
	if err := checkIdentifier("identities.reviewer_id", id.ReviewerID, true); err != nil {
		return err
	}
	if strings.TrimSpace(id.SigningKeyID) == "" {
		return approvalErr("identities.signing_key_id", "is required")
	}
	if !ValidKeyID(id.SigningKeyID) {
		return approvalErr("identities.signing_key_id", "must be "+KeyIDPrefix+"<16 lowercase hex>")
	}
	if err := checkOptionalLine("identities.signing_device_id", id.SigningDeviceID); err != nil {
		return err
	}
	// Verify runs this too, so a baseline from a signer that skipped the
	// check still fails as approval_invalid (TF05-R8).
	return checkNoSecrets([][2]string{
		{"reviewer", a.Reviewer},
		{"change_id", a.ChangeID},
		{"reason", a.Reason},
		{"policy_ref", a.PolicyRef},
		{"identities.capture_actor", id.CaptureActor},
		{"identities.reviewer_id", id.ReviewerID},
	})
}

// ParseApproval decodes an approval document in any JSON formatting (key
// order, indentation, line endings), rejects unknown fields and trailing
// data, and validates it. The approval.json inside a baseline is additionally
// required to be in canonical file form; Verify checks that.
func ParseApproval(b []byte) (Approval, error) {
	var a Approval
	if err := trustfreeze.UnmarshalStrict(b, &a); err != nil {
		return Approval{}, fmt.Errorf("%w: %w", ErrApprovalInvalid, err)
	}
	if err := ValidateApproval(a); err != nil {
		return Approval{}, err
	}
	return a, nil
}

// checkIdentifier: a reviewer, change or actor id (SPEC-0470 section 4.2),
// 1 to trustfreeze.MaxIdentifierLen ASCII letters, digits and . _ - @ + :
// An optional id may be empty; a required one must not be blank.
func checkIdentifier(field, v string, required bool) error {
	if v == "" && !required {
		return nil
	}
	if required && strings.TrimSpace(v) == "" {
		return approvalErr(field, "is required")
	}
	if trustfreeze.ValidateIdentifier(v) != nil {
		return approvalErr(field, fmt.Sprintf("must be 1 to %d characters from %s", trustfreeze.MaxIdentifierLen, trustfreeze.IdentifierCharset))
	}
	return nil
}

func checkRequiredLine(field, v string) error {
	if strings.TrimSpace(v) == "" {
		return approvalErr(field, "is required")
	}
	return checkLine(field, v)
}

func checkOptionalLine(field, v string) error {
	if v == "" {
		return nil
	}
	return checkLine(field, v)
}

// checkLine: normalized, valid UTF-8, single line, no control characters.
func checkLine(field, v string) error {
	if len(v) > maxLineField {
		return approvalErr(field, fmt.Sprintf("is longer than %d bytes", maxLineField))
	}
	if !utf8.ValidString(v) {
		return approvalErr(field, "is not valid UTF-8")
	}
	if NormalizeText(v) != v {
		return approvalErr(field, "has surrounding white space or CR line endings")
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return approvalErr(field, "must be a single line without control characters")
		}
	}
	return nil
}

// checkReason: like checkLine, but LF and TAB are allowed.
func checkReason(v string) error {
	if strings.TrimSpace(v) == "" {
		return approvalErr("reason", "is required")
	}
	if len(v) > maxReason {
		return approvalErr("reason", fmt.Sprintf("is longer than %d bytes", maxReason))
	}
	if !utf8.ValidString(v) {
		return approvalErr("reason", "is not valid UTF-8")
	}
	if NormalizeText(v) != v {
		return approvalErr("reason", "has surrounding white space or CR line endings")
	}
	for _, r := range v {
		if r != '\n' && r != '\t' && unicode.IsControl(r) {
			return approvalErr("reason", "contains control characters")
		}
	}
	return nil
}

func checkTime(field, v string, required bool) (time.Time, error) {
	if strings.TrimSpace(v) == "" {
		if required {
			return time.Time{}, approvalErr(field, "is required")
		}
		return time.Time{}, nil
	}
	t, err := trustfreeze.ParseTime(v)
	if err != nil {
		return time.Time{}, approvalErr(field, "must be a UTC RFC 3339 time in canonical form")
	}
	if t.IsZero() {
		return time.Time{}, approvalErr(field, "is required")
	}
	return t, nil
}

// validDigest reports whether s is "sha256:" + 64 lowercase hex characters.
func validDigest(s string) bool {
	h, ok := strings.CutPrefix(s, "sha256:")
	return ok && isLowerHex(h, 64)
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
