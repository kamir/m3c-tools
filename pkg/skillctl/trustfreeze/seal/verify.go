package seal

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
)

// Reason is the typed reason of a verification failure.
type Reason string

// Verification failure reasons.
const (
	// ReasonIntegrity: a trustfreeze.VerifyDir failure; IntegrityReason says
	// which one.
	ReasonIntegrity Reason = "integrity"
	// ReasonWrongKind: the bundle is not a baseline (a capture or diff never
	// verifies as one, whatever files it carries).
	ReasonWrongKind Reason = "wrong_kind"
	// ReasonMissingApproval: the baseline has no approval.json.
	ReasonMissingApproval Reason = "missing_approval"
	// ReasonMissingSignature: the baseline has no signature file.
	ReasonMissingSignature Reason = "missing_signature"
	// ReasonCaptureInvalid: capture.json inside the baseline is not valid.
	ReasonCaptureInvalid Reason = "capture_invalid"
	// ReasonApprovalInvalid: approval.json is malformed, misses a mandatory
	// field, or contradicts the manifest or capture.json.
	ReasonApprovalInvalid Reason = "approval_invalid"
	// ReasonSignatureMalformed: the signature file is not a valid
	// trust-freeze/signature/v1 document.
	ReasonSignatureMalformed Reason = "signature_malformed"
	// ReasonDomainMismatch: the signature file names another domain.
	ReasonDomainMismatch Reason = "domain_mismatch"
	// ReasonSigningKeyMismatch: the signature key differs from the key the
	// approval names.
	ReasonSigningKeyMismatch Reason = "signing_key_mismatch"
	// ReasonStatementMismatch: the statement rebuilt from the bundle is not
	// the one the signature file says was signed.
	ReasonStatementMismatch Reason = "statement_mismatch"
	// ReasonBadSignature: the signature does not verify over the rebuilt
	// statement.
	ReasonBadSignature Reason = "bad_signature"
	// ReasonKeyNotTrusted: the signing key is not in the trust policy.
	ReasonKeyNotTrusted Reason = "key_not_trusted"
	// ReasonCaptureDigestMismatch: approval.json capture_digest is not the
	// content digest of the capture rebuilt from this baseline
	// (trustfreeze.DeriveCaptureManifest).
	ReasonCaptureDigestMismatch Reason = "capture_digest_mismatch"
	// ReasonExpired: expires_at lies before the policy clock's now.
	ReasonExpired Reason = "expired"
	// ReasonApprovedInFuture: approved_at lies after the policy clock's now.
	ReasonApprovedInFuture Reason = "approved_in_future"
	// ReasonSelfApprovalBlocked: the policy blocks a detected self-approval.
	ReasonSelfApprovalBlocked Reason = "self_approval_blocked"
	// ReasonTrustPolicyInvalid: the trust policy itself is invalid.
	ReasonTrustPolicyInvalid Reason = "trust_policy_invalid"
	// ReasonCanceled: the context was canceled.
	ReasonCanceled Reason = "canceled"
)

// Failure is one verification failure.
type Failure struct {
	Reason          Reason                      `json:"reason"`
	IntegrityReason trustfreeze.IntegrityReason `json:"integrity_reason,omitempty"`
	Path            string                      `json:"path,omitempty"`
	Detail          string                      `json:"detail,omitempty"`
}

// VerificationResult is the outcome of Verify. OK is true exactly when
// Failures is empty. SignatureValid reports the cryptographic check on its
// own, KeyTrusted the trust decision (SPEC-0470 section 4.6): a
// valid signature by an untrusted key is SignatureValid true, KeyTrusted
// false, OK false.
type VerificationResult struct {
	OK               bool                        `json:"ok"`
	Kind             trustfreeze.Kind            `json:"kind,omitempty"`
	BundleID         string                      `json:"bundle_id,omitempty"`
	ContentDigest    string                      `json:"content_digest,omitempty"`
	CaptureDigest    string                      `json:"capture_digest,omitempty"`
	KeyID            string                      `json:"key_id,omitempty"`
	SignatureChecked bool                        `json:"signature_checked"`
	SignatureValid   bool                        `json:"signature_valid"`
	KeyTrusted       bool                        `json:"key_trusted"`
	Integrity        trustfreeze.IntegrityResult `json:"integrity"`
	Approval         *Approval                   `json:"approval,omitempty"`
	Failures         []Failure                   `json:"failures"`
	Warnings         []Warning                   `json:"warnings"`
}

// ErrVerification is wrapped by VerificationResult.Err.
var ErrVerification = errors.New("seal: baseline verification failed")

// Has reports whether the result has a failure with the given reason.
func (r VerificationResult) Has(reason Reason) bool {
	for _, f := range r.Failures {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

// HasIntegrity reports whether the result has the given integrity failure.
func (r VerificationResult) HasIntegrity(reason trustfreeze.IntegrityReason) bool {
	for _, f := range r.Failures {
		if f.Reason == ReasonIntegrity && f.IntegrityReason == reason {
			return true
		}
	}
	return false
}

// Reasons returns the distinct failure reasons in order of first appearance.
func (r VerificationResult) Reasons() []Reason {
	var out []Reason
	seen := map[Reason]bool{}
	for _, f := range r.Failures {
		if !seen[f.Reason] {
			seen[f.Reason] = true
			out = append(out, f.Reason)
		}
	}
	return out
}

// Err returns nil when OK and otherwise an error wrapping ErrVerification.
func (r VerificationResult) Err() error {
	if r.OK {
		return nil
	}
	if len(r.Failures) == 0 {
		return ErrVerification
	}
	f := r.Failures[0]
	msg := string(f.Reason)
	if f.IntegrityReason != "" {
		msg += " " + string(f.IntegrityReason)
	}
	if f.Path != "" {
		msg += " " + f.Path
	}
	return fmt.Errorf("%w: %d failure(s), first: %s", ErrVerification, len(r.Failures), msg)
}

// Verify checks a baseline directory offline (SPEC-0470 TF05-AC1, TF05-R5):
//
//  1. the trust policy is valid;
//  2. the bundle passes trustfreeze.VerifyDir and is of kind baseline; when
//     integrity fails nothing in the bundle is interpreted further;
//  3. capture.json is valid for the manifest;
//  4. approval.json is in canonical file form, carries every mandatory field
//     and matches the manifest subject and the capture actor, and its
//     capture_digest is the content digest of the capture rebuilt from this
//     baseline (trustfreeze.DeriveCaptureManifest, SPEC-0470 section 4.4);
//  5. the signature file is a valid trust-freeze/signature/v1 document of
//     the Trust Freeze domain whose key is the key the approval names;
//  6. the statement is rebuilt from the manifest on disk and approval.json
//     (statement_sha256 is compared for diagnosis only) and the ed25519
//     signature is checked over it;
//  7. the key is trusted, the approval is neither expired (expires_at before
//     the policy clock's now) nor dated in the future (approved_at after
//     it), and the self-approval mode does not block.
//
// Verify reads only the bundle directory. It has no network code path.
// Verify is for baselines; a capture or diff is reported as wrong_kind (use
// trustfreeze.VerifyDir for their integrity).
func Verify(ctx context.Context, dir string, policy TrustPolicy) (res VerificationResult) {
	res.Failures = []Failure{}
	res.Warnings = []Warning{}
	defer func() { res.OK = len(res.Failures) == 0 }()
	fail := func(reason Reason, path, detail string) {
		res.Failures = append(res.Failures, Failure{Reason: reason, Path: path, Detail: detail})
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		fail(ReasonCanceled, "", err.Error())
		return res
	}
	if err := policy.Validate(); err != nil {
		fail(ReasonTrustPolicyInvalid, "", err.Error())
		return res
	}

	b, readErr := trustfreeze.ReadBundle(dir)
	res.Integrity = b.Integrity
	m := b.Integrity.Manifest
	if m != nil {
		res.Kind, res.BundleID, res.ContentDigest = m.Kind, m.BundleID, m.ContentDigest
	}
	wrongKind := m != nil && m.Kind != trustfreeze.KindBaseline
	if wrongKind {
		fail(ReasonWrongKind, trustfreeze.ManifestFile, fmt.Sprintf("bundle kind is %q, want %q", m.Kind, trustfreeze.KindBaseline))
	}
	if !b.Integrity.OK {
		missingApproval, missingSignature := false, false
		for _, f := range b.Integrity.Failures {
			res.Failures = append(res.Failures, Failure{Reason: ReasonIntegrity, IntegrityReason: f.Reason, Path: f.Path, Detail: f.Detail})
			if wrongKind {
				continue
			}
			absent := f.Reason == trustfreeze.IntegrityMissing || f.Reason == trustfreeze.IntegrityKindLayoutViolation
			missingApproval = missingApproval || (absent && f.Path == trustfreeze.ApprovalFile)
			missingSignature = missingSignature || (absent && f.Path == trustfreeze.SignatureFile)
		}
		if missingApproval {
			fail(ReasonMissingApproval, trustfreeze.ApprovalFile, "a baseline must carry approval.json")
		}
		if missingSignature {
			fail(ReasonMissingSignature, trustfreeze.SignatureFile, "a baseline must carry its signature file")
		}
		return res
	}
	if wrongKind || m == nil {
		return res
	}
	if readErr != nil || b.Capture == nil {
		path, detail := trustfreeze.CaptureFile, "capture.json missing"
		if b.Capture != nil && b.State == nil {
			// capture.json decoded; ReadBundle failed on state/device.json.
			path = trustfreeze.StateDeviceFile
		}
		if readErr != nil {
			detail = readErr.Error()
		}
		fail(ReasonCaptureInvalid, path, detail)
		return res
	}

	// Approval.
	raw, err := b.ReadFile(trustfreeze.ApprovalFile)
	if err != nil {
		fail(ReasonMissingApproval, trustfreeze.ApprovalFile, err.Error())
		return res
	}
	var a Approval
	if err := trustfreeze.UnmarshalCanonicalFile(raw, &a); err != nil {
		fail(ReasonApprovalInvalid, trustfreeze.ApprovalFile, err.Error())
		return res
	}
	if err := ValidateApproval(a); err != nil {
		fail(ReasonApprovalInvalid, trustfreeze.ApprovalFile, err.Error())
		return res
	}
	res.Approval = &a
	res.CaptureDigest = a.CaptureDigest
	approvalOK := true
	if a.Identities.CapturedSubjectID != m.Subject.ID {
		fail(ReasonApprovalInvalid, trustfreeze.ApprovalFile, "identities.captured_subject_id differs from the manifest subject")
		approvalOK = false
	}
	if a.Identities.CaptureActor != b.Capture.Capture.Actor {
		fail(ReasonApprovalInvalid, trustfreeze.ApprovalFile, "identities.capture_actor differs from capture.json capture.actor")
		approvalOK = false
	}
	// The approval must name the capture this baseline holds: its digest is
	// recomputed from the baseline files, never taken from the approval.
	if cm, err := trustfreeze.DeriveCaptureManifest(*m, *b.Capture); err != nil {
		fail(ReasonCaptureInvalid, trustfreeze.CaptureFile, err.Error())
	} else if cm.ContentDigest != a.CaptureDigest {
		fail(ReasonCaptureDigestMismatch, trustfreeze.ApprovalFile,
			"approval names capture "+a.CaptureDigest+", the baseline holds capture "+cm.ContentDigest)
	}

	// Signature document.
	sb, err := trustfreeze.ReadSignatureFile(dir)
	if err != nil {
		reason := ReasonSignatureMalformed
		if errors.Is(err, fs.ErrNotExist) {
			reason = ReasonMissingSignature
		}
		fail(reason, trustfreeze.SignatureFile, err.Error())
		return res
	}
	ds, err := decodeSignatureDoc(sb)
	if err != nil {
		fail(ReasonSignatureMalformed, trustfreeze.SignatureFile, err.Error())
		return res
	}
	res.KeyID = ds.doc.KeyID
	if ds.doc.Domain != Domain {
		fail(ReasonDomainMismatch, trustfreeze.SignatureFile, fmt.Sprintf("domain %q, want %q", ds.doc.Domain, Domain))
	}
	if ds.doc.KeyID != a.Identities.SigningKeyID {
		fail(ReasonSigningKeyMismatch, trustfreeze.SignatureFile, fmt.Sprintf("signed by %s, approval names %s", ds.doc.KeyID, a.Identities.SigningKeyID))
	}

	// Statement and signature. The statement comes from the files on disk,
	// never from the signature document.
	if err := ctx.Err(); err != nil {
		fail(ReasonCanceled, "", err.Error())
		return res
	}
	msg, err := BuildStatement(a.CaptureDigest, m.ContentDigest, a).Message()
	if err != nil {
		fail(ReasonApprovalInvalid, trustfreeze.ApprovalFile, err.Error())
		return res
	}
	if StatementSHA256(msg) != ds.doc.StatementSHA256 {
		fail(ReasonStatementMismatch, trustfreeze.SignatureFile, "the signed statement is not the statement of this bundle")
	}
	res.SignatureChecked = true
	res.SignatureValid = ed25519.Verify(ds.pub, msg, ds.sig)
	if !res.SignatureValid {
		fail(ReasonBadSignature, trustfreeze.SignatureFile, "the signature does not verify over this bundle's statement")
	}
	res.KeyTrusted = policy.Trusts(ds.pub)
	if !res.KeyTrusted {
		fail(ReasonKeyNotTrusted, trustfreeze.SignatureFile, "key "+ds.doc.KeyID+" is not in the trust policy")
	}

	// Expiry: valid up to and including expires_at. An approval dated after
	// now claims a time the verifier has not reached yet: refused, so a
	// wrong clock at approval time cannot extend a baseline's life.
	now := policy.clock().Now()
	if a.ExpiresAt != "" {
		exp, err := trustfreeze.ParseTime(a.ExpiresAt)
		if err != nil {
			fail(ReasonApprovalInvalid, trustfreeze.ApprovalFile, err.Error())
		} else if exp.Before(now) {
			fail(ReasonExpired, trustfreeze.ApprovalFile, "expired at "+a.ExpiresAt+", now "+trustfreeze.FormatTime(now))
		}
	}
	// ValidateApproval has already parsed approved_at.
	if at, err := trustfreeze.ParseTime(a.ApprovedAt); err == nil && at.After(now) {
		fail(ReasonApprovedInFuture, trustfreeze.ApprovalFile, "approved at "+a.ApprovedAt+", now "+trustfreeze.FormatTime(now))
	}

	// Self-approval.
	if approvalOK {
		findings, blocked := CheckSelfApproval(a, m.Subject.ID, a.Identities.SigningDeviceID, policy.SelfApproval)
		if blocked {
			codes := make([]string, 0, len(findings))
			for _, f := range findings {
				codes = append(codes, f.Code)
			}
			fail(ReasonSelfApprovalBlocked, trustfreeze.ApprovalFile, strings.Join(codes, ", "))
		} else {
			res.Warnings = append(res.Warnings, findings...)
		}
	}
	return res
}
