// Package seal turns an explicitly approved capture into a signed baseline
// and verifies baselines offline (SPEC-0470, TF-05).
//
// It is the only package that constructs a baseline bundle (TF05-R2). It
// collects no system state, performs no network IO and never runs without
// an explicit approval: nothing in capture, compare, policy, report or the
// platform packages imports it (guard test in this package).
//
// Signing reuses crypto/ed25519 and the key file conventions of
// pkg/skillctl/signing; the signed message is a new, domain-separated format
// (Domain) and no existing signed format is changed (TF05-R9).
package seal

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
)

// Seal errors.
var (
	ErrNotCapture          = errors.New("seal: input is not a valid capture bundle")
	ErrSelfApprovalBlocked = errors.New("seal: self-approval is blocked by policy")
	ErrUnsafeOutput        = errors.New("seal: output location is not allowed")
	ErrNoClock             = errors.New("seal: no clock")
)

// SealRequest is one `baseline approve` operation.
type SealRequest struct {
	// CaptureDir is the capture bundle to approve. It is only read.
	CaptureDir string
	// OutputDir is the new baseline directory. It must not exist or be
	// empty, and must lie outside CaptureDir. A baseline is never overwritten.
	OutputDir string
	// Approval is the human input.
	Approval ApprovalInput
	// Signer signs the statement.
	Signer Signer
	// Clock supplies approved_at.
	Clock trustfreeze.Clock
	// SelfApproval is the self-approval mode at approval time (default warn).
	SelfApproval SelfApprovalMode
	// HomeRoot is refused as an output target together with its ancestors
	// (see trustfreeze.WriterOptions).
	HomeRoot string
}

// SealResult describes a written baseline. OutputDir and Manifest stay out
// of JSON output; the local path is the caller's business.
type SealResult struct {
	OutputDir     string               `json:"-"`
	BundleID      string               `json:"bundle_id"`
	ContentDigest string               `json:"content_digest"`
	CaptureDigest string               `json:"capture_digest"`
	KeyID         string               `json:"key_id"`
	Approval      Approval             `json:"approval"`
	Signature     SignatureDoc         `json:"signature"`
	Warnings      []Warning            `json:"warnings"`
	Manifest      trustfreeze.Manifest `json:"-"`
}

// Seal creates a baseline from a capture (SPEC-0470 TF05-R2, section 4.1).
// In order:
//
//  1. the human approval fields are validated (before anything is read);
//  2. the capture must pass trustfreeze.ReadBundle (VerifyDir plus a valid
//     capture.json) and be of kind capture;
//  3. the approval is built with approved_at from req.Clock and validated;
//  4. the self-approval check runs; block mode stops here;
//  5. every manifested capture file is copied byte for byte (and re-checked
//     against the capture manifest) into a new directory, approval.json is
//     added, the baseline manifest is written, and only then the statement
//     is signed and the signature file written; the writer verifies the
//     staged bundle before it renames it into place.
//
// The capture directory is never written to. Any failure before step 5
// leaves no output and never calls the signer.
func Seal(ctx context.Context, req SealRequest) (*SealResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := req.Approval.Check(); err != nil {
		return nil, err
	}
	if req.Clock == nil {
		return nil, ErrNoClock
	}
	if _, err := checkSigner(req.Signer); err != nil {
		return nil, err
	}

	capture, err := trustfreeze.ReadBundle(req.CaptureDir)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotCapture, err)
	}
	if capture.Manifest.Kind != trustfreeze.KindCapture || capture.Capture == nil {
		return nil, fmt.Errorf("%w: bundle kind is %q", ErrNotCapture, capture.Manifest.Kind)
	}
	cm := capture.Manifest

	approvedAt := req.Clock.Now()
	a, err := NewApproval(req.Approval, approvedAt, CaptureRef{
		ContentDigest: cm.ContentDigest,
		SubjectID:     cm.Subject.ID,
		Actor:         capture.Capture.Capture.Actor,
	}, req.Signer.KeyID())
	if err != nil {
		return nil, err
	}

	warnings, blocked := CheckSelfApproval(a, cm.Subject.ID, a.Identities.SigningDeviceID, req.SelfApproval)
	if blocked {
		codes := make([]string, 0, len(warnings))
		for _, w := range warnings {
			codes = append(codes, w.Code)
		}
		return nil, fmt.Errorf("%w: %s", ErrSelfApprovalBlocked, strings.Join(codes, ", "))
	}
	if capture.Capture.Completeness.Status != trustfreeze.CompletenessComplete {
		warnings = append(warnings, Warning{
			Code:    CodeCaptureIncomplete,
			Message: fmt.Sprintf("the approved capture is incomplete (%d gap(s)); the gaps become part of the baseline", len(capture.Capture.Completeness.Gaps)),
		})
	}
	if warnings == nil {
		warnings = []Warning{}
	}

	if err := checkOutputOutside(req.OutputDir, req.CaptureDir); err != nil {
		return nil, err
	}
	w, err := trustfreeze.NewWriter(req.OutputDir, trustfreeze.WriterOptions{Kind: trustfreeze.KindBaseline, HomeRoot: req.HomeRoot})
	if err != nil {
		return nil, err
	}
	// Abort is a no-op after a successful finalize and removes the staging
	// directory on every error path.
	done := false
	defer func() {
		if !done {
			_ = w.Abort()
		}
	}()
	for _, f := range cm.Files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := w.CopyManifestedFile(req.CaptureDir, cm, f.Path); err != nil {
			return nil, fmt.Errorf("copy %s: %w", f.Path, err)
		}
	}
	if err := w.WriteJSON(trustfreeze.ApprovalFile, a); err != nil {
		return nil, err
	}

	var sigDoc SignatureDoc
	header := trustfreeze.ManifestHeader{
		Kind:      trustfreeze.KindBaseline,
		BundleID:  trustfreeze.BundleID(trustfreeze.KindBaseline, approvedAt, cm.Subject.ID),
		CreatedAt: approvedAt,
		Subject:   cm.Subject,
	}
	m, err := w.FinalizeSigned(header, func(m trustfreeze.Manifest) (any, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		d, err := SignStatement(req.Signer, BuildStatement(a.CaptureDigest, m.ContentDigest, a))
		if err != nil {
			return nil, err
		}
		sigDoc = d
		return d, nil
	})
	if err != nil {
		return nil, err
	}
	done = true
	return &SealResult{
		OutputDir:     w.Target(),
		BundleID:      m.BundleID,
		ContentDigest: m.ContentDigest,
		CaptureDigest: a.CaptureDigest,
		KeyID:         sigDoc.KeyID,
		Approval:      a,
		Signature:     sigDoc,
		Warnings:      warnings,
		Manifest:      m,
	}, nil
}

// checkOutputOutside refuses an output directory that is the capture
// directory or lies below it, also when reached through a symlinked parent,
// because the writer stages next to the target and would then write into
// the capture.
func checkOutputOutside(output, captureDir string) error {
	if strings.TrimSpace(output) == "" {
		return fmt.Errorf("%w: empty output", ErrUnsafeOutput)
	}
	out, err := filepath.Abs(output)
	if err != nil {
		return err
	}
	out = filepath.Clean(out)
	if parent, err := filepath.EvalSymlinks(filepath.Dir(out)); err == nil {
		out = filepath.Join(parent, filepath.Base(out))
	}
	capAbs, err := filepath.Abs(captureDir)
	if err != nil {
		return err
	}
	capAbs = filepath.Clean(capAbs)
	if resolved, err := filepath.EvalSymlinks(capAbs); err == nil {
		capAbs = resolved
	}
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		out, capAbs = strings.ToLower(out), strings.ToLower(capAbs)
	}
	rel, err := filepath.Rel(capAbs, out)
	if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel) {
		return fmt.Errorf("%w: the baseline must be written outside the capture directory", ErrUnsafeOutput)
	}
	return nil
}
