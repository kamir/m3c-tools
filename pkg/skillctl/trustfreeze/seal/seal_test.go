package seal

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
)

// TF05-R2, SPEC-0470 section 4.1: the baseline is a new directory holding the
// byte-identical capture files plus approval.json, a baseline manifest and
// the signature file; the capture is not modified.
func TestSealCreatesBaselineAndLeavesCaptureUntouched(t *testing.T) {
	root := t.TempDir()
	capDir, capManifest := newCapture(t, root, "capture", defaultFixture())
	before := treeState(t, capDir)
	s := &countingSigner{Signer: seedSigner(t, seedTrusted)}
	out := filepath.Join(root, "baseline")

	res, err := Seal(t.Context(), defaultRequest(capDir, out, s))
	if err != nil {
		t.Fatal(err)
	}
	sameTree(t, before, treeState(t, capDir))
	noSiblingsLike(t, root, ".tf-staging-")
	if s.calls() != 1 {
		t.Fatalf("signer called %d times, want 1", s.calls())
	}

	integ := trustfreeze.VerifyDir(out)
	if !integ.OK {
		t.Fatalf("baseline integrity: %v", integ.Err())
	}
	m := *integ.Manifest
	if m.Kind != trustfreeze.KindBaseline {
		t.Fatalf("kind %q", m.Kind)
	}
	if m.Subject != capManifest.Subject {
		t.Fatalf("subject %+v, want %+v", m.Subject, capManifest.Subject)
	}
	if m.CreatedAt != trustfreeze.FormatTime(approveTime) {
		t.Fatalf("created_at %q", m.CreatedAt)
	}
	want := map[string]trustfreeze.FileEntry{}
	for _, f := range capManifest.Files {
		want[f.Path] = f
	}
	if len(m.Files) != len(capManifest.Files)+1 {
		t.Fatalf("baseline lists %d files, want %d", len(m.Files), len(capManifest.Files)+1)
	}
	for _, f := range m.Files {
		if f.Path == trustfreeze.ApprovalFile {
			continue
		}
		if want[f.Path] != f {
			t.Fatalf("baseline entry %+v differs from capture entry %+v", f, want[f.Path])
		}
		if !bytes.Equal(readRaw(t, out, f.Path), readRaw(t, capDir, f.Path)) {
			t.Fatalf("%s is not byte-identical to the capture", f.Path)
		}
	}
	if _, err := os.Stat(filepath.Join(out, filepath.FromSlash(trustfreeze.SignatureFile))); err != nil {
		t.Fatal(err)
	}

	a := readApproval(t, out)
	if a != res.Approval {
		t.Fatalf("approval on disk differs from the result")
	}
	if a.CaptureDigest != capManifest.ContentDigest || res.CaptureDigest != capManifest.ContentDigest {
		t.Fatalf("capture_digest %q, want %q", a.CaptureDigest, capManifest.ContentDigest)
	}
	if a.ApprovedAt != trustfreeze.FormatTime(approveTime) {
		t.Fatalf("approved_at %q", a.ApprovedAt)
	}
	wantID := Identities{
		CapturedSubjectID: capManifest.Subject.ID,
		CaptureActor:      "alice",
		ReviewerID:        "bob",
		SigningKeyID:      s.KeyID(),
		SigningDeviceID:   trustfreeze.SubjectID("darwin", "approver.example"),
	}
	if a.Identities != wantID {
		t.Fatalf("identities %+v, want %+v", a.Identities, wantID)
	}
	if res.ContentDigest != m.ContentDigest || res.BundleID != m.BundleID || res.KeyID != s.KeyID() {
		t.Fatalf("result %+v does not describe manifest %+v", res, m)
	}
	sig := readSig(t, out)
	if sig != res.Signature || sig.Domain != Domain || sig.Algorithm != Algorithm || sig.SchemaVersion != trustfreeze.SchemaSignature {
		t.Fatalf("signature document %+v", sig)
	}
	if len(res.Warnings) != 0 {
		t.Fatalf("unexpected warnings %+v", res.Warnings)
	}
	requireOK(t, Verify(t.Context(), out, testPolicy(s)))
}

// TF05-R2, SPEC-0470 section 4.1: only a valid capture can be sealed, and
// nothing is signed or written otherwise.
func TestSealRefusesInvalidInput(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(t *testing.T, root string) string
	}{
		{"baseline-as-input", func(t *testing.T, root string) string {
			b := newBaseline(t, nil)
			return b.dir
		}},
		{"tampered-capture", func(t *testing.T, root string) string {
			dir, _ := newCapture(t, root, "capture", defaultFixture())
			p := "evidence/common.identity/uname-r"
			b := readRaw(t, dir, p)
			b[0] ^= 0x01
			writeRaw(t, dir, p, b)
			return dir
		}},
		{"capture-with-signatures-dir", func(t *testing.T, root string) string {
			dir, _ := newCapture(t, root, "capture", defaultFixture())
			writeRaw(t, dir, trustfreeze.SignatureFile, []byte("{}\n"))
			return dir
		}},
		{"missing-directory", func(t *testing.T, root string) string {
			return filepath.Join(root, "does-not-exist")
		}},
		{"empty-directory", func(t *testing.T, root string) string {
			dir := filepath.Join(root, "empty")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			return dir
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			in := tc.prepare(t, root)
			s := &countingSigner{Signer: seedSigner(t, seedTrusted)}
			out := filepath.Join(root, "out")
			_, err := Seal(t.Context(), defaultRequest(in, out, s))
			if !errors.Is(err, ErrNotCapture) {
				t.Fatalf("err = %v, want ErrNotCapture", err)
			}
			if s.calls() != 0 {
				t.Fatalf("signer called %d times", s.calls())
			}
			if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("output exists after refusal: %v", err)
			}
		})
	}
}

// SPEC-0470 section 4.1: the output must not exist or be empty; a baseline is
// never overwritten.
func TestSealOutputTarget(t *testing.T) {
	root := t.TempDir()
	capDir, _ := newCapture(t, root, "capture", defaultFixture())
	s := seedSigner(t, seedTrusted)

	empty := filepath.Join(root, "empty")
	if err := os.Mkdir(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Seal(t.Context(), defaultRequest(capDir, empty, s)); err != nil {
		t.Fatalf("empty target: %v", err)
	}
	before := treeState(t, empty)
	if _, err := Seal(t.Context(), defaultRequest(capDir, empty, s)); !errors.Is(err, trustfreeze.ErrTargetNotEmpty) {
		t.Fatalf("second seal into a baseline: err = %v, want ErrTargetNotEmpty", err)
	}
	sameTree(t, before, treeState(t, empty))

	full := filepath.Join(root, "full")
	writeRaw(t, full, "note.txt", []byte("keep"))
	if _, err := Seal(t.Context(), defaultRequest(capDir, full, s)); !errors.Is(err, trustfreeze.ErrTargetNotEmpty) {
		t.Fatalf("non-empty target: err = %v, want ErrTargetNotEmpty", err)
	}
	noSiblingsLike(t, root, ".tf-staging-")
}

// SPEC-0470 section 4.1: the capture directory is never modified, so an output
// inside it (the writer would stage there) is refused.
func TestSealRefusesOutputInsideCapture(t *testing.T) {
	root := t.TempDir()
	capDir, _ := newCapture(t, root, "capture", defaultFixture())
	before := treeState(t, capDir)
	s := &countingSigner{Signer: seedSigner(t, seedTrusted)}

	for _, out := range []string{capDir, filepath.Join(capDir, "baseline"), filepath.Join(capDir, "probes", "baseline")} {
		_, err := Seal(t.Context(), defaultRequest(capDir, out, s))
		if !errors.Is(err, ErrUnsafeOutput) {
			t.Fatalf("output %s: err = %v, want ErrUnsafeOutput", out, err)
		}
	}
	t.Run("through-symlinked-parent", func(t *testing.T) {
		link := filepath.Join(root, "link-to-capture")
		if err := os.Symlink(capDir, link); err != nil {
			t.Skipf("symlinks unavailable on this host: %v", err)
		}
		_, err := Seal(t.Context(), defaultRequest(capDir, filepath.Join(link, "baseline"), s))
		if !errors.Is(err, ErrUnsafeOutput) {
			t.Fatalf("err = %v, want ErrUnsafeOutput", err)
		}
	})
	if s.calls() != 0 {
		t.Fatalf("signer called %d times", s.calls())
	}
	sameTree(t, before, treeState(t, capDir))
}

// TF05-AC5: an approval without reviewer, change id or reason (missing or
// white space only), or without approved_at, is rejected before the signer
// is ever invoked, and nothing is written.
func TestSealRejectsIncompleteApprovalBeforeSigning(t *testing.T) {
	cases := []struct {
		name  string
		field string
		mut   func(*SealRequest)
	}{
		{"reviewer-missing", "reviewer", func(r *SealRequest) { r.Approval.Reviewer = "" }},
		{"reviewer-whitespace", "reviewer", func(r *SealRequest) { r.Approval.Reviewer = " \t\r\n " }},
		{"change-id-missing", "change_id", func(r *SealRequest) { r.Approval.ChangeID = "" }},
		{"change-id-whitespace", "change_id", func(r *SealRequest) { r.Approval.ChangeID = "  \t" }},
		{"reason-missing", "reason", func(r *SealRequest) { r.Approval.Reason = "" }},
		{"reason-whitespace", "reason", func(r *SealRequest) { r.Approval.Reason = "\r\n\r\n  \n" }},
		{"approved-at-missing", "approved_at", func(r *SealRequest) { r.Clock = trustfreeze.FixedClock{} }},
		{"reviewer-multiline", "reviewer", func(r *SealRequest) { r.Approval.Reviewer = "bob\nmallory" }},
		{"expires-before-approval", "expires_at", func(r *SealRequest) { r.Approval.ExpiresAt = approveTime.Add(-time.Second) }},
		{"expires-at-approval", "expires_at", func(r *SealRequest) { r.Approval.ExpiresAt = approveTime }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			capDir, _ := newCapture(t, root, "capture", defaultFixture())
			before := treeState(t, capDir)
			s := &countingSigner{Signer: seedSigner(t, seedTrusted)}
			out := filepath.Join(root, "baseline")
			req := defaultRequest(capDir, out, s)
			tc.mut(&req)
			_, err := Seal(t.Context(), req)
			var ae *ApprovalError
			if !errors.As(err, &ae) || !errors.Is(err, ErrApprovalInvalid) {
				t.Fatalf("err = %v, want an ApprovalError", err)
			}
			if ae.Field != tc.field {
				t.Fatalf("field %q, want %q (%v)", ae.Field, tc.field, err)
			}
			if s.calls() != 0 {
				t.Fatalf("signer called %d times before a valid approval existed", s.calls())
			}
			if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("output exists: %v", err)
			}
			noSiblingsLike(t, root, ".tf-staging-")
			sameTree(t, before, treeState(t, capDir))
		})
	}
}

// TF05-AC6 at approval time: block mode refuses a self-approval before
// signing; warn mode seals and reports it; allow mode seals silently.
func TestSealSelfApproval(t *testing.T) {
	sameDevice := func(r *SealRequest) {
		r.Approval.ApproverSubjectID = defaultFixture().subject().ID
	}
	samePerson := func(r *SealRequest) { r.Approval.Reviewer = " Alice " }
	unknownDevice := func(r *SealRequest) { r.Approval.ApproverSubjectID = "" }
	cases := []struct {
		name      string
		mode      SelfApprovalMode
		mut       func(*SealRequest)
		wantErr   bool
		wantCodes []string
	}{
		{"block-same-device", SelfApprovalBlock, sameDevice, true, nil},
		{"block-same-person", SelfApprovalBlock, samePerson, true, nil},
		{"block-independent", SelfApprovalBlock, func(*SealRequest) {}, false, nil},
		{"warn-same-device", SelfApprovalWarn, sameDevice, false, []string{CodeSelfApprovalSameDevice}},
		{"warn-same-person", SelfApprovalWarn, samePerson, false, []string{CodeSelfApprovalSamePerson}},
		{"default-mode-warns", "", samePerson, false, []string{CodeSelfApprovalSamePerson}},
		{"allow-same-device", SelfApprovalAllow, sameDevice, false, nil},
		{"unknown-mode-blocks", SelfApprovalMode("sometimes"), sameDevice, true, nil},
		// The approving device is unknown: block cannot evaluate the
		// same-device check and fails closed; warn seals and says so.
		{"block-device-unknown", SelfApprovalBlock, unknownDevice, true, nil},
		{"warn-device-unknown", SelfApprovalWarn, unknownDevice, false, []string{CodeSelfApprovalDeviceUnknown}},
		{"allow-device-unknown", SelfApprovalAllow, unknownDevice, false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			capDir, _ := newCapture(t, root, "capture", defaultFixture())
			s := &countingSigner{Signer: seedSigner(t, seedTrusted)}
			out := filepath.Join(root, "baseline")
			req := defaultRequest(capDir, out, s)
			req.SelfApproval = tc.mode
			tc.mut(&req)
			res, err := Seal(t.Context(), req)
			if tc.wantErr {
				if !errors.Is(err, ErrSelfApprovalBlocked) {
					t.Fatalf("err = %v, want ErrSelfApprovalBlocked", err)
				}
				if s.calls() != 0 {
					t.Fatalf("signer called %d times", s.calls())
				}
				if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("output exists: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var codes []string
			for _, w := range res.Warnings {
				codes = append(codes, w.Code)
			}
			if len(codes) != len(tc.wantCodes) || (len(codes) > 0 && codes[0] != tc.wantCodes[0]) {
				t.Fatalf("warnings %v, want %v", codes, tc.wantCodes)
			}
		})
	}
}

func TestSealIncompleteCaptureIsSealedWithWarning(t *testing.T) {
	root := t.TempDir()
	fx := defaultFixture()
	fx.required = []string{"common.identity", "common.git"}
	capDir, _ := newCapture(t, root, "capture", fx)
	s := seedSigner(t, seedTrusted)
	res, err := Seal(t.Context(), defaultRequest(capDir, filepath.Join(root, "baseline"), s))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Warnings) != 1 || res.Warnings[0].Code != CodeCaptureIncomplete {
		t.Fatalf("warnings %+v, want one %s", res.Warnings, CodeCaptureIncomplete)
	}
	requireOK(t, Verify(t.Context(), filepath.Join(root, "baseline"), testPolicy(s)))
}

// lyingSigner claims a key id that is not its own.
type lyingSigner struct{ Signer }

func (lyingSigner) KeyID() string { return "ed25519:0000000000000000" }

// garbageSigner returns a signature that does not verify.
type garbageSigner struct{ Signer }

func (garbageSigner) Sign([]byte) ([]byte, error) { return make([]byte, 64), nil }

// failingSigner fails to sign.
type failingSigner struct{ Signer }

func (failingSigner) Sign([]byte) ([]byte, error) { return nil, errors.New("token not present") }

func TestSealRejectsBadSigner(t *testing.T) {
	base := seedSigner(t, seedTrusted)
	cases := []struct {
		name string
		s    Signer
		want error
	}{
		{"nil", nil, ErrSignerInvalid},
		{"key-id-lies", lyingSigner{base}, ErrSignerInvalid},
		{"garbage-signature", garbageSigner{base}, ErrSignerInvalid},
		{"sign-fails", failingSigner{base}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			capDir, _ := newCapture(t, root, "capture", defaultFixture())
			before := treeState(t, capDir)
			out := filepath.Join(root, "baseline")
			req := defaultRequest(capDir, out, tc.s)
			_, err := Seal(t.Context(), req)
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("output exists: %v", err)
			}
			noSiblingsLike(t, root, ".tf-staging-")
			sameTree(t, before, treeState(t, capDir))
		})
	}
}

func TestSealHonorsCanceledContext(t *testing.T) {
	root := t.TempDir()
	capDir, _ := newCapture(t, root, "capture", defaultFixture())
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	s := &countingSigner{Signer: seedSigner(t, seedTrusted)}
	_, err := Seal(ctx, defaultRequest(capDir, filepath.Join(root, "baseline"), s))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if s.calls() != 0 {
		t.Fatalf("signer called %d times", s.calls())
	}
}

// The home root and filesystem roots are refused as outputs (the core
// writer check is reached through Seal).
func TestSealRefusesHomeRootOutput(t *testing.T) {
	root := t.TempDir()
	capDir, _ := newCapture(t, root, "capture", defaultFixture())
	home := filepath.Join(root, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	req := defaultRequest(capDir, home, seedSigner(t, seedTrusted))
	req.HomeRoot = home
	if _, err := Seal(t.Context(), req); !errors.Is(err, trustfreeze.ErrUnsafeTarget) {
		t.Fatalf("err = %v, want ErrUnsafeTarget", err)
	}
	fsRoot := string(filepath.Separator)
	if runtime.GOOS == "windows" {
		fsRoot = filepath.VolumeName(root) + `\`
	}
	req = defaultRequest(capDir, fsRoot, seedSigner(t, seedTrusted))
	if _, err := Seal(t.Context(), req); err == nil {
		t.Fatal("sealing into the filesystem root succeeded")
	}
}
