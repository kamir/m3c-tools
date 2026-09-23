package seal

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
)

// resignApproval plays a forger who holds the reviewer's key: it writes
// approval a into the baseline, rebuilds the manifest and signs the new
// statement, so integrity, signature and key trust all hold again.
func resignApproval(t *testing.T, b sealed, a Approval) {
	t.Helper()
	writeJSONFile(t, b.dir, trustfreeze.ApprovalFile, a)
	m := readManifest(t, b.dir)
	refreshEntry(t, b.dir, &m, trustfreeze.ApprovalFile)
	writeManifest(t, b.dir, m, true)
	m = readManifest(t, b.dir)
	msg, err := BuildStatement(a.CaptureDigest, m.ContentDigest, a).Message()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := b.signer.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	pub := b.signer.PublicKey()
	writeSig(t, b.dir, SignatureDoc{
		SchemaVersion: trustfreeze.SchemaSignature, Domain: Domain, Algorithm: Algorithm,
		KeyID: KeyIDFor(pub), PublicKey: base64.StdEncoding.EncodeToString(pub),
		Signature: base64.StdEncoding.EncodeToString(sig), StatementSHA256: StatementSHA256(msg),
	})
}

// O-1, SPEC-0470 section 4.4: verify recomputes the capture digest from the
// baseline's own files and capture.json and refuses an approval whose
// capture_digest names another capture, even when the forged approval is
// signed by a trusted key.
func TestVerifyRecomputesCaptureDigest(t *testing.T) {
	b := newBaseline(t, nil)
	requireOK(t, Verify(t.Context(), b.dir, testPolicy(b.signer)))

	a := readApproval(t, b.dir)
	a.CaptureDigest = "sha256:" + strings.Repeat("ab", 32)
	resignApproval(t, b, a)
	res := Verify(t.Context(), b.dir, testPolicy(b.signer))
	if !res.SignatureValid || !res.KeyTrusted {
		t.Fatalf("fixture error: the forgery must be cryptographically valid: %s", describe(res))
	}
	requireExactReasons(t, res, Reason("capture_digest_mismatch"))

	// Restoring the true digest makes the same bundle pass again.
	a.CaptureDigest = b.result.CaptureDigest
	resignApproval(t, b, a)
	requireOK(t, Verify(t.Context(), b.dir, testPolicy(b.signer)))
}

// O-2: an approval dated after the policy clock's now is refused
// (approved_in_future); at and after approved_at it verifies. The cases sit
// one nanosecond apart, so the policy here disables the clock-skew tolerance
// (ClockSkew(0)); the boundaries of the tolerance itself, including the
// default one, are TestVerifyClockSkewDefaultApprovedAt.
func TestVerifyRejectsApprovalFromTheFuture(t *testing.T) {
	b := newBaseline(t, nil)
	cases := []struct {
		name string
		now  time.Time
		want Reason
	}{
		{"one nanosecond before approved_at", approveTime.Add(-time.Nanosecond), Reason("approved_in_future")},
		{"a day before approved_at", approveTime.Add(-24 * time.Hour), Reason("approved_in_future")},
		{"at approved_at", approveTime, ""},
		{"one nanosecond after approved_at", approveTime.Add(time.Nanosecond), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := testPolicy(b.signer)
			p.Now = trustfreeze.FixedClock{T: tc.now}
			p.MaxClockSkew = ClockSkew(0)
			res := Verify(t.Context(), b.dir, p)
			if tc.want == "" {
				requireOK(t, res)
				return
			}
			requireExactReasons(t, res, tc.want)
		})
	}
}

// Identifier test values. The good ones span the whole allowed charset.
var (
	goodIdentifiers = []string{"alice", "id:alice@example", "CHG-0001", "a.b_c-d@e+f:g", "Az09._-@+:", strings.Repeat("a", 128)}
	badIdentifiers  = []string{"Alice Smith", "corp/alice", "b\u00f8b", strings.Repeat("a", 129), "#1234", "a=b", "alice;x", `a\b`, `"q"`, "a,b", "(alice)", "alice\u200b"}
)

// O-3, SPEC-0470 section 4.2: reviewer and change_id are 1 to 128 ASCII
// letters, digits and ._-@+: and anything else is refused before anything is
// read or signed.
func TestApprovalInputIdentifiersCharset(t *testing.T) {
	for _, field := range []string{"reviewer", "change_id"} {
		set := func(in *ApprovalInput, v string) {
			if field == "reviewer" {
				in.Reviewer = v
			} else {
				in.ChangeID = v
			}
		}
		for _, v := range goodIdentifiers {
			in := ApprovalInput{Reviewer: "bob", ChangeID: "CHG-0001", Reason: "Reviewed."}
			set(&in, v)
			if err := in.Check(); err != nil {
				t.Errorf("%s %q refused: %v", field, v, err)
			}
		}
		for _, v := range badIdentifiers {
			in := ApprovalInput{Reviewer: "bob", ChangeID: "CHG-0001", Reason: "Reviewed."}
			set(&in, v)
			var ae *ApprovalError
			if err := in.Check(); !errors.As(err, &ae) || ae.Field != field {
				t.Errorf("%s %q: Check() = %v, want an ApprovalError for %s", field, v, err, field)
			}
		}
	}

	// Seal refuses before the signer is called; nothing is written.
	root := t.TempDir()
	capDir, _ := newCapture(t, root, "capture", defaultFixture())
	before := treeState(t, capDir)
	s := &countingSigner{Signer: seedSigner(t, seedTrusted)}
	out := filepath.Join(root, "baseline")
	req := defaultRequest(capDir, out, s)
	req.Approval.Reviewer = "Alice Smith"
	var ae *ApprovalError
	if _, err := Seal(t.Context(), req); !errors.As(err, &ae) || ae.Field != "reviewer" {
		t.Fatalf("Seal: err = %v, want an ApprovalError for reviewer", err)
	}
	if s.calls() != 0 {
		t.Fatalf("signer called %d times", s.calls())
	}
	if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("output exists: %v", err)
	}
	sameTree(t, before, treeState(t, capDir))
}

// O-3 on the document side: ValidateApproval (which Verify runs) applies the
// same charset to reviewer, change_id, identities.reviewer_id and
// identities.capture_actor, so a baseline from a signer that skipped the
// check fails as approval_invalid.
func TestValidateApprovalIdentifiersCharset(t *testing.T) {
	b := newBaseline(t, nil)
	base := readApproval(t, b.dir)
	if err := ValidateApproval(base); err != nil {
		t.Fatalf("control: %v", err)
	}
	fields := map[string]func(*Approval, string){
		"reviewer":                 func(a *Approval, v string) { a.Reviewer, a.Identities.ReviewerID = v, v },
		"change_id":                func(a *Approval, v string) { a.ChangeID = v },
		"identities.reviewer_id":   func(a *Approval, v string) { a.Identities.ReviewerID = v },
		"identities.capture_actor": func(a *Approval, v string) { a.Identities.CaptureActor = v },
	}
	for field, set := range fields {
		for _, v := range goodIdentifiers {
			a := base
			set(&a, v)
			if err := ValidateApproval(a); err != nil {
				t.Errorf("%s %q refused: %v", field, v, err)
			}
		}
		for _, v := range badIdentifiers {
			a := base
			set(&a, v)
			var ae *ApprovalError
			if err := ValidateApproval(a); !errors.As(err, &ae) || ae.Field != field {
				t.Errorf("%s %q: ValidateApproval = %v, want an ApprovalError for %s", field, v, err, field)
			}
		}
	}

	a := base
	a.Reviewer, a.Identities.ReviewerID = "Alice Smith", "Alice Smith"
	resignApproval(t, b, a)
	requireExactReasons(t, Verify(t.Context(), b.dir, testPolicy(b.signer)), ReasonApprovalInvalid)
}
