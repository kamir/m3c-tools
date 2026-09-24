package seal

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
)

// TF05-R9: the domain is fixed by SPEC-0470 and pinned here.
func TestDomainPinned(t *testing.T) {
	if Domain != "m3c-tools/trust-freeze/baseline/v1" {
		t.Fatalf("Domain = %q", Domain)
	}
	if Algorithm != "ed25519" {
		t.Fatalf("Algorithm = %q", Algorithm)
	}
	msg, err := BuildStatement(fixedDigest("a"), fixedDigest("b"), fixedApproval()).Message()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(msg, []byte("m3c-tools/trust-freeze/baseline/v1\n{")) {
		t.Fatalf("message does not start with the domain line: %q", msg[:48])
	}
}

func fixedDigest(c string) string { return "sha256:" + strings.Repeat(c, 64) }

func fixedApproval() Approval {
	return Approval{
		SchemaVersion: trustfreeze.SchemaApproval,
		Reviewer:      "bob",
		ChangeID:      "CHG-0001",
		Reason:        "Line <one> & fine.\nLine two.",
		ApprovedAt:    "2026-01-02T04:04:05Z",
		CaptureDigest: fixedDigest("a"),
		Identities: Identities{
			CapturedSubjectID: "device/0123456789abcdef",
			CaptureActor:      "alice",
			ReviewerID:        "bob",
			SigningKeyID:      "ed25519:0123456789abcdef",
			SigningDeviceID:   "device/fedcba9876543210",
		},
	}
}

// TF05-R4: the canonicalization contract pinned byte for byte: domain line,
// LF, compact JSON in declaration order, no HTML escaping, JSON string
// escapes for LF, optional empty fields omitted, no trailing newline.
func TestSignedMessageBytesPinned(t *testing.T) {
	msg, err := BuildStatement(fixedDigest("a"), fixedDigest("b"), fixedApproval()).Message()
	if err != nil {
		t.Fatal(err)
	}
	want := "m3c-tools/trust-freeze/baseline/v1\n" +
		`{"domain":"m3c-tools/trust-freeze/baseline/v1","schema_version":"trust-freeze/baseline/v1","kind":"baseline",` +
		`"capture_content_digest":"` + fixedDigest("a") + `","baseline_content_digest":"` + fixedDigest("b") + `",` +
		`"approval":{"schema_version":"trust-freeze/approval/v1","reviewer":"bob","change_id":"CHG-0001",` +
		`"reason":"Line <one> & fine.\nLine two.","approved_at":"2026-01-02T04:04:05Z","capture_digest":"` + fixedDigest("a") + `",` +
		`"identities":{"captured_subject_id":"device/0123456789abcdef","capture_actor":"alice","reviewer_id":"bob",` +
		`"signing_key_id":"ed25519:0123456789abcdef","signing_device_id":"device/fedcba9876543210"}}}`
	if string(msg) != want {
		t.Fatalf("signed bytes changed\n got: %s\nwant: %s", msg, want)
	}
	if StatementSHA256(msg) != trustfreeze.SHA256Hex([]byte(want)) {
		t.Fatal("statement_sha256 is not the SHA-256 of the signed bytes")
	}
}

func TestStatementMessageRejectsBadDomain(t *testing.T) {
	for _, d := range []string{"", "m3c-tools/trust-freeze/baseline/v1\nx", "a\rb"} {
		st := BuildStatement(fixedDigest("a"), fixedDigest("b"), fixedApproval())
		st.Domain = d
		if _, err := st.Message(); !errors.Is(err, ErrStatementInvalid) {
			t.Fatalf("domain %q: err = %v", d, err)
		}
	}
}

// TF05-AC5 at the signing boundary: SignStatement validates the statement
// and the approval before the signer is invoked.
func TestSignStatementValidatesBeforeSigning(t *testing.T) {
	s := seedSigner(t, seedTrusted)
	valid := func() Statement {
		a := fixedApproval()
		a.Identities.SigningKeyID = s.KeyID()
		return BuildStatement(fixedDigest("a"), fixedDigest("b"), a)
	}
	cases := []struct {
		name  string
		mut   func(*Statement)
		field string
	}{
		{"reviewer-missing", func(st *Statement) { st.Approval.Reviewer = "" }, "reviewer"},
		{"reviewer-whitespace", func(st *Statement) { st.Approval.Reviewer = "  " }, "reviewer"},
		{"change-id-missing", func(st *Statement) { st.Approval.ChangeID = "" }, "change_id"},
		{"change-id-whitespace", func(st *Statement) { st.Approval.ChangeID = "\t" }, "change_id"},
		{"reason-missing", func(st *Statement) { st.Approval.Reason = "" }, "reason"},
		{"reason-whitespace", func(st *Statement) { st.Approval.Reason = "\n \n" }, "reason"},
		{"approved-at-missing", func(st *Statement) { st.Approval.ApprovedAt = "" }, "approved_at"},
		{"approved-at-zero", func(st *Statement) { st.Approval.ApprovedAt = "0001-01-01T00:00:00Z" }, "approved_at"},
		{"approved-at-offset", func(st *Statement) { st.Approval.ApprovedAt = "2026-01-02T05:04:05+01:00" }, "approved_at"},
		{"capture-digest-missing", func(st *Statement) { st.Approval.CaptureDigest = "" }, "capture_digest"},
		{"capture-digest-whitespace", func(st *Statement) { st.Approval.CaptureDigest = " " }, "capture_digest"},
		{"capture-digest-uppercase", func(st *Statement) {
			st.Approval.CaptureDigest = "sha256:" + strings.Repeat("A", 64)
		}, "capture_digest"},
		{"schema-wrong", func(st *Statement) { st.Approval.SchemaVersion = trustfreeze.SchemaCapture }, "schema_version"},
		{"reviewer-id-missing", func(st *Statement) { st.Approval.Identities.ReviewerID = "" }, "identities.reviewer_id"},
		{"subject-missing", func(st *Statement) { st.Approval.Identities.CapturedSubjectID = "" }, "identities.captured_subject_id"},
		{"key-id-malformed", func(st *Statement) { st.Approval.Identities.SigningKeyID = "device:0123456789abcdef" }, "identities.signing_key_id"},
		{"reason-with-cr", func(st *Statement) { st.Approval.Reason = "a\r\nb" }, "reason"},
		{"reviewer-control-char", func(st *Statement) { st.Approval.Reviewer = "bob\x00" }, "reviewer"},
		{"expires-not-after-approval", func(st *Statement) { st.Approval.ExpiresAt = st.Approval.ApprovedAt }, "expires_at"},
		{"policy-ref-multiline", func(st *Statement) { st.Approval.PolicyRef = "a\nb" }, "policy_ref"},
		{"policy-ref-unix-path", func(st *Statement) { st.Approval.PolicyRef = "/home/alice/policy.yaml" }, "policy_ref"},
		{"policy-ref-windows-path", func(st *Statement) { st.Approval.PolicyRef = `C:\Users\alice\policy.yaml` }, "policy_ref"},
		{"policy-ref-backslash", func(st *Statement) { st.Approval.PolicyRef = `policies\default` }, "policy_ref"},
		{"domain-wrong", func(st *Statement) { st.Domain = "attestation" }, ""},
		{"kind-capture", func(st *Statement) { st.Kind = trustfreeze.KindCapture }, ""},
		{"schema-capture", func(st *Statement) { st.SchemaVersion = trustfreeze.SchemaCapture }, ""},
		{"baseline-digest-malformed", func(st *Statement) { st.BaselineContentDigest = "sha256:xyz" }, ""},
		{"capture-digest-differs", func(st *Statement) { st.CaptureContentDigest = fixedDigest("c") }, ""},
		{"approval-names-other-key", func(st *Statement) { st.Approval.Identities.SigningKeyID = "ed25519:0123456789abcdef" }, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cs := &countingSigner{Signer: s}
			st := valid()
			tc.mut(&st)
			_, err := SignStatement(cs, st)
			if err == nil {
				t.Fatal("SignStatement accepted an invalid statement")
			}
			if cs.calls() != 0 {
				t.Fatalf("signer invoked %d times", cs.calls())
			}
			if tc.field != "" {
				var ae *ApprovalError
				if !errors.As(err, &ae) || ae.Field != tc.field {
					t.Fatalf("err = %v, want approval field %q", err, tc.field)
				}
			}
		})
	}
	cs := &countingSigner{Signer: s}
	if _, err := SignStatement(cs, valid()); err != nil || cs.calls() != 1 {
		t.Fatalf("valid statement: err = %v, calls = %d", err, cs.calls())
	}
	withRef := valid()
	withRef.Approval.PolicyRef = "trust-freeze/policy/default-v0"
	if _, err := SignStatement(s, withRef); err != nil {
		t.Fatalf("policy id as policy_ref: %v", err)
	}
}

// sealMessage seals with req and returns the signed message (rebuilt from
// the result) and the signature document.
func sealMessage(t *testing.T, req SealRequest) ([]byte, SignatureDoc) {
	t.Helper()
	res, err := Seal(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := BuildStatement(res.CaptureDigest, res.ContentDigest, res.Approval).Message()
	if err != nil {
		t.Fatal(err)
	}
	if StatementSHA256(msg) != res.Signature.StatementSHA256 {
		t.Fatal("result signature does not cover the rebuilt statement")
	}
	return msg, res.Signature
}

func requireSameSigned(t *testing.T, name string, refMsg []byte, refSig SignatureDoc, msg []byte, sig SignatureDoc) {
	t.Helper()
	if !bytes.Equal(refMsg, msg) {
		t.Fatalf("%s: signed bytes differ\nref: %s\ngot: %s", name, refMsg, msg)
	}
	// ed25519 is deterministic: equal messages give equal signatures.
	if refSig != sig {
		t.Fatalf("%s: signature documents differ", name)
	}
}

// TF05-R4: the signed bytes do not depend on OS line endings, path
// separators or path spelling, JSON indentation or key order of input files,
// time zone or formatting of equivalent instants, or map insertion order.
func TestSignedBytesInvariant(t *testing.T) {
	s := seedSigner(t, seedTrusted)

	t.Run("approval-json-line-endings-indentation-key-order", func(t *testing.T) {
		b := newBaseline(t, nil)
		m := readManifest(t, b.dir)
		ref := readApproval(t, b.dir)
		refMsg, err := BuildStatement(ref.CaptureDigest, m.ContentDigest, ref).Message()
		if err != nil {
			t.Fatal(err)
		}
		canonicalFile := readRaw(t, b.dir, trustfreeze.ApprovalFile)
		compact, _ := trustfreeze.MarshalCanonical(ref)
		fourSpaces, _ := json.MarshalIndent(ref, "", "    ")
		tabs, _ := json.MarshalIndent(ref, "", "\t")
		var generic map[string]any
		if err := json.Unmarshal(canonicalFile, &generic); err != nil {
			t.Fatal(err)
		}
		sortedKeys, _ := json.Marshal(generic) // alphabetical key order
		variants := map[string][]byte{
			"canonical-lf":     canonicalFile,
			"canonical-crlf":   bytes.ReplaceAll(canonicalFile, []byte("\n"), []byte("\r\n")),
			"compact":          compact,
			"four-spaces":      fourSpaces,
			"tabs-crlf":        bytes.ReplaceAll(tabs, []byte("\n"), []byte("\r\n")),
			"alphabetical":     sortedKeys,
			"trailing-newline": append(append([]byte{}, compact...), '\n', '\n'),
		}
		if bytes.Equal(sortedKeys, compact) {
			t.Fatal("setup: alphabetical variant equals the declaration-order variant")
		}
		for name, raw := range variants {
			a, err := ParseApproval(raw)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			msg, err := BuildStatement(a.CaptureDigest, m.ContentDigest, a).Message()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(msg, refMsg) {
				t.Fatalf("%s: signed bytes differ", name)
			}
		}
	})

	t.Run("reason-line-endings", func(t *testing.T) {
		ref := ApprovalInput{Reviewer: "bob", ChangeID: "CHG-1", Reason: "Line one.\nLine two."}
		refA, err := NewApproval(ref, approveTime, CaptureRef{ContentDigest: fixedDigest("a"), SubjectID: "device/0123456789abcdef"}, s.KeyID())
		if err != nil {
			t.Fatal(err)
		}
		refMsg, _ := BuildStatement(fixedDigest("a"), fixedDigest("b"), refA).Message()
		for _, reason := range []string{"Line one.\r\nLine two.\r\n", "\r\nLine one.\rLine two.  ", " Line one.\nLine two.\n\n"} {
			in := ref
			in.Reason = reason
			in.Reviewer = " bob\r\n"
			a, err := NewApproval(in, approveTime, CaptureRef{ContentDigest: fixedDigest("a"), SubjectID: "device/0123456789abcdef"}, s.KeyID())
			if err != nil {
				t.Fatal(err)
			}
			msg, _ := BuildStatement(fixedDigest("a"), fixedDigest("b"), a).Message()
			if !bytes.Equal(msg, refMsg) {
				t.Fatalf("reason %q: signed bytes differ", reason)
			}
		}
	})

	t.Run("time-zone-and-format", func(t *testing.T) {
		root := t.TempDir()
		capDir, _ := newCapture(t, root, "capture", defaultFixture())
		expires := approveTime.Add(48 * time.Hour)
		zones := []*time.Location{time.UTC, time.FixedZone("plus-0530", 5*3600+1800), time.FixedZone("minus-0800", -8*3600)}
		var refMsg []byte
		var refSig SignatureDoc
		for i, loc := range zones {
			req := defaultRequest(capDir, filepath.Join(root, "baseline-"+loc.String()), s)
			req.Clock = trustfreeze.FixedClock{T: approveTime.In(loc)}
			req.Approval.ExpiresAt = expires.In(zones[len(zones)-1-i])
			msg, sig := sealMessage(t, req)
			if i == 0 {
				refMsg, refSig = msg, sig
				continue
			}
			requireSameSigned(t, loc.String(), refMsg, refSig, msg, sig)
		}
	})

	t.Run("path-separators-and-spelling", func(t *testing.T) {
		root := t.TempDir()
		capDir, _ := newCapture(t, root, "capture", defaultFixture())
		if err := os.Mkdir(filepath.Join(root, "sub"), 0o700); err != nil {
			t.Fatal(err)
		}
		sep := string(filepath.Separator)
		spellings := map[string]string{
			"plain":             capDir,
			"trailing-sep":      capDir + sep,
			"dot-segment":       root + sep + "." + sep + "capture",
			"dotdot-segment":    root + sep + "sub" + sep + ".." + sep + "capture",
			"double-separator":  root + sep + sep + "capture",
			"forward-slashes":   filepath.ToSlash(capDir),
			"native-separators": filepath.FromSlash(capDir),
		}
		refMsg, refSig := sealMessage(t, defaultRequest(capDir, filepath.Join(root, "ref"), s))
		i := 0
		for name, spelled := range spellings {
			i++
			out := root + sep + "out" + sep + ".." + sep + "baseline-" + name
			if runtime.GOOS == "windows" {
				out = filepath.ToSlash(out)
			}
			msg, sig := sealMessage(t, defaultRequest(spelled, out, s))
			requireSameSigned(t, name, refMsg, refSig, msg, sig)
		}
		t.Run("relative", func(t *testing.T) {
			t.Chdir(root)
			msg, sig := sealMessage(t, defaultRequest("capture", "baseline-relative", s))
			requireSameSigned(t, "relative", refMsg, refSig, msg, sig)
		})
		if bytes.Contains(refMsg, []byte(root)) || bytes.Contains(refMsg, []byte(filepath.ToSlash(root))) {
			t.Fatal("the signed bytes contain a local path")
		}
		if bytes.Contains(refMsg, []byte(`\\`)) {
			t.Fatal("the signed bytes contain a backslash")
		}
		// A manifest built on Windows lists the same canonical entries.
		for _, f := range readManifest(t, filepath.Join(root, "ref")).Files {
			c, err := trustfreeze.CanonicalPath(strings.ReplaceAll(f.Path, "/", `\`))
			if err != nil || c != f.Path {
				t.Fatalf("CanonicalPath(backslash form of %s) = %q, %v", f.Path, c, err)
			}
		}
	})

	t.Run("map-insertion-order", func(t *testing.T) {
		root := t.TempDir()
		fwd := defaultFixture()
		rev := defaultFixture()
		rev.reverseMaps = true
		capA, mA := newCapture(t, root, "capture-forward", fwd)
		capB, mB := newCapture(t, root, "capture-reverse", rev)
		if mA.ContentDigest != mB.ContentDigest {
			t.Fatal("capture content digest depends on map insertion order")
		}
		refMsg, refSig := sealMessage(t, defaultRequest(capA, filepath.Join(root, "baseline-forward"), s))
		for i := 0; i < 5; i++ {
			msg, sig := sealMessage(t, defaultRequest(capB, filepath.Join(root, "baseline-reverse-"+string(rune('a'+i))), s))
			requireSameSigned(t, "reverse", refMsg, refSig, msg, sig)
		}
	})
}
