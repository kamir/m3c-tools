package seal

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
)

// secretPEM returns the PEM PKCS#8 block of a synthetic test key, the text an
// operator gets with `--reason @<private key file>`.
func secretPEM(t *testing.T) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(ed25519.NewKeyFromSeed(seedAttacker))
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// TF05-R8, SPEC-0470 section 4.5: approval text is signed and can never be
// redacted later, so text that the default redaction patterns flag as secret
// material is refused before anything is read or signed, for every free-text
// field.
func TestApprovalRefusesSecretText(t *testing.T) {
	cases := []struct {
		name  string
		field string
		mut   func(*ApprovalInput)
	}{
		{"reason-private-key", "reason", func(in *ApprovalInput) { in.Reason = secretPEM(t) }},
		{"reason-password-pair", "reason", func(in *ApprovalInput) { in.Reason = "ok password=hunter2hunter2" }},
		{"reason-bearer", "reason", func(in *ApprovalInput) {
			in.Reason = "Reviewed.\nAuthorization: Bearer abcdefghijklmnop0123456789"
		}},
		{"change-id-token-url", "change_id", func(in *ApprovalInput) {
			in.ChangeID = "CHG-1 https://t.example/x?token=abcdef0123456789"
		}},
		{"reviewer-github-token", "reviewer", func(in *ApprovalInput) { in.Reviewer = "ghp_abcdefghijklmnopqrstuvwxyz0123" }},
		{"policy-ref-secret", "policy_ref", func(in *ApprovalInput) { in.PolicyRef = "policy api_key=abcdef0123456789" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := ApprovalInput{Reviewer: "bob", ChangeID: "CHG-0001", Reason: "Reviewed the capture."}
			if err := in.Check(); err != nil {
				t.Fatalf("control input rejected: %v", err)
			}
			tc.mut(&in)
			err := in.Check()
			var ae *ApprovalError
			if !errors.As(err, &ae) || !errors.Is(err, ErrApprovalInvalid) || ae.Field != tc.field {
				t.Fatalf("Check() = %v, want an ApprovalError for %s", err, tc.field)
			}
			if strings.Contains(err.Error(), "PRIVATE KEY") || strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "abcdef0123456789") {
				t.Fatalf("the error echoes the secret: %v", err)
			}

			// Seal refuses it before the signer is called; nothing is written.
			root := t.TempDir()
			capDir, _ := newCapture(t, root, "capture", defaultFixture())
			before := treeState(t, capDir)
			s := &countingSigner{Signer: seedSigner(t, seedTrusted)}
			out := filepath.Join(root, "baseline")
			req := defaultRequest(capDir, out, s)
			req.Approval.Reviewer, req.Approval.ChangeID, req.Approval.Reason, req.Approval.PolicyRef = in.Reviewer, in.ChangeID, in.Reason, in.PolicyRef
			if _, err := Seal(t.Context(), req); !errors.As(err, &ae) || ae.Field != tc.field {
				t.Fatalf("Seal: err = %v, want an ApprovalError for %s", err, tc.field)
			}
			if s.calls() != 0 {
				t.Fatalf("signer called %d times", s.calls())
			}
			if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("output exists: %v", err)
			}
			noSiblingsLike(t, root, ".tf-staging-")
			sameTree(t, before, treeState(t, capDir))
		})
	}
}

// TF05-R8 on the verify side: a baseline whose signed approval carries
// secret material (for example from another signer implementation) fails as
// approval_invalid, even when its signature is valid and trusted.
func TestVerifyRejectsSecretInApproval(t *testing.T) {
	for _, field := range []string{"reason", "change_id", "reviewer", "policy_ref", "identities.capture_actor"} {
		t.Run(field, func(t *testing.T) {
			b := newBaseline(t, nil)
			a := readApproval(t, b.dir)
			switch field {
			case "reason":
				a.Reason = strings.TrimSpace(secretPEM(t))
			case "change_id":
				a.ChangeID = "CHG-1 https://t.example/x?token=abcdef0123456789"
			case "reviewer":
				a.Reviewer = "ghp_abcdefghijklmnopqrstuvwxyz0123"
				a.Identities.ReviewerID = a.Reviewer
			case "policy_ref":
				a.PolicyRef = "policy api_key=abcdef0123456789"
			case "identities.capture_actor":
				a.Identities.CaptureActor = "alice session=abcdef0123456789"
			}
			if err := ValidateApproval(a); err == nil {
				t.Fatalf("ValidateApproval accepted secret text in %s", field)
			}
			// Play a signer that skips the check: write the approval, rebuild
			// the manifest and sign the statement bytes directly.
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
			res := Verify(t.Context(), b.dir, testPolicy(b.signer))
			requireExactReasons(t, res, ReasonApprovalInvalid)
		})
	}
}
