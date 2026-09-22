package seal

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
)

// Domain is the Trust Freeze baseline signature domain (SPEC-0470 TF05-R9).
// It is the literal first line of every signed message, following the
// convention of the attestation ("attestation") and revocation ("revoke")
// messages of pkg/skillctl/signing, and it also appears inside the signed
// statement. A test pins the value.
const Domain = "m3c-tools/trust-freeze/baseline/v1"

// Algorithm is the only signature algorithm of trust-freeze/signature/v1.
const Algorithm = "ed25519"

// Canonicalization contract of the signed bytes (SPEC-0470 TF05-R4):
//
//	message = UTF-8(Domain) + "\n" + trustfreeze.MarshalCanonical(statement)
//
// MarshalCanonical is compact JSON with struct fields in declaration order,
// HTML escaping off, no trailing newline, strings only (no floats, no maps in
// the statement). Every time is a trustfreeze.FormatTime string (UTC, RFC 3339
// with nanoseconds, trailing zeros removed). Approval text fields are
// normalized by NormalizeText (CRLF and CR to LF, trimmed). The statement
// holds digests and approval fields only, never a local path; bundle paths
// inside the covered manifest are canonical "/" paths. The signed bytes
// therefore do not depend on map iteration order, the path separator, the
// time zone or time formatting of the host, JSON indentation of any input
// file or the OS line ending.

// Statement is what a baseline signature covers (SPEC-0470 TF05-R4).
// BaselineContentDigest is the content_digest of the baseline manifest, which
// covers every manifested file (approval.json included) and every manifest
// field. CaptureContentDigest is the content_digest of the approved capture.
type Statement struct {
	Domain                string           `json:"domain"`
	SchemaVersion         string           `json:"schema_version"`
	Kind                  trustfreeze.Kind `json:"kind"`
	CaptureContentDigest  string           `json:"capture_content_digest"`
	BaselineContentDigest string           `json:"baseline_content_digest"`
	Approval              Approval         `json:"approval"`
}

// BuildStatement returns the baseline statement for the two digests and the
// approval. Domain, schema id and kind are fixed; Verify rebuilds the
// statement the same way from the files on disk.
func BuildStatement(captureContentDigest, baselineContentDigest string, a Approval) Statement {
	return Statement{
		Domain:                Domain,
		SchemaVersion:         trustfreeze.SchemaBaseline,
		Kind:                  trustfreeze.KindBaseline,
		CaptureContentDigest:  captureContentDigest,
		BaselineContentDigest: baselineContentDigest,
		Approval:              a,
	}
}

// ErrStatementInvalid is wrapped when a statement cannot be encoded or signed.
var ErrStatementInvalid = errors.New("seal: statement is invalid")

// Message returns the signed bytes of s: its domain, one LF, then the
// canonical JSON of s. It only encodes; it does not check that s is a valid
// baseline statement (SignStatement does).
func (s Statement) Message() ([]byte, error) {
	if s.Domain == "" || strings.ContainsAny(s.Domain, "\r\n") {
		return nil, fmt.Errorf("%w: domain must be one non-empty line", ErrStatementInvalid)
	}
	body, err := trustfreeze.MarshalCanonical(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStatementInvalid, err)
	}
	msg := make([]byte, 0, len(s.Domain)+1+len(body))
	msg = append(msg, s.Domain...)
	msg = append(msg, '\n')
	msg = append(msg, body...)
	return msg, nil
}

// StatementSHA256 returns the lowercase hex SHA-256 of a signed message, the
// statement_sha256 of the signature document. It is a diagnostic aid only:
// Verify rebuilds the message and checks the signature over it.
func StatementSHA256(msg []byte) string {
	return trustfreeze.SHA256Hex(msg)
}

// SignatureDoc is signatures/manifest.ed25519.json
// (schema trust-freeze/signature/v1). It carries only public material: the key
// id, the public key and the signature, each base64 in standard encoding.
type SignatureDoc struct {
	SchemaVersion   string `json:"schema_version"`
	Domain          string `json:"domain"`
	Algorithm       string `json:"algorithm"`
	KeyID           string `json:"key_id"`
	PublicKey       string `json:"public_key"`
	Signature       string `json:"signature"`
	StatementSHA256 string `json:"statement_sha256"`
}

// checkStatement verifies that st is a well-formed baseline statement.
func checkStatement(st Statement) error {
	switch {
	case st.Domain != Domain:
		return fmt.Errorf("%w: domain %q, want %q", ErrStatementInvalid, st.Domain, Domain)
	case st.SchemaVersion != trustfreeze.SchemaBaseline:
		return fmt.Errorf("%w: schema_version %q, want %q", ErrStatementInvalid, st.SchemaVersion, trustfreeze.SchemaBaseline)
	case st.Kind != trustfreeze.KindBaseline:
		return fmt.Errorf("%w: kind %q, want %q", ErrStatementInvalid, st.Kind, trustfreeze.KindBaseline)
	case !validDigest(st.CaptureContentDigest):
		return fmt.Errorf("%w: capture_content_digest is not sha256:<64 lowercase hex>", ErrStatementInvalid)
	case !validDigest(st.BaselineContentDigest):
		return fmt.Errorf("%w: baseline_content_digest is not sha256:<64 lowercase hex>", ErrStatementInvalid)
	}
	if err := ValidateApproval(st.Approval); err != nil {
		return err
	}
	if st.Approval.CaptureDigest != st.CaptureContentDigest {
		return fmt.Errorf("%w: approval capture_digest differs from capture_content_digest", ErrStatementInvalid)
	}
	return nil
}

// SignStatement validates st (approval included) and the signer, and only
// then asks the signer for a signature (SPEC-0470 TF05-AC5). The returned
// signature is verified before it is handed out, so a faulty signer cannot
// produce a baseline that would never verify.
func SignStatement(signer Signer, st Statement) (SignatureDoc, error) {
	if err := checkStatement(st); err != nil {
		return SignatureDoc{}, err
	}
	pub, err := checkSigner(signer)
	if err != nil {
		return SignatureDoc{}, err
	}
	if st.Approval.Identities.SigningKeyID != signer.KeyID() {
		return SignatureDoc{}, fmt.Errorf("%w: approval names signing key %q, signer is %q", ErrStatementInvalid, st.Approval.Identities.SigningKeyID, signer.KeyID())
	}
	msg, err := st.Message()
	if err != nil {
		return SignatureDoc{}, err
	}
	sig, err := signer.Sign(msg)
	if err != nil {
		return SignatureDoc{}, fmt.Errorf("seal: sign: %w", err)
	}
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, msg, sig) {
		return SignatureDoc{}, fmt.Errorf("%w: signer returned a signature that does not verify under its own public key", ErrSignerInvalid)
	}
	return SignatureDoc{
		SchemaVersion:   trustfreeze.SchemaSignature,
		Domain:          Domain,
		Algorithm:       Algorithm,
		KeyID:           KeyIDFor(pub),
		PublicKey:       base64.StdEncoding.EncodeToString(pub),
		Signature:       base64.StdEncoding.EncodeToString(sig),
		StatementSHA256: StatementSHA256(msg),
	}, nil
}

// decodedSignature is a signature document whose encodings were checked.
type decodedSignature struct {
	doc SignatureDoc
	pub ed25519.PublicKey
	sig []byte
}

// decodeSignatureDoc parses signature file bytes: canonical file form, known
// schema id and algorithm, strict base64 of the right lengths, a key id that
// belongs to the public key and a well-formed statement_sha256. The domain is
// not checked here, so a caller can report a domain mismatch as such.
func decodeSignatureDoc(b []byte) (decodedSignature, error) {
	var doc SignatureDoc
	if err := trustfreeze.UnmarshalCanonicalFile(b, &doc); err != nil {
		return decodedSignature{}, err
	}
	if err := trustfreeze.CheckSchema(doc.SchemaVersion, trustfreeze.SchemaSignature); err != nil {
		return decodedSignature{}, err
	}
	if doc.Algorithm != Algorithm {
		return decodedSignature{}, fmt.Errorf("algorithm %q, want %q", doc.Algorithm, Algorithm)
	}
	pub, err := decodeB64(doc.PublicKey, ed25519.PublicKeySize)
	if err != nil {
		return decodedSignature{}, fmt.Errorf("public_key: %w", err)
	}
	sig, err := decodeB64(doc.Signature, ed25519.SignatureSize)
	if err != nil {
		return decodedSignature{}, fmt.Errorf("signature: %w", err)
	}
	if doc.KeyID != KeyIDFor(pub) {
		return decodedSignature{}, fmt.Errorf("key_id %q does not belong to public_key (want %q)", doc.KeyID, KeyIDFor(pub))
	}
	if !isLowerHex(doc.StatementSHA256, 64) {
		return decodedSignature{}, errors.New("statement_sha256 is not 64 lowercase hex characters")
	}
	return decodedSignature{doc: doc, pub: ed25519.PublicKey(pub), sig: sig}, nil
}

// decodeB64 decodes strict standard base64 of exactly n bytes and requires
// the input to be the unique encoding of the result (no embedded newlines).
func decodeB64(s string, n int) ([]byte, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, errors.New("not strict standard base64")
	}
	if len(b) != n {
		return nil, fmt.Errorf("decodes to %d bytes, want %d", len(b), n)
	}
	if base64.StdEncoding.EncodeToString(b) != s {
		return nil, errors.New("not the canonical base64 encoding")
	}
	return b, nil
}
