package registry

// SPEC-0359 D3(i) — federation via cross-signing.
//
// A GOVERNANCE ROOT key signs a member reviewer's key, so trusting the root
// transitively admits the member as an N-of-M co-attestation signer. The record
// is an envelope-signed map[string]any on the SAME canonical wire as every other
// event (Sign/VerifyEnvelopeSignature unchanged), so this only expands WHICH keys
// are consulted — never how a signature is checked. It carries a hard, signed
// not_after; an expired cross-signature must NOT admit its member (fail-closed).
//
// Trust model (SPEC-0359 §9, confirmed): verified against a PINNED governance root
// ONLY — never a fetched one. Only members admitted this way may contribute to a
// registry's revoke union (D5(b)); a bare-pinned peer's feed is advisory.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CrossSignSchema is the schema_version domain-separator for a cross-signature.
const CrossSignSchema = "m3c-cross-signature/v1"

// CrossSignInput is the typed input for a member cross-signature.
type CrossSignInput struct {
	GovernanceRootFingerprint string    // signing root fingerprint (provenance)
	MemberReviewerID          string    // the admitted member's reviewer identity id
	MemberPubKeyB64           string    // the admitted member's ed25519 pubkey (base64)
	MemberRegistryLocator     string    // optional: the member's registry locator
	IssuedAt                  time.Time // occurred_at
	NotAfter                  time.Time // hard signed expiry (fail-closed)
	TenantScope               *string
}

// BuildMemberCrossSignature builds an UNSIGNED cross-signature record; sign it
// with the GOVERNANCE ROOT private key via SignEnvelopeSignature.
func BuildMemberCrossSignature(in CrossSignInput) (map[string]any, error) {
	if strings.TrimSpace(in.MemberReviewerID) == "" {
		return nil, fmt.Errorf("%w: member_reviewer_id required", ErrInvalidEvent)
	}
	pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(in.MemberPubKeyB64))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: member_root_pubkey_b64 invalid", ErrInvalidEvent)
	}
	if in.NotAfter.IsZero() {
		return nil, fmt.Errorf("%w: not_after required (a cross-signature must expire)", ErrInvalidEvent)
	}
	return map[string]any{
		"schema_version":              CrossSignSchema,
		"event_id":                    newEventID(),
		"occurred_at":                 rfc3339(in.IssuedAt),
		"governance_root_fingerprint": in.GovernanceRootFingerprint,
		"member_reviewer_id":          in.MemberReviewerID,
		"member_root_pubkey_b64":      in.MemberPubKeyB64,
		"member_registry_locator":     in.MemberRegistryLocator,
		"not_after":                   rfc3339(in.NotAfter),
		"tenant_scope":                derefOrNil(in.TenantScope),
	}, nil
}

// VerifyCrossSignature verifies a cross-signature against the PINNED governance
// root public key and returns the admitted member Signer. It FAILS CLOSED when:
// the schema is wrong, the envelope signature does not verify against the pinned
// root, not_after is absent/unparseable, or now is not before not_after (expired).
func VerifyCrossSignature(governanceRootPub ed25519.PublicKey, ev map[string]any, now time.Time) (Signer, error) {
	if s, _ := ev["schema_version"].(string); s != CrossSignSchema {
		return Signer{}, fmt.Errorf("cross-sign: wrong schema_version %q", s)
	}
	if err := VerifyEnvelopeSignature(governanceRootPub, ev); err != nil {
		return Signer{}, fmt.Errorf("cross-sign: not signed by the pinned governance root: %w", err)
	}
	naRaw, _ := ev["not_after"].(string)
	if naRaw == "" {
		return Signer{}, fmt.Errorf("cross-sign: no not_after (a cross-signature must expire)")
	}
	na, err := time.Parse(time.RFC3339, naRaw)
	if err != nil || !now.Before(na) {
		return Signer{}, fmt.Errorf("cross-sign: expired or unparseable not_after %q", naRaw)
	}
	rid, _ := ev["member_reviewer_id"].(string)
	b64, _ := ev["member_root_pubkey_b64"].(string)
	pub, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if rid == "" || derr != nil || len(pub) != ed25519.PublicKeySize {
		return Signer{}, fmt.Errorf("cross-sign: invalid member identity/key")
	}
	return Signer{ReviewerID: rid, PubKeyB64: b64, pub: ed25519.PublicKey(pub)}, nil
}

// DeriveCrossSignedSigners returns the member signers admitted by verified,
// unexpired cross-signatures from the pinned governance root. Invalid/expired
// records are silently dropped (fail-closed — they simply do not admit a member).
func DeriveCrossSignedSigners(governanceRootPub ed25519.PublicKey, records []map[string]any, now time.Time) []Signer {
	var out []Signer
	for _, ev := range records {
		if s, err := VerifyCrossSignature(governanceRootPub, ev, now); err == nil {
			out = append(out, s)
		}
	}
	return out
}

// loadCrossSignRecords reads cross-signature records from a path: a directory of
// *.json files (one record each, or a JSON array), or a single JSON file.
func loadCrossSignRecords(path string) ([]map[string]any, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	var files []string
	if fi.IsDir() {
		ents, rerr := os.ReadDir(path)
		if rerr != nil {
			return nil, rerr
		}
		for _, e := range ents {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
				files = append(files, filepath.Join(path, e.Name()))
			}
		}
	} else {
		files = []string{path}
	}
	var out []map[string]any
	for _, f := range files {
		data, rerr := os.ReadFile(f)
		if rerr != nil {
			return nil, rerr
		}
		var one map[string]any
		if json.Unmarshal(data, &one) == nil && len(one) > 0 {
			out = append(out, one)
			continue
		}
		var many []map[string]any
		if json.Unmarshal(data, &many) == nil {
			out = append(out, many...)
		}
	}
	return out, nil
}
