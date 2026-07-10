// Package agentid is the pure, stdlib-only core of the SPEC-0277 agent-instance
// identity layer (Round B). An AgentID is a signed JSON envelope — deliberately
// the same SHAPE as a SPEC-0188 BundleMeta (a payload + a signatures[] array) —
// that binds an agent instance to a key-holding owner and an attenuated
// capability grant. It is verifiable OFFLINE against a pinned owner key, with no
// hosted CA in the verification path (the whole point: self-sovereign, not a
// rival's "owner = an email in a token").
//
// This package owns three things and NOTHING cryptographic that isn't already
// shipped (SPEC-0277 §3 reuse map):
//
//   - the AgentID envelope type (§2 data model);
//   - CanonicalAgentIDBytes — the deterministic, domain-separated signed bytes,
//     modeled byte-for-byte on the shipped CanonicalRevocationBytes pattern
//     (struct marshal, SORTED grant arrays) so signer and verifier agree;
//   - Sign (owner key) / Verify (against a PINNED owner key + expiry check),
//     reusing stdlib ed25519 exactly as verify.stepVerifyAuthor does.
//
// The package is intentionally free of any network, registry, or filesystem
// dependency: it takes raw key material and an envelope, and returns a verdict.
// The CLI (cmd/skillctl/agentid_cmds.go) wires it to the pinned-key machinery in
// pkg/skillctl/verify (the SAME pins that admit bundles).
package agentid

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Domain is the literal first line of the canonical signed message for an
// AgentID. It is the domain separator (SPEC-0277 §2): a signature produced over
// these bytes can NEVER be replayed as a signature under another message family
// — capability_v1 (SPEC-0202 tokens), attestation (SPEC-0188 governance),
// invocation_event_v1 (SPEC-0202 runtime events), revoke (SPEC-0188 revocation),
// or skillctl-revocation-list (SPEC-0276) — even when the SAME key signs both.
// Cross-domain signature reuse against any of those is the explicit red-team
// target; the distinct first line defeats it.
const Domain = "agentid_v1"

// CanonicalType / CanonicalVersion are folded INTO the signed canonical payload
// (mirroring revocationCanonicalV1) so the type+version cannot be reinterpreted
// without re-signing. A future format change is a version bump, not a silent
// reinterpretation.
const (
	CanonicalType    = "skillctl-agentid"
	CanonicalVersion = 1
)

// RoleOwner / RoleApprover / RoleIssuer are the signature roles in signatures[].
//
//   - owner    — the key-holding PLM principal the agent acts ON BEHALF OF
//     (the delegator). REQUIRED. The load-bearing signature.
//   - approver — the SPEC-0277 §11.2 "sign-off human": an independent,
//     accountable human who co-signs. Optional unless a trust-roots policy floor
//     (require_agent_approver) demands it with approver != owner.
//   - issuer   — an optional org/institution countersignature (P2; modeled here
//     so the envelope is forward-compatible, not enforced in P0/P1).
const (
	RoleOwner    = "owner"
	RoleApprover = "approver"
	RoleIssuer   = "issuer"
)

// Grant is the attenuated capability grant (SPEC-0277 §2, SPEC-0196 vocabulary,
// REUSED). It is the set of things the agent MAY do; the runtime gate denies
// anything outside it (fail-closed). The arrays are SORTED + de-duplicated in
// the canonical bytes so signer and verifier agree byte-for-byte regardless of
// input order.
type Grant struct {
	// Skills are the skill references the agent may invoke, e.g.
	// "fetch-contract@>=1.0.0" or a bare skill name. Matching at the gate is by
	// the skill NAME component (the part before '@'); see SkillNames.
	Skills []string `json:"skills"`

	// Intents are the SPEC-0196 capability intents the agent may exercise, e.g.
	// "network:read", "fs:read". Opaque strings; set-membership at the gate.
	Intents []string `json:"intents"`

	// DataScopes are the SPEC-0196 data-scope ids the agent may touch, e.g.
	// "ctx:107677460544181387647___skills". Optional.
	DataScopes []string `json:"data_scopes,omitempty"`

	// Limits are optional hard ceilings (Estonia's actual ask), e.g.
	// {"spend_eur_max": "0"}. Stored as string->string so the canonical bytes
	// are unambiguous (no float formatting drift); keys are sorted in canon.
	Limits map[string]string `json:"limits,omitempty"`
}

// Payload is the signed core of an AgentID (the `agentid` object in §2). Every
// field here is covered by the owner (and approver) signature — tampering any of
// them breaks verification.
type Payload struct {
	// ID is the stable, opaque agent identifier, e.g. "agent:9f2c…" (UUIDv4 or
	// DID-like). It is the key for revocation (RevocationList keyed agent:<id>)
	// and the value stamped into the SPEC-0202 invocation event's agent_identity.
	ID string `json:"id"`

	// Owner is a PLM principal that HOLDS A KEY (not an email string), e.g.
	// "id:kamir@m3c". The owner signature must verify against the key pinned for
	// THIS id in trust-roots.
	Owner string `json:"owner"`

	// DisplayName is a human label, e.g. "ResearchAgent". Cosmetic but signed.
	DisplayName string `json:"display_name,omitempty"`

	// AgentBundleDigest is the FR-0060 signed agent bundle this identity is FOR
	// (OQ-B4), "sha256:<hex>". Optional in P0/P1 — the AgentID references the
	// agent definition, it does not re-implement agent packaging.
	AgentBundleDigest string `json:"agent_bundle_digest,omitempty"`

	// CreatedAt is the RFC3339 UTC issuance time, e.g. "2026-06-22T10:00:00Z".
	CreatedAt string `json:"created_at"`

	// NotAfter is the optional expiry (absent = no expiry), RFC3339 UTC. Verify
	// refuses an AgentID whose NotAfter is in the past with a DISTINCT error
	// (ErrExpired) so the operator can tell "expired" from "bad signature".
	NotAfter string `json:"not_after,omitempty"`

	// TrustRoot is the registry URL this AgentID speaks for, e.g.
	// "https://onboarding.guide/api/skills". Matched against the pinned root.
	TrustRoot string `json:"trust_root,omitempty"`

	// Grant is the attenuated capability grant — what the agent may do.
	Grant Grant `json:"grant"`
}

// Signature is one row in signatures[] (the §2 shape). The signature is over
// CanonicalAgentIDBytes(payload); the verifier resolves the verifying key from
// the PINNED principal whose id == IdentityID (no registry call).
type Signature struct {
	// Role is "owner" | "approver" | "issuer".
	Role string `json:"role"`

	// IdentityID is the principal id, e.g. "id:kamir@m3c". Matched against the
	// pinned-key list for the resolved role.
	IdentityID string `json:"identity_id"`

	// SignatureB64 is base64-std of the raw 64-byte ed25519 signature over the
	// canonical bytes.
	SignatureB64 string `json:"signature_b64"`

	// PubkeyFingerprint, if present, is the advisory "sha256:<hex>" over the raw
	// signing pubkey. UX hint only — verification uses the PINNED key bytes, never
	// this string (a forged fingerprint cannot launder an unpinned key).
	PubkeyFingerprint string `json:"pubkey_fingerprint,omitempty"`
}

// AgentID is the full signed envelope: a payload + a signatures[] array. Same
// shape as a SPEC-0188 BundleMeta so the SPEC-0276 verifier machinery applies
// almost verbatim (§2).
type AgentID struct {
	Payload    Payload     `json:"agentid"`
	Signatures []Signature `json:"signatures"`
}

// grantCanonicalV1 is the deterministic projection of a Grant: sorted, de-duped
// arrays and sorted limit keys. A struct (not a map) so json.Marshal field order
// is fixed.
type grantCanonicalV1 struct {
	Skills     []string    `json:"skills"`
	Intents    []string    `json:"intents"`
	DataScopes []string    `json:"data_scopes"`
	Limits     [][2]string `json:"limits"`
}

// agentIDCanonicalV1 is the deterministic, signed payload. A struct (not a map)
// so json.Marshal field order is fixed; the grant arrays are sorted before
// marshalling so the same logical AgentID always yields the same bytes —
// modeled directly on revocationCanonicalV1 (SPEC-0276).
type agentIDCanonicalV1 struct {
	Type              string           `json:"type"`
	Version           int              `json:"version"`
	ID                string           `json:"id"`
	Owner             string           `json:"owner"`
	DisplayName       string           `json:"display_name"`
	AgentBundleDigest string           `json:"agent_bundle_digest"`
	CreatedAt         string           `json:"created_at"`
	NotAfter          string           `json:"not_after"`
	TrustRoot         string           `json:"trust_root"`
	Grant             grantCanonicalV1 `json:"grant"`
}

// CanonicalAgentIDBytes returns the EXACT bytes that are signed/verified for an
// AgentID. The bytes are the domain-separator line "agentid_v1\n" followed by a
// deterministic JSON marshal of the canonical payload (sorted grant arrays,
// sorted limit keys). The domain prefix is the cross-domain replay guard
// (Domain doc); the sorting + struct-fixed field order make signer and verifier
// agree byte-for-byte regardless of input ordering or whitespace.
//
// Pattern source: verify.CanonicalRevocationBytes + signing.CanonicalizeAttestationMessage
// (domain-separated). NO new crypto — this is a deterministic byte assembler.
func CanonicalAgentIDBytes(p Payload) ([]byte, error) {
	if strings.TrimSpace(p.ID) == "" {
		return nil, errors.New("agentid: id is required")
	}
	if strings.TrimSpace(p.Owner) == "" {
		return nil, errors.New("agentid: owner is required")
	}
	if strings.ContainsAny(p.ID+p.Owner+p.DisplayName+p.AgentBundleDigest+p.CreatedAt+p.NotAfter+p.TrustRoot, "\n\r") {
		// A newline in a signed field could forge the domain-line boundary.
		return nil, errors.New("agentid: payload field contains a newline; refusing to sign ambiguous bytes")
	}

	canon := agentIDCanonicalV1{
		Type:              CanonicalType,
		Version:           CanonicalVersion,
		ID:                strings.TrimSpace(p.ID),
		Owner:             strings.TrimSpace(p.Owner),
		DisplayName:       p.DisplayName,
		AgentBundleDigest: strings.TrimSpace(p.AgentBundleDigest),
		CreatedAt:         strings.TrimSpace(p.CreatedAt),
		NotAfter:          strings.TrimSpace(p.NotAfter),
		TrustRoot:         strings.TrimRight(strings.TrimSpace(p.TrustRoot), "/"),
		Grant:             canonicalGrant(p.Grant),
	}

	body, err := marshalNoHTMLEscape(canon)
	if err != nil {
		return nil, fmt.Errorf("agentid: marshal canonical payload: %w", err)
	}
	out := make([]byte, 0, len(Domain)+1+len(body))
	out = append(out, Domain...)
	out = append(out, '\n')
	out = append(out, body...)
	return out, nil
}

// marshalNoHTMLEscape marshals v to compact JSON WITHOUT Go's default HTML
// escaping of '<', '>', '&'. Those characters appear verbatim in skill version
// constraints (e.g. "fetch-contract@>=1.0.0"); escaping them to > would
// produce uglier, harder-to-cross-language-verify bytes. json.Encoder appends a
// trailing newline, which we trim so the canonical body is exactly the JSON.
func marshalNoHTMLEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// canonicalGrant sorts + de-dups every array in a Grant and sorts the limit keys
// into a deterministic [][2]string so the canonical bytes are stable.
func canonicalGrant(g Grant) grantCanonicalV1 {
	limits := make([][2]string, 0, len(g.Limits))
	for k, v := range g.Limits {
		limits = append(limits, [2]string{k, v})
	}
	sort.Slice(limits, func(i, j int) bool { return limits[i][0] < limits[j][0] })
	return grantCanonicalV1{
		Skills:     sortedDedup(g.Skills),
		Intents:    sortedDedup(g.Intents),
		DataScopes: sortedDedup(g.DataScopes),
		Limits:     limits,
	}
}

// sortedDedup trims, drops empties, de-duplicates and sorts a string slice.
// Returns a NON-nil empty slice so the JSON is "[]" not "null" — a stable shape
// for the golden-bytes test and for cross-language parity.
func sortedDedup(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// Sign produces an owner (or approver) Signature over the canonical bytes of p,
// using the provided ed25519 private key. The caller supplies role + identityID
// (the principal id whose key this is). This is a thin wrapper over ed25519.Sign
// — the stdlib primitive runs in constant time; we add only a length assertion.
//
// Reuse note: this mirrors signing.SignAttestation / SignRevocation exactly; no
// new crypto. The detached signature is base64-std encoded into SignatureB64.
func Sign(p Payload, role, identityID string, priv ed25519.PrivateKey) (Signature, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return Signature{}, fmt.Errorf("agentid: private key is %d bytes, want %d", len(priv), ed25519.PrivateKeySize)
	}
	if role != RoleOwner && role != RoleApprover && role != RoleIssuer {
		return Signature{}, fmt.Errorf("agentid: invalid signature role %q (want owner|approver|issuer)", role)
	}
	if strings.TrimSpace(identityID) == "" {
		return Signature{}, errors.New("agentid: identity_id is required to sign")
	}
	msg, err := CanonicalAgentIDBytes(p)
	if err != nil {
		return Signature{}, err
	}
	sig := ed25519.Sign(priv, msg)
	if len(sig) != ed25519.SignatureSize {
		return Signature{}, fmt.Errorf("agentid: ed25519.Sign returned %d bytes (want %d)", len(sig), ed25519.SignatureSize)
	}
	return Signature{
		Role:              role,
		IdentityID:        strings.TrimSpace(identityID),
		SignatureB64:      base64.StdEncoding.EncodeToString(sig),
		PubkeyFingerprint: PubkeyFingerprint(priv.Public().(ed25519.PublicKey)),
	}, nil
}

// PubkeyFingerprint returns the advisory "sha256:<hex>" fingerprint over the raw
// ed25519 pubkey bytes, matching the derivation used across the trust stack
// (verify.authorFingerprint etc.) so an operator can cross-check it out-of-band.
func PubkeyFingerprint(pub ed25519.PublicKey) string {
	return fingerprint(pub)
}

// FindSignature returns the single Signature row with the given role, or nil if
// there is zero or more than one. >1 is refused upstream (verifyOneRole) — two
// owner signatures is not a configuration to silently pick from.
func (a *AgentID) FindSignature(role string) *Signature {
	if a == nil {
		return nil
	}
	var hit *Signature
	count := 0
	for i := range a.Signatures {
		if a.Signatures[i].Role == role {
			hit = &a.Signatures[i]
			count++
		}
	}
	if count == 1 {
		return hit
	}
	return nil
}

// nowFn is the clock seam so tests can pin "now" for expiry checks without
// dragging time mocking into every caller.
var nowFn = time.Now

// ParseRFC3339UTC parses an RFC3339 timestamp, returning the time in UTC. Empty
// input returns the zero time and no error (an absent not_after = no expiry).
func ParseRFC3339UTC(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("agentid: invalid RFC3339 timestamp %q: %w", s, err)
	}
	return t.UTC(), nil
}
