// Package registry is the skillctl HTTP client for the aims-core skill
// registry admission API (SPEC-0188 §5).
//
// Stream S7 owns this package: just the client + its data types. The
// admission server (S5) develops in aims-core in parallel, so this client
// is unit-tested against an httptest.Server returning canned fixtures
// matching the published S5 contract:
//
//	GET /api/skills/by-name/<name>
//	    → {"name": "...", "versions": [{...}, ...]}
//	GET /api/skills/bundles/<digest>
//	    → blob octets (Content-Type: application/octet-stream)
//	GET /api/skills/bundles/<digest>?meta=1
//	    → JSON metadata: {"bundle": {...}, "signatures": [...], "manifest": {...}}
//	GET /api/skills/bundles/<digest>/manifest
//	    → bundle.json (parsed)
//	GET /api/skills/identities/<id>
//	    → {"id": "...", "pubkey_b64": "...", "auth_source": "...", "revoked_at": ""}
//
// Field-naming caveat: the S5 brief in PLAN-SPEC-0188-parallel-execution.md
// publishes the response shape but not the exact JSON field spelling. This
// package decodes leniently for both common spellings (`pubkey` vs
// `pubkey_b64`) so a small drift between the brief and what S5 ships
// doesn't block S8. Any drift discovered at integration time is documented
// in the stream report and fixed in a follow-up.
package registry

import "time"

// BundleVersion is one row from a `GET /by-name/<name>` response. The
// shape is defined in SPEC-0188 §5: the registry returns versions
// newest-first, each version carrying enough info for the verifier to
// pick a target without a second roundtrip.
type BundleVersion struct {
	// Version is the human-pickable version string from the bundle's
	// manifest (e.g. "1.0.0"). Not unique on its own; pair with Digest
	// for an immutable handle.
	Version string `json:"version"`

	// Digest is the canonical identifier "sha256:<hex>". The verifier
	// recomputes this from the blob and refuses to install on mismatch
	// (exit code 10).
	Digest string `json:"digest"`

	// AuthorIntent is the bundle's declared `governance_intent`
	// (🟢🟡🔴 self-classification per SPEC-0130). The verifier MUST
	// NOT trust this for the gate decision — only signed governance
	// attestations bind the verdict (SPEC-0188 §7 step 6).
	AuthorIntent string `json:"author_intent,omitempty"`

	// AdmittedAt is when the registry signed its admission attestation.
	// May be zero if the registry didn't include it; UI uses it for
	// sorting only.
	AdmittedAt time.Time `json:"admitted_at,omitempty"`

	// Status is "admitted" | "revoked". Revoked versions still appear
	// in by-name responses for transparency but the verifier refuses
	// to install them.
	Status string `json:"status,omitempty"`
}

// BundleMeta is the JSON envelope returned by
// `GET /api/skills/bundles/<digest>?meta=1`. Field types use `map[string]any`
// for the inner records so this package doesn't need to track every Pydantic
// shape change in `flask/modules/skill_registry/models.py`. Verify-layer
// code in S8 picks out the fields it needs (digest, author identity_id,
// signature_b64, etc.).
type BundleMeta struct {
	// Bundle is the raw BundleRecord JSON document. Includes
	// `bundle_digest`, `name`, `version`, `manifest_ref`, etc.
	Bundle map[string]any `json:"bundle"`

	// Signatures is the list of signature documents attached to this
	// bundle. Each row covers one role (author / registry / governance);
	// see SignatureRow.
	Signatures []SignatureRow `json:"signatures"`

	// Manifest is the parsed bundle.json. Carries `governance_intent`,
	// `depends_on`, `prompts`, etc. Optional; some servers may omit it
	// to save bandwidth and require a separate /manifest fetch.
	Manifest map[string]any `json:"manifest,omitempty"`
}

// SignatureRow is one entry in BundleMeta.Signatures. Mirrors the
// `_skill_signatures` Firestore document shape in compact form. Verify-
// layer code groups by Role to pick out the author signature, registry
// attestation, and (if present) governance attestation.
type SignatureRow struct {
	// Role is "author" | "registry" | "governance". The verifier
	// branches on this — string match must be exact (lowercased on
	// both sides at the verify layer if needed; we don't normalize
	// here so callers see the wire form).
	Role string `json:"role"`

	// IdentityID is the author/reviewer identifier, e.g.
	// `id:kamir@m3c`. Resolves to a public key via GetIdentity.
	IdentityID string `json:"identity_id"`

	// SignatureB64 is base64 of the raw 64-byte ed25519 signature.
	// The verifier base64-decodes once and runs ed25519.Verify against
	// the bundle digest.
	SignatureB64 string `json:"signature_b64"`

	// PubkeyFingerprint, if non-empty, is a hint the registry attaches
	// to make key-rotation triage easier. Not authoritative; verifier
	// always re-fetches the identity and uses its current pubkey.
	PubkeyFingerprint string `json:"pubkey_fingerprint,omitempty"`

	// Status is "active" | "revoked". A revoked signature is kept in
	// the registry for audit; the verifier ignores it.
	Status string `json:"status,omitempty"`
}

// Identity is one row from `GET /api/skills/identities/<id>`. Carries the
// authoritative public key the verifier uses to check author signatures.
//
// Wire-format flexibility: we decode either `pubkey` or `pubkey_b64`
// during JSON unmarshalling (see UnmarshalJSON below) because the S5
// brief and the existing skill_registry models haven't fully aligned on a
// field name. Both forms are accepted; PubkeyB64 is the canonical Go
// field.
type Identity struct {
	// ID is the canonical identity id, e.g. `id:kamir@m3c`. Mirrors
	// the path parameter the GetIdentity caller passed.
	ID string `json:"id"`

	// PubkeyB64 is base64 of the raw 32-byte ed25519 public key.
	PubkeyB64 string `json:"pubkey_b64"`

	// AuthSource is one of "manual" | "github-oidc" | "dsm-sso"
	// (Phase-1 ships only "manual"; the field is a binding contract
	// once OIDC ships). UI displays it; verifier doesn't gate on it.
	AuthSource string `json:"auth_source,omitempty"`

	// RevokedAt, if non-empty, marks the identity as revoked.
	// SPEC-0188 §7 step 4 implies the verifier should refuse signatures
	// from revoked identities; S8 is responsible for that check.
	RevokedAt string `json:"revoked_at,omitempty"`
}

// IsRevoked is the canonical predicate for callers (S8) to decide whether
// an identity is still trusted. A non-empty RevokedAt means revoked; we
// don't compare against time.Now (revocation is binary in v1).
func (i Identity) IsRevoked() bool {
	return i.RevokedAt != ""
}
