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
	// `bundle_digest`, `name`, `version`, `manifest_ref`, `status`
	// ("admitted"|"revoked"), etc.
	Bundle map[string]any `json:"bundle"`

	// Signatures is the list of signature documents attached to this
	// bundle. Each row covers one role (author / registry / governance);
	// see SignatureRow.
	Signatures []SignatureRow `json:"signatures"`

	// Manifest is the parsed bundle.json. Carries `governance_intent`,
	// `depends_on`, `prompts`, etc. Optional; some servers may omit it
	// to save bandwidth and require a separate /manifest fetch.
	Manifest map[string]any `json:"manifest,omitempty"`

	// Attestations is the list of governance attestations attached to the
	// bundle, newest-first per the S5 contract. Stream S8 (verifier) uses
	// these for forensic logging / chain summaries; the binding governance
	// verdict the verifier gates on lives in CurrentGovernance, computed
	// server-side from the same data so the client doesn't reimplement
	// "newest by reviewer role" tie-breaking.
	//
	// Optional on the wire. Older / stub registries may omit it; in that
	// case verifier code falls back to CurrentGovernance == "" → red
	// (fail-closed, see SPEC-0188 §7 step 6).
	Attestations []AttestationRow `json:"attestations,omitempty"`

	// CurrentGovernance is the binding 🟢/🟡/🔴 verdict for this bundle
	// per SPEC-0188 §4.3 ("the most-recent signed governance attestation
	// by a reviewer with the required role"). One of "green" | "yellow" |
	// "red"; empty string means the registry didn't compute it (treat as
	// "red" / below-minimum — fail-closed).
	//
	// The verifier MUST gate on this field (and NOT on Manifest's
	// `author_governance_intent` per SPEC-0188 §3.2 + §7 step 6).
	CurrentGovernance string `json:"current_governance,omitempty"`
}

// AttestationRow is one entry in BundleMeta.Attestations. Mirrors the
// `_skill_attestations` Firestore document shape in compact form.
//
// In v1 the verifier does NOT independently re-verify each governance
// signature — it gates on BundleMeta.CurrentGovernance, which the registry
// computed by validating attestations server-side. Attestations are kept
// here so verbose chain summaries can show "which reviewer signed which
// level when." A future tightening could drop the trust in the registry
// and re-verify each attestation against the reviewer's identity pubkey;
// SPEC-0188 §7 step 6 explicitly leaves room for that.
type AttestationRow struct {
	// AttestationID is the registry-assigned id of this attestation,
	// e.g. `att:01H…`. Surface only — used in chain summaries / audit
	// trails, never matched against signature material.
	AttestationID string `json:"attestation_id,omitempty"`

	// Level is the governance verdict: "green" | "yellow" | "red".
	Level string `json:"level"`

	// ReviewerID is the identity that signed the attestation, e.g.
	// `id:reviewer@m3c`. Resolves to a public key via GetIdentity if a
	// future verifier mode wants to re-check signatures.
	ReviewerID string `json:"reviewer_id"`

	// AttestedAt is the RFC3339 UTC timestamp the reviewer signed at.
	// Carried verbatim from the registry; "newest-first" ordering is
	// the registry's responsibility.
	AttestedAt string `json:"attested_at,omitempty"`

	// Rationale is the reviewer's free-text justification (advisory;
	// never folded into the signed bytes per SPEC §4.3).
	Rationale string `json:"rationale,omitempty"`

	// SignatureB64 is base64 of the raw 64-byte ed25519 signature over
	// the canonical attestation message (see `signing.CanonicalizeAttestationMessage`).
	// Optional in v1; empty means the registry didn't surface it (we
	// gate on CurrentGovernance, so we don't refuse-on-empty here).
	SignatureB64 string `json:"signature_b64,omitempty"`

	// Status is "active" | "revoked". A revoked attestation is kept in
	// the registry for audit; the registry's CurrentGovernance computation
	// already excludes revoked rows, so this is informational.
	Status string `json:"status,omitempty"`

	// TenantScope, when non-empty, scopes this attestation to a specific
	// tenant id (e.g. "kup-berlin"). Per SPEC-0188 §7 step 5.5 (G-18 closure,
	// 2026-05-06) the verifier consults tenant-scoped attestations to allow
	// a tenant CISO to block an otherwise-trusted bundle for THAT tenant
	// without affecting other tenants. An empty TenantScope means the
	// attestation is global / untenanted; the tenant-block step ignores
	// global rows.
	TenantScope string `json:"tenant_scope,omitempty"`
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
