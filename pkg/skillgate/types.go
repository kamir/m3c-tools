// Package skillgate is the cooperative invocation gateway for SPEC-0202
// capability tokens. It mirrors the Python reference implementation in
// aims-core/flask/modules/skill_registry/capability_tokens.py.
//
// The gateway is COOPERATIVE: it pre-checks subprocess / egress / capability
// requests against the envelope baked into a verified token, refuses any
// request that escapes the envelope, and posts an audit event. It does not
// sandbox forcibly — the wrapped binary is trusted to consult the gate
// before it acts.
//
// SPEC reference: SPEC-0202 §5 (verifier), §7 (Go gateway shim), §8 (refusal
// exit codes), §17 AC-9..AC-11.
package skillgate

// DataSource mirrors the Python `DataSource` model. It is advisory metadata
// in v1 — not part of the canonical signed message — but the gateway carries
// it through verbatim for downstream consumers.
type DataSource struct {
	Name string `json:"name"`
	URI  string `json:"uri"`
	Mode string `json:"mode"` // "read" | "write" | "none"
}

// TokenEnvelope is the strict-intersection envelope. v1 stores it as-given;
// the gateway interprets it.
type TokenEnvelope struct {
	Capabilities        []string `json:"capabilities"`
	EgressAllowlist     []string `json:"egress_allowlist"`
	SubprocessAllowlist []string `json:"subprocess_allowlist"`
	SubprocessDenylist  []string `json:"subprocess_denylist"`
	Destructive         bool     `json:"destructive"`
	MaxInvocations      int      `json:"max_invocations"`
	MaxRuntimeSeconds   int      `json:"max_runtime_seconds"`
	MaxEgressBytes      int64    `json:"max_egress_bytes"`
}

// Attenuation records one Macaroon-pattern attenuation step. The chain is
// stored in token.Attenuations in oldest-to-newest order.
//
// `Value` is typed `any` (BUG-0143, 2026-05-11) because the Python registry
// preserves whatever scalar/list/dict the operator passed to attenuate.
// SPEC-0202 §6 wire shapes seen on the wire:
//   - dict   `value: {egress: [...]}`     (envelope-shape deltas)
//   - list   `value: ["api.anthropic.com"]` (shrink_egress_allowlist)
//   - scalar `value: 60`                    (shrink_max_runtime_seconds)
//   - scalar `value: "2026-..."`            (shrink_expires_at)
//   - bool   `value: false`                 (force_destructive_false)
//
// Before BUG-0143 this was `map[string]any` which rejected scalar/list
// wire values at json.Unmarshal time. Pre-BUG-0143 Go callers that
// constructed Attenuation in-code worked around this by wrapping the
// raw value under a sentinel `_value` key. That convention is kept
// (canonicalAttenuationValue recognises it) but is no longer required.
type Attenuation struct {
	AppliedAt string `json:"applied_at"`
	AppliedBy string `json:"applied_by"`
	Rule      string `json:"rule"`
	Value     any    `json:"value"`
	Rationale string `json:"rationale,omitempty"`
}

// Token is the on-wire representation of a SPEC-0202 capability token (v1).
//
// Field tags match the Python pydantic CapabilityToken — `schema` (not
// `schema_`), `signature_b64` is the registry detached ed25519 signature
// over the canonical bytes (registry_signature_b64 in the Python wire shape;
// kept consistent here via JSON tag).
type Token struct {
	Schema         string        `json:"schema"`
	TokenID        string        `json:"token_id"`
	IssuedAt       string        `json:"issued_at"`
	ExpiresAt      string        `json:"expires_at"`
	BundleDigest   string        `json:"bundle_digest"`
	SkillName      string        `json:"skill_name"`
	SkillVersion   string        `json:"skill_version"`
	TenantScope    string        `json:"tenant_scope,omitempty"`
	CallerIdentity string        `json:"caller_identity"`
	CallerSession  string        `json:"caller_session"`
	Envelope       TokenEnvelope `json:"envelope"`
	DataSources    []DataSource  `json:"data_sources,omitempty"`
	RegistryKeyID  string        `json:"registry_key_id"`
	ParentTokenID  string        `json:"parent_token_id,omitempty"`
	Attenuations   []Attenuation `json:"attenuations,omitempty"`
	SignatureB64   string        `json:"registry_signature_b64"`

	// Advisory metadata — NOT part of the v1 canonical signed message.
	FederationChain   []string         `json:"federation_chain,omitempty"`
	ImportedFrom      string           `json:"imported_from,omitempty"`
	ThirdPartyCaveats []map[string]any `json:"third_party_caveats,omitempty"`
}
