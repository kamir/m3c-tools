// Package skillbundle implements deterministic packing of skill bundles
// (`.skb` archives) per SPEC-0188 §3 (Bundle Format).
//
// Phase 1 covers packing only. Signing (author, registry, governance) is
// Phase 2 and lives in a separate package.
package skillbundle

import "time"

// Schema is the canonical schema identifier embedded in every SKILL bundle
// manifest. It stays at v1 forever: bumping it for all bundles would change the
// re-serialized manifest bytes of every unchanged skill, and pack.go hashes
// those bytes, so each skill would report a new digest without a content change
// (SPEC-0432 §3.2).
const Schema = "m3c-skill-bundle/v1"

// SchemaAgent is the schema identifier for bundles carrying Kind == KindAgent.
// A v1-only reader must REJECT such a bundle rather than install it at the skill
// location (SPEC-0432 §3.2).
const SchemaAgent = "m3c-skill-bundle/v2"

// The bundle kinds. KindSkill is the implied default for a manifest that carries
// no Kind at all: all 78 bundles admitted before SPEC-0432 are skills, so the
// default is measured, not guessed.
const (
	KindSkill = "skill"
	KindAgent = "agent"
)

// ValidKind reports whether k is a kind this packer accepts. The empty string is
// valid and means KindSkill.
func ValidKind(k string) bool {
	return k == "" || k == KindSkill || k == KindAgent
}

// Dependency declares a runtime or build-time requirement for the skill.
// Mirrors SPEC-0188 §3.2 `depends_on[]`.
type Dependency struct {
	Kind       string `json:"kind"`       // e.g. "python", "system", "skill"
	Name       string `json:"name"`       // e.g. "requests"
	Constraint string `json:"constraint"` // e.g. ">=2.31"
}

// Intent declares the skill's self-asserted behaviors and constraints.
// Mirrors SPEC-0196 §3 `intent` block. Cross-checked against
// DataDependencies and AuthorGovernanceIntent via
// ValidateIntentDataCrossRules.
type Intent struct {
	Summary             string   `json:"summary,omitempty"`
	Claims              []string `json:"claims,omitempty"`
	SideEffects         []string `json:"side_effects,omitempty"` // ["UNKNOWN"] = awareness sentinel
	Destructive         bool     `json:"destructive,omitempty"`
	Network             *bool    `json:"network,omitempty"` // pointer so we can distinguish "false" from "unset"
	HumanReviewRequired bool     `json:"human_review_required,omitempty"`
	Subprocess          []string `json:"subprocess,omitempty"`
}

// DataDependency declares one data source the skill reads or writes.
// Mirrors SPEC-0196 §3 `data_dependencies[]`.
//
// The JSON tags match the SPEC-0196 §3.2 wire shape AND the
// `pkg/skillctl/datascope.DataScope` projection exactly, so a typed data-scope
// declared at pack time (`skillctl pack --data-scopes`, SPEC-0196 §12 Q1 / P2b)
// round-trips byte-for-byte into the signed `bundle.json` and back out of the
// verifier with no translation layer. `ID`/`Scope`/`Reason`/`PayloadClass`/
// `Retention` are the P2b signed-binding fields; `Kind`/`Access` are also read
// by the §3.3 cross-rules (ValidateIntentDataCrossRules). `Ref` is the legacy
// pre-P2b identifier kept so manifests written before the datascope shape
// existed still decode.
type DataDependency struct {
	ID           string `json:"id,omitempty"`     // SPEC-0196 §3.2 "ds:"-prefixed identifier
	Kind         string `json:"kind"`             // local_fs | http_endpoint | er1_collection | firestore_collection | gcs_bucket | secrets_store
	Ref          string `json:"ref,omitempty"`    // legacy identifier within Kind (pre-P2b)
	Access       string `json:"access,omitempty"` // read | write | passthrough | transform
	Scope        string `json:"scope,omitempty"`  // narrow specifier — path glob / URL pattern / collection path
	Reason       string `json:"reason,omitempty"` // human rationale (§3.2 required for new declarations)
	PayloadClass string `json:"payload_class,omitempty"`
	Retention    string `json:"retention,omitempty"`
}

// BundleManifest is the on-disk `bundle.json` document inside an `.skb` archive.
// Field order in this struct is preserved by encoding/json's struct-tag emission,
// which matters for canonicalization: BundleDigest is positioned last among
// the digest-relevant fields and is always serialized empty for the digest pass.
type BundleManifest struct {
	Schema string `json:"schema"`
	// Kind is the bundle kind ("agent"), absent for skills. It MUST stay
	// `omitempty` and this packer MUST never write "skill" explicitly: an
	// emitted `"kind":"skill"` would be new bytes in the canonical manifest,
	// and every unchanged skill would re-pack to a different digest
	// (SPEC-0432 §3.2). Reading an explicit "skill" from a foreign bundle is
	// fine; writing it is not. Use EffectiveKind to read.
	Kind         string `json:"kind,omitempty"`
	Name         string `json:"name"`
	Version      string `json:"version"`
	Summary      string `json:"summary"`
	SourceRepo   string `json:"source_repo"`
	SourceCommit string `json:"source_commit"`
	SourcePath   string `json:"source_path"`
	// AuthorGovernanceIntent is advisory metadata only — verifiers MUST NOT
	// use it for trust decisions. The binding governance verdict comes from
	// signed attestations (SPEC-0188 §4.3). See SPEC-0188 §3.2 "Author intent
	// vs binding governance verdict".
	AuthorGovernanceIntent    string `json:"author_governance_intent"`
	AuthorGovernanceRationale string `json:"author_governance_rationale"`
	// Intent and DataDependencies (SPEC-0196 §3). Optional in v1; pack-time
	// validator enforces cross-rule consistency via ValidateIntentDataCrossRules.
	Intent           *Intent          `json:"intent,omitempty"`
	DataDependencies []DataDependency `json:"data_dependencies,omitempty"`
	DependsOn        []Dependency     `json:"depends_on"`
	Supersedes       *string          `json:"supersedes"`
	DerivedFrom      *string          `json:"derived_from"`
	Compatibility    string           `json:"compatibility"`
	BundleDigest     string           `json:"bundle_digest"`
	BuiltAt          time.Time        `json:"built_at"`
	BuiltBy          string           `json:"built_by"`
}

// EffectiveKind returns the manifest's kind, resolving an absent Kind to
// KindSkill. This is the ONE place that encodes "missing means skill"
// (SPEC-0432 §3.2); no caller may re-derive it.
func (m BundleManifest) EffectiveKind() string {
	if m.Kind == "" {
		return KindSkill
	}
	return m.Kind
}

// withEmptyDigest returns a shallow copy of m with BundleDigest cleared.
// Used to compute the canonical archive whose hash *is* the bundle digest.
func (m BundleManifest) withEmptyDigest() BundleManifest {
	m.BundleDigest = ""
	return m
}
