// Package skillbundle implements deterministic packing of skill bundles
// (`.skb` archives) per SPEC-0188 §3 (Bundle Format).
//
// Phase 1 covers packing only. Signing (author, registry, governance) is
// Phase 2 and lives in a separate package.
package skillbundle

import "time"

// Schema is the canonical schema identifier embedded in every bundle manifest.
const Schema = "m3c-skill-bundle/v1"

// Dependency declares a runtime or build-time requirement for the skill.
// Mirrors SPEC-0188 §3.2 `depends_on[]`.
type Dependency struct {
	Kind       string `json:"kind"`       // e.g. "python", "system", "skill"
	Name       string `json:"name"`       // e.g. "requests"
	Constraint string `json:"constraint"` // e.g. ">=2.31"
}

// BundleManifest is the on-disk `bundle.json` document inside an `.skb` archive.
// Field order in this struct is preserved by encoding/json's struct-tag emission,
// which matters for canonicalization: BundleDigest is positioned last among
// the digest-relevant fields and is always serialized empty for the digest pass.
type BundleManifest struct {
	Schema              string       `json:"schema"`
	Name                string       `json:"name"`
	Version             string       `json:"version"`
	Summary             string       `json:"summary"`
	SourceRepo          string       `json:"source_repo"`
	SourceCommit        string       `json:"source_commit"`
	SourcePath          string       `json:"source_path"`
	// AuthorGovernanceIntent is advisory metadata only — verifiers MUST NOT
	// use it for trust decisions. The binding governance verdict comes from
	// signed attestations (SPEC-0188 §4.3). See SPEC-0188 §3.2 "Author intent
	// vs binding governance verdict".
	AuthorGovernanceIntent     string       `json:"author_governance_intent"`
	AuthorGovernanceRationale  string       `json:"author_governance_rationale"`
	DependsOn           []Dependency `json:"depends_on"`
	Supersedes          *string      `json:"supersedes"`
	DerivedFrom         *string      `json:"derived_from"`
	Compatibility       string       `json:"compatibility"`
	BundleDigest        string       `json:"bundle_digest"`
	BuiltAt             time.Time    `json:"built_at"`
	BuiltBy             string       `json:"built_by"`
}

// withEmptyDigest returns a shallow copy of m with BundleDigest cleared.
// Used to compute the canonical archive whose hash *is* the bundle digest.
func (m BundleManifest) withEmptyDigest() BundleManifest {
	m.BundleDigest = ""
	return m
}
