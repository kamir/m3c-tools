// Package skillbundle implements deterministic packing of skill bundles
// (`.skb` archives) per SPEC-0188 §3 (Bundle Format).
//
// Phase 1 covers packing only. Signing (author, registry, governance) is
// Phase 2 and lives in a separate package.
package skillbundle

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Schema is the FORMAT version of a bundle manifest, and nothing else. The
// bundle's ART lives in Kind. Owner decision of 2026-10-08, taken with
// ADR-0047: the two axes used to share this one string, and that is why the
// numbers below look the way they do.
//
// It was "m3c-skill-bundle/v1" and carried the note that it would stay there
// FOREVER, because bumping it would change the re-serialized manifest bytes of
// every unchanged skill and so move every digest without a content change
// (SPEC-0432 §3.2). ADR-0047 moves every digest anyway, by decision, so that
// reason is spent.
//
// The new value skips a number on purpose. "m3c-skill-bundle/v2" is NOT free:
// it was the marker an AGENT bundle carried, so a reader that saw /v2 could not
// tell a pre-ADR-0047 agent bundle from a post-ADR-0047 skill bundle. /v3 is
// unambiguous: anything below it predates the digest change and cannot verify.
const Schema = "m3c-skill-bundle/v3"

// The retired markers. They are named so a reader can say WHY it refuses a
// bundle instead of reporting a digest mismatch, which reads like tampering.
const (
	LegacySchemaSkillV1 = "m3c-skill-bundle/v1"
	LegacySchemaAgentV2 = "m3c-skill-bundle/v2"
)

// SchemaAgent is retained only so existing callers keep compiling and keep
// meaning what they meant: an agent bundle's schema. Since the art moved to
// Kind it is the same value as Schema. Deprecated: use Schema and set Kind.
const SchemaAgent = Schema

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
	Scope        string `json:"scope,omitempty"`  // narrow specifier: path glob / URL pattern / collection path
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
	// AuthorGovernanceIntent is advisory metadata only. Verifiers MUST NOT
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
	// BundleDigest is NOT written since v0.7.0 (ADR-0047): the digest is
	// formed over the canonical tar, and a value inside the bytes it covers
	// would force every verifier to rebuild the archive before checking it.
	// The field is retained so an older bundle still unmarshals, and
	// `omitempty` keeps it out of the canonical JSON that Pack hashes.
	BundleDigest string    `json:"bundle_digest,omitempty"`
	BuiltAt      time.Time `json:"built_at"`
	BuiltBy      string    `json:"built_by"`
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

// ReadManifest returns the bundle.json of a packed .skb archive.
//
// Callers on the INSTALL side need the manifest before they decide where the
// bundle goes (SPEC-0432 §3.2): the kind names the target, and the schema says
// whether this reader understands the bundle at all.
func ReadManifest(archive []byte) (BundleManifest, error) {
	var m BundleManifest
	entries, err := Unpack(archive, UnpackOptions{})
	if err != nil {
		return m, fmt.Errorf("manifest: unpack: %w", err)
	}
	// Our own Pack puts bundle.json at the top level, but a bundle may arrive
	// wrapped in a single directory (the shape WrapperDir exists for). Look in
	// both places rather than declaring a wrapped bundle manifest-less.
	want := "bundle.json"
	if w := WrapperDir(entries); w != "" {
		want = w + "/bundle.json"
	}
	for _, e := range entries {
		if e.Rel != "bundle.json" && e.Rel != want {
			continue
		}
		if err := json.Unmarshal(e.Content, &m); err != nil {
			return m, fmt.Errorf("manifest: parse bundle.json: %w", err)
		}
		return m, nil
	}
	return m, errors.New("manifest: archive carries no bundle.json")
}

// KnownSchema reports whether this build understands a bundle's schema.
//
// Fail-closed on purpose. An unknown schema means the bundle was written by a
// NEWER producer that may place its content somewhere this reader does not
// know about; installing it anyway would put the artifact in the wrong place
// while reporting success (SPEC-0432 §3.2).
func KnownSchema(s string) bool {
	return s == Schema
}

// LegacyDigestSchema reports whether s is one of the retired markers, i.e. a
// bundle written before ADR-0047 moved the digest in front of the compression.
// Such a bundle cannot verify under this build and must be re-packed; saying so
// is the whole reason this function exists.
//
// The empty string counts: the field was optional before SPEC-0432, and every
// bundle that old is older still than the digest change.
func LegacyDigestSchema(s string) bool {
	return s == "" || s == LegacySchemaSkillV1 || s == LegacySchemaAgentV2
}
