package artifact

import "time"

// EventKind is the SPEC-0190 lifecycle event kind. The string values are
// byte-identical to registry.EventKind* so the same signed envelope crosses
// every backend unchanged.
type EventKind string

const (
	KindAdmit   EventKind = "admitted"
	KindAttest  EventKind = "attested"
	KindRevoke  EventKind = "revoked"
	KindInstall EventKind = "installed"
)

// ArtifactMeta is the backend-neutral identity/version metadata a backend needs
// to build its NATIVE index entry (ER1 tags, OCI annotations, git tag name).
// registry.SkillMeta is ER1-tag-flavoured and lives in registry, so it cannot
// be the shared vocabulary without a cycle; the ER1 adapter maps ArtifactMeta
// into registry.SkillMeta.
type ArtifactMeta struct {
	Name            string // "pdf"
	Version         string // "1.2.0"
	Digest          string // "sha256:<hex>" — the invariant join key
	AuthorIdentity  string // "id:kamir@m3c"
	GovernanceLevel string // "green" | "yellow" | "red"
	PackedOnHost    string
	ProjectID       string
	Rooms           []string // SPEC-0096 labels; backends without Rooms ignore
}

// PublishRequest carries the SAME signed SPEC-0190 envelope across every
// backend. Event is deliberately a map[string]any reused verbatim from the
// registry event builders — no re-typing, so the canonical signed bytes never
// drift.
type PublishRequest struct {
	Kind           EventKind
	Event          map[string]any // signed; envelope_signature already set
	Meta           ArtifactMeta
	Blob           []byte // REQUIRED iff Kind == KindAdmit; else nil
	InlineMaxBytes int    // claim-check threshold hint; backend may ignore
}

// PublishResult reports where the event landed on the backend's native address
// space, and whether the publish was an idempotent no-op.
type PublishResult struct {
	Ref           ArtifactRef // digest-pinned, native Locator filled in
	NativeID      string      // ER1 doc_id | OCI manifest digest | git tag ref
	Transport     string      // "er1-inline" | "oci-blob" | "git-asset" | ...
	AlreadyExists bool        // idempotent no-op
}

// ArtifactRef is the unified single-artifact pointer. Digest is the invariant
// every backend can Fetch by; Locator is the backend-native address.
type ArtifactRef struct {
	Name    string // may be "" when addressed purely by digest
	Version string
	Digest  string // "sha256:<hex>" — REQUIRED for Fetch
	Locator string // ER1 doc_id | oci://…@sha256:… | https://…/bundles/<digest> | git ref
	Scheme  string // originating backend scheme, for provenance
}

// RefQuery addresses one artifact by name(+version) or by an explicit digest
// pin. Version == "" resolves per the backend's LatestPolicy.
type RefQuery struct {
	Name    string
	Version string // "" => resolve per LatestPolicy
	Digest  string // if set, a direct pin (Name/Version optional)
}

// ListFilter is the backend-neutral filter. Since is a first-class field (it
// fixes the previously-dead --since flag); Latest collapses to the LatestPolicy
// winner per skill.
type ListFilter struct {
	Name   string    // "" => all skills
	Since  time.Time // zero => no lower bound
	Latest bool      // collapse to the LatestPolicy winner per skill
}

// Page drives cursor pagination — the fix for the single-shot list bug.
type Page struct {
	Cursor string // "" => first page; opaque, backend-defined
	Limit  int    // 0 => backend default
}

// Listing is one backend-neutral index page.
type Listing struct {
	Skills     []SkillIndexEntry
	NextCursor string // "" => last page
}

// SkillIndexEntry is the union of what ER1's SkillView and HTTP's
// []BundleVersion carry; each adapter maps its native shape into it.
type SkillIndexEntry struct {
	Name             string
	LatestVersion    string
	LatestDigest     string // "sha256:<hex>"
	LatestGovernance string
	IsRevoked        bool
	Versions         []VersionRow
}

// VersionRow is one known version of a skill.
type VersionRow struct {
	Version    string
	Digest     string
	Governance string
	Status     string // "admitted" | "revoked"
	AdmittedAt time.Time
}

// EventPage is one page of the raw event timeline (GovernanceLog backends).
type EventPage struct {
	Events     []EventRecord
	NextCursor string
}

// EventRecord is a backend-neutral projection of one signed lifecycle event.
type EventRecord struct {
	Kind       EventKind
	Digest     string
	OccurredAt time.Time
	Governance string
	Host       string
	Rationale  string
	NativeID   string
	Envelope   map[string]any // the raw signed event, for re-verification
}

