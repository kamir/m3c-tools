// Package datascope is the typed, client-side contract for SPEC-0196
// declared data-scope (the `data_dependencies` + `intent` blocks in a
// signed bundle).
//
// It is a LEAF package: stdlib-only, no imports from the rest of m3c-tools.
// That is deliberate — both the `intent declare` CLI path (post-hoc PATCH)
// and any future pack-time binding share ONE validator, and the package is
// safe for bodyscan (P1) to import later without a cycle. It does NOT import
// bodyscan; bodyscan does NOT import it today (no collision — see ADR §4.5).
//
// What this package adds over the server-side validation that already existed
// (which only ran on PATCH/admit and surfaced as exit 18) is the missing
// Go-side enforcement:
//
//   - per-`kind` scope validators (SPEC-0196 §12 Q2: the glob/URL/collection
//     specifier depends on the dependency's kind);
//   - the §3.3 cross-rules (destructive↔green, network→needs http dep,
//     write→destructive), runnable offline before any byte is signed;
//   - the §5 side-effect vocabulary as a closed set.
//
// SPEC reference: SPEC-0196 §3 (fields), §3.3 (cross-rules), §5 (side-effect
// vocabulary), §12 Q2 (per-kind scope syntax).
package datascope

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// Access is one of the four declared access modes a skill may have over a
// data source (SPEC-0196 §3.2 + §6.2 edge mapping). Closed set.
type Access string

const (
	// AccessRead — the skill reads from the source (reads_from edge).
	AccessRead Access = "read"
	// AccessWrite — the skill writes to the source (writes_to edge).
	AccessWrite Access = "write"
	// AccessTransform — reads + writes; mapped to writes_to (SPEC-0196 §6.2).
	AccessTransform Access = "transform"
	// AccessPassthrough — relays data without retention; mapped to reads_from.
	AccessPassthrough Access = "passthrough"
)

// validAccess is the closed access set. A declaration outside it is rejected
// before anything is signed.
var validAccess = map[Access]struct{}{
	AccessRead:        {},
	AccessWrite:       {},
	AccessTransform:   {},
	AccessPassthrough: {},
}

// isWriteAccess reports whether an access mode mutates the source. Used by the
// §3.3 write→destructive cross-rule and the writes_to edge mapping.
func (a Access) isWriteAccess() bool {
	return a == AccessWrite || a == AccessTransform
}

// Kind is the data-source kind. Each kind selects a scope validator
// (SPEC-0196 §12 Q2). Closed set; an unknown kind fails validation rather
// than being waved through (fail-closed — an attacker can't smuggle a scope
// past the per-kind validator by inventing a kind).
type Kind string

const (
	// KindLocalFS — local filesystem; scope is a path glob (** allowed).
	KindLocalFS Kind = "local_fs"
	// KindHTTPEndpoint — an outbound HTTP endpoint; scope is a URL pattern.
	KindHTTPEndpoint Kind = "http_endpoint"
	// KindER1Collection — an ER1 / Firestore collection path.
	KindER1Collection Kind = "er1_collection"
	// KindFirestore — a raw Firestore collection (alias kind kept distinct
	// so the CISO console can facet ER1 vs general Firestore).
	KindFirestore Kind = "firestore_collection"
	// KindGCSBucket — a Google Cloud Storage bucket / object prefix.
	KindGCSBucket Kind = "gcs_bucket"
	// KindSecretsStore — a secrets store reference (e.g. macOS Keychain item).
	KindSecretsStore Kind = "secrets_store"
)

// validKinds is the closed kind set.
var validKinds = map[Kind]struct{}{
	KindLocalFS:       {},
	KindHTTPEndpoint:  {},
	KindER1Collection: {},
	KindFirestore:     {},
	KindGCSBucket:     {},
	KindSecretsStore:  {},
}

// SideEffectVocabulary is the FIXED §5 side-effect token set (v1). Additive
// evolution is allowed; no token may be repurposed. A declaration containing a
// token outside this set fails validation (SPEC-0196 §5: "Skills declaring
// side-effects outside the vocabulary fail bundle-pack validation").
//
// The sentinel "UNKNOWN" (SPEC-0196 §7 awareness backfill) is permitted: a
// legacy awareness-only bundle carries side_effects=["UNKNOWN"] and must not be
// rejected by the validator before the operator has had a chance to declare.
var SideEffectVocabulary = map[string]struct{}{
	"fs:read":          {},
	"fs:write":         {},
	"fs:delete":        {},
	"git:read":         {},
	"git:write":        {},
	"network:outbound": {},
	"network:inbound":  {},
	"subprocess":       {},
	"secrets:read":     {},
	"llm:call":         {},
	"UNKNOWN":          {}, // §7 awareness sentinel — tolerated, not first-class.
}

// DataScope is one declared (skill → data source) dependency. It is the typed
// projection of one `data_dependencies[]` entry (SPEC-0196 §3.2). The JSON
// tags match the bundle.json wire shape exactly so a DataScope round-trips
// through the signed bundle / the PATCH body without a translation layer.
type DataScope struct {
	// ID is the data-source identifier, e.g. "ds:er1/plm/skill-creations".
	// Must be a "ds:"-prefixed, non-empty token (§3.2: "Each entry MUST have
	// id"). It resolves to a DataSource record at admit time server-side.
	ID string `json:"id"`
	// Kind selects the scope validator (§12 Q2).
	Kind Kind `json:"kind"`
	// Access is read|write|transform|passthrough (§3.2).
	Access Access `json:"access"`
	// Scope is the narrow specifier — path glob / URL pattern / collection
	// path — interpreted per Kind. Optional for some kinds (e.g. a whole ER1
	// collection); required for others (local_fs, http_endpoint) so a write
	// dependency can never be unbounded.
	Scope string `json:"scope,omitempty"`
	// Reason is the human rationale (§3.2: "Each entry MUST have ... reason").
	Reason string `json:"reason,omitempty"`
	// PayloadClass is optional metadata (PII / non-PII / config).
	PayloadClass string `json:"payload_class,omitempty"`
	// Retention is optional metadata (none / session / persistent).
	Retention string `json:"retention,omitempty"`
}

// Intent is the typed projection of the `intent` block (SPEC-0196 §3.1). Only
// the fields the §3.3 cross-rules read are first-class here; the free-form rest
// (summary, claims, subprocess) stay advisory and are carried verbatim by the
// caller's map. The pointer fields distinguish "declared false" from "absent",
// which the cross-rules need (a missing `destructive` is not the same as
// `destructive:false`).
type Intent struct {
	SideEffects []string `json:"side_effects,omitempty"`
	Destructive *bool    `json:"destructive,omitempty"`
	Network     *bool    `json:"network,omitempty"`
}

// ValidationError is a structured validation failure. FailedRule carries the
// stable §3.3 rule name (destructive_green, network_false_http_dep,
// write_access_non_destructive) so the CLI can map it to exit 18 exactly the
// way the server-side PATCH path does, and the red-team can assert on it.
type ValidationError struct {
	// FailedRule is the stable rule identifier, or "" for a structural error.
	FailedRule string
	// Detail is the human message.
	Detail string
}

func (e *ValidationError) Error() string {
	if e.FailedRule != "" {
		return fmt.Sprintf("data-scope rule %s: %s", e.FailedRule, e.Detail)
	}
	return "data-scope: " + e.Detail
}

// Stable §3.3 cross-rule identifiers. These MUST match the server-side
// `failed_rule` values (SPEC-0196 §7.1) so a client-side refusal and a
// server-side 422 are indistinguishable to CI.
const (
	RuleDestructiveGreen    = "destructive_green"
	RuleNetworkFalseHTTPDep = "network_false_http_dep"
	RuleWriteAccessNonDestr = "write_access_non_destructive"
)

// ValidateScope validates a single DataScope: the id shape, the kind, the
// access mode, and the per-kind scope specifier. Pure; no I/O.
func (d DataScope) Validate() error {
	if strings.TrimSpace(d.ID) == "" {
		return &ValidationError{Detail: "data_dependencies[].id must not be empty"}
	}
	if !strings.HasPrefix(d.ID, "ds:") {
		return &ValidationError{Detail: fmt.Sprintf("data_dependencies[].id %q must be a ds:-prefixed identifier", d.ID)}
	}
	if _, ok := validKinds[d.Kind]; !ok {
		return &ValidationError{Detail: fmt.Sprintf("data_dependencies[].kind %q is not a known kind (%s)", d.Kind, kindList())}
	}
	if _, ok := validAccess[d.Access]; !ok {
		return &ValidationError{Detail: fmt.Sprintf("data_dependencies[].access %q is not read|write|transform|passthrough", d.Access)}
	}
	if err := validateScopeForKind(d.Kind, d.Access, d.Scope); err != nil {
		return err
	}
	return nil
}

// validateScopeForKind runs the per-kind scope validator (SPEC-0196 §12 Q2).
//
// The load-bearing invariant: a WRITE/TRANSFORM dependency on a bounded-scope
// kind (filesystem, http, gcs) MUST carry a non-empty scope, so a skill can
// never declare an *unbounded* write. A read may omit the scope (read the whole
// collection) but a write must say where.
func validateScopeForKind(kind Kind, access Access, scope string) error {
	scope = strings.TrimSpace(scope)
	switch kind {
	case KindLocalFS:
		// A WRITE/TRANSFORM to the filesystem MUST be bounded — a skill may not
		// declare an unbounded write. A READ may omit the scope (read broadly).
		if access.isWriteAccess() && scope == "" {
			return &ValidationError{Detail: "local_fs write dependency requires a path-glob scope (e.g. <cwd>/decks/**)"}
		}
		// When a scope IS given (any access), it must not be a bare wildcard
		// that escapes any anchor — "**" or "/**" alone is unbounded.
		if scope == "**" || scope == "/**" || scope == "/" {
			return &ValidationError{Detail: fmt.Sprintf("local_fs scope %q is unbounded; anchor it (e.g. <cwd>/path/**)", scope)}
		}
	case KindHTTPEndpoint:
		if scope == "" {
			return &ValidationError{Detail: "http_endpoint dependency requires a URL-pattern scope (e.g. https://api.anthropic.com/*)"}
		}
		if err := validateHTTPScope(scope); err != nil {
			return err
		}
	case KindGCSBucket:
		if access.isWriteAccess() && scope == "" {
			return &ValidationError{Detail: "gcs_bucket write dependency requires a bucket/prefix scope"}
		}
	case KindER1Collection, KindFirestore:
		// Collection scope is optional (a read of the whole collection is a
		// legitimate, common case). When present it must look like a
		// collection path, not a glob or URL.
		if scope != "" && (strings.Contains(scope, "://") || strings.HasPrefix(scope, "/")) {
			return &ValidationError{Detail: fmt.Sprintf("%s scope %q should be a collection path (no scheme, no leading slash)", kind, scope)}
		}
	case KindSecretsStore:
		// Secrets are read-only by contract; a write to a secrets store is a
		// declaration error.
		if access.isWriteAccess() {
			return &ValidationError{Detail: "secrets_store dependency cannot declare write/transform access"}
		}
	}
	return nil
}

// validateHTTPScope checks an http_endpoint scope is an https URL pattern. A
// trailing "/*" or "*" is allowed (prefix match per §12 Q2). http:// (non-TLS)
// is rejected — a declared cleartext egress is a smell, and the gate's
// egress_allowlist is host-based anyway.
func validateHTTPScope(scope string) error {
	bare := strings.TrimSuffix(strings.TrimSuffix(scope, "*"), "/")
	if bare == "" {
		return &ValidationError{Detail: fmt.Sprintf("http_endpoint scope %q has no host", scope)}
	}
	u, err := url.Parse(bare)
	if err != nil {
		return &ValidationError{Detail: fmt.Sprintf("http_endpoint scope %q is not a URL pattern: %v", scope, err)}
	}
	if u.Scheme != "https" {
		return &ValidationError{Detail: fmt.Sprintf("http_endpoint scope %q must use https (got scheme %q)", scope, u.Scheme)}
	}
	if u.Host == "" {
		return &ValidationError{Detail: fmt.Sprintf("http_endpoint scope %q has no host", scope)}
	}
	return nil
}

// ValidateSideEffects checks every side-effect token is in the §5 vocabulary.
func ValidateSideEffects(sideEffects []string) error {
	for _, s := range sideEffects {
		if _, ok := SideEffectVocabulary[s]; !ok {
			return &ValidationError{Detail: fmt.Sprintf("side_effect %q is not in the SPEC-0196 §5 vocabulary (%s)", s, sideEffectList())}
		}
	}
	return nil
}

// Validate runs the FULL SPEC-0196 declaration check: per-scope validation, the
// §5 side-effect vocabulary, and the §3.3 cross-rules. It takes the typed
// Intent plus the governance level (green|yellow|red|"") because two of the
// three cross-rules straddle intent and governance.
//
// On the FIRST failure it returns a *ValidationError whose FailedRule (when a
// cross-rule fired) matches the server-side `failed_rule` exactly. Pure.
func Validate(intent Intent, scopes []DataScope, governanceLevel string) error {
	// (a) every scope is individually well-formed.
	for i, d := range scopes {
		if err := d.Validate(); err != nil {
			if ve, ok := err.(*ValidationError); ok {
				return &ValidationError{FailedRule: ve.FailedRule, Detail: fmt.Sprintf("data_dependencies[%d]: %s", i, ve.Detail)}
			}
			return err
		}
	}
	// (b) side-effect vocabulary.
	if err := ValidateSideEffects(intent.SideEffects); err != nil {
		return err
	}
	// (c) the three §3.3 cross-rules.
	return crossRules(intent, scopes, governanceLevel)
}

// crossRules enforces SPEC-0196 §3.3:
//
//  1. destructive=true paired with governance "green" is incompatible.
//  2. network=true requires at least one HTTP-shaped data dependency.
//  3. data_dependencies[].access=write paired with destructive=false is
//     inconsistent (a write IS a destructive-ish effect; declaring otherwise is
//     the cross-check the spec wants to catch).
//
// "Spec divergence between fields is itself a security signal" (§3.3) — a skill
// that lies in `intent` but tells the truth in `data_dependencies` is caught
// here. Fail-closed ordering: the cheapest, most-specific rule first.
func crossRules(intent Intent, scopes []DataScope, governanceLevel string) error {
	destructive := intent.Destructive != nil && *intent.Destructive
	network := intent.Network != nil && *intent.Network

	// Rule 1: destructive ⇒ NOT green.
	if destructive && strings.EqualFold(strings.TrimSpace(governanceLevel), "green") {
		return &ValidationError{
			FailedRule: RuleDestructiveGreen,
			Detail:     "intent.destructive=true is incompatible with governance_intent=green (a destructive skill cannot be 🟢)",
		}
	}

	// Rule 2: network ⇒ at least one HTTP-shaped dependency.
	if network {
		hasHTTP := false
		for _, d := range scopes {
			if d.Kind == KindHTTPEndpoint {
				hasHTTP = true
				break
			}
		}
		if !hasHTTP {
			return &ValidationError{
				FailedRule: RuleNetworkFalseHTTPDep,
				Detail:     "intent.network=true but no http_endpoint data dependency is declared",
			}
		}
	}

	// Rule 3: any write/transform dependency ⇒ destructive=true.
	// Only fires when destructive was explicitly declared false (a missing
	// destructive is handled by the pack-time requirement, not here) — this
	// mirrors the server rule `write_access_non_destructive`.
	if intent.Destructive != nil && !*intent.Destructive {
		for i, d := range scopes {
			if d.Access.isWriteAccess() {
				return &ValidationError{
					FailedRule: RuleWriteAccessNonDestr,
					Detail:     fmt.Sprintf("data_dependencies[%d] declares access=%q but intent.destructive=false", i, d.Access),
				}
			}
		}
	}
	return nil
}

// kindList renders the closed kind set sorted, for error messages.
func kindList() string {
	out := make([]string, 0, len(validKinds))
	for k := range validKinds {
		out = append(out, string(k))
	}
	sort.Strings(out)
	return strings.Join(out, "|")
}

// sideEffectList renders the §5 vocabulary sorted, for error messages.
func sideEffectList() string {
	out := make([]string, 0, len(SideEffectVocabulary))
	for s := range SideEffectVocabulary {
		out = append(out, s)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}
