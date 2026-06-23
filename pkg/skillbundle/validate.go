package skillbundle

// SPEC-0196 §3.3 — Intent / data-dependencies cross-rule validation.
//
// TWO validators name a `network_*_http_dep` rule. They are NOT interchangeable
// (P2b challenge-gate finding #3 — the "duplicate name, opposite semantics"
// foot-gun). Read this before wiring either:
//
//   - THE AUTHORITATIVE GATE is pkg/skillctl/datascope.Validate. It is the SINGLE
//     source of truth for SPEC-0196 declared-scope validity (per-kind scope, §5
//     side-effect vocabulary, §3.3 cross-rules) and is what the pack/sign boundary
//     now enforces — see ValidateManifestDataScope below, which Pack calls so NO
//     unvalidated scope is ever author-signed. Its Rule 2
//     (datascope.RuleNetworkFalseHTTPDep) fires on network=TRUE with NO
//     http_endpoint dep.
//
//   - THE LEGACY bundle-shaped helpers in THIS file
//     (ValidateIntentDataCrossRules / ValidateManifestCrossRules /
//     ExitCodeForViolation) predate the typed datascope package. They model the
//     COMPLEMENTARY direction — network=FALSE with an http_endpoint dep present —
//     under the SAME stable failed_rule string "network_false_http_dep". They are
//     retained for API + test compatibility and a forensic/legacy read of a raw
//     manifest, but they are NOT the security gate and MUST NOT be used to decide
//     whether a scope may be signed. Use ValidateManifestDataScope / datascope for
//     that. DO NOT introduce a third copy of this rule.
//
// Locked decisions (S3-DECISIONS.md S3.2):
//   Q1 = A — pre-pack validation; same shape as the Python server-side rule.
//   Q2 = A — exit codes 11 (missing_governance_intent) for green+destructive,
//            12 (intent_data_inconsistent) for the other two cross-rules.
//   Q3 = A — no override flag in v1.

import "github.com/kamir/m3c-tools/pkg/skillctl/datascope"

// CrossRuleViolation names a SPEC-0196 §3.3 cross-rule failure.
type CrossRuleViolation string

const (
	// RuleNone — record is internally consistent or is the legacy
	// awareness sentinel (intent.side_effects == ["UNKNOWN"]).
	RuleNone CrossRuleViolation = ""

	// RuleDestructiveGreen — Rule 1: intent.destructive=true is
	// incompatible with author_governance_intent="green". Maps to
	// pack-time exit 11 (missing_governance_intent — the green claim is
	// the missing piece, since destructive=true requires yellow or red).
	RuleDestructiveGreen CrossRuleViolation = "destructive_green"

	// RuleNetworkFalseHttpDep — Rule 2 (this package's LEGACY framing):
	// intent.network=false but a data_dependency declares kind="http_endpoint".
	//
	// FOOT-GUN CROSS-REFERENCE (P2b finding #3): datascope.RuleNetworkFalseHTTPDep
	// uses the SAME failed_rule string "network_false_http_dep" for the OPPOSITE
	// trigger (network=TRUE with NO http dep). Both express the same §3.3 "network
	// claim disagrees with the http dependency set" signal; the authoritative
	// validator is datascope. This constant exists only for the legacy helpers in
	// this file — do not route signing decisions through it.
	RuleNetworkFalseHttpDep CrossRuleViolation = "network_false_http_dep"

	// RuleWriteAccessNonDestructive — Rule 3: a data_dependency with
	// access="write" is inconsistent with intent.destructive=false. Maps to
	// pack-time exit 12 (intent_data_inconsistent).
	RuleWriteAccessNonDestructive CrossRuleViolation = "write_access_non_destructive"
)

// ValidateManifestDataScope is the LIBRARY-BOUNDARY gate Pack calls before it
// produces (and the author signs) any bytes (P2b challenge-gate finding #2). It
// runs the FULL SPEC-0196 check — per-kind scope, §5 side-effect vocabulary, and
// the §3.3 cross-rules — via the SINGLE authoritative validator
// (datascope.Validate), against the manifest's declared intent, data dependencies,
// and author governance Ampel.
//
// This is what makes "no unvalidated scope is ever author-signed" hold at the
// library boundary itself, not only in the CLI: any programmatic producer that
// calls skillbundle.Pack (e.g. publish_cmds.go ensureBundle) is now bound by the
// same rule the CLI runs.
//
// Returns nil when there is nothing to validate (no intent and no data deps — the
// common legacy case) so old bundles pack exactly as before. Returns a non-nil
// error (wrapping *datascope.ValidationError, so callers can errors.As the
// FailedRule) on the FIRST failure — fail-closed; Pack then writes no bundle.
func ValidateManifestDataScope(m BundleManifest) error {
	if m.Intent == nil && len(m.DataDependencies) == 0 {
		return nil
	}
	return datascope.Validate(
		manifestIntentToDatascope(m.Intent),
		manifestDepsToDatascope(m.DataDependencies),
		m.AuthorGovernanceIntent,
	)
}

// manifestIntentToDatascope projects a manifest *Intent onto the datascope.Intent
// the cross-rules read. A nil manifest intent yields the zero datascope.Intent
// (all-absent). The Destructive bool is projected through a pointer so the §3.3
// write_access_non_destructive rule (which only fires when destructive is
// EXPLICITLY false) behaves identically to the CLI path.
func manifestIntentToDatascope(in *Intent) datascope.Intent {
	if in == nil {
		return datascope.Intent{}
	}
	d := in.Destructive
	return datascope.Intent{
		SideEffects: in.SideEffects,
		Destructive: &d,
		Network:     in.Network,
	}
}

// manifestDepsToDatascope projects manifest DataDependency entries onto typed
// datascope.DataScope values. The JSON tags are identical (SPEC-0196 §3.2), so the
// mapping is field-for-field and lossless for the validated fields.
func manifestDepsToDatascope(deps []DataDependency) []datascope.DataScope {
	out := make([]datascope.DataScope, 0, len(deps))
	for _, d := range deps {
		out = append(out, datascope.DataScope{
			ID:           d.ID,
			Kind:         datascope.Kind(d.Kind),
			Access:       datascope.Access(d.Access),
			Scope:        d.Scope,
			Reason:       d.Reason,
			PayloadClass: d.PayloadClass,
			Retention:    d.Retention,
		})
	}
	return out
}

// ValidateIntentDataCrossRules applies the three SPEC-0196 §3.3 cross-rules
// to a triplet of (intent, author_governance_intent, data_dependencies).
//
// LEGACY helper — see the file header. The AUTHORITATIVE gate is
// ValidateManifestDataScope / datascope.Validate. This retains the original
// bundle-shaped semantics (including the network=FALSE+http-dep direction of
// Rule 2) for back-compat and forensic reads of a raw manifest.
//
// Returns RuleNone when the record is internally consistent. Returns the
// matching violation constant when a rule fires; rules are checked in the
// order defined by SPEC-0196 §3.3 (destructive_green, network_false_http_dep,
// write_access_non_destructive).
//
// Sentinel: when intent is nil OR intent.SideEffects == ["UNKNOWN"] (the
// awareness path's missing-claims marker per SPEC-0196 §7), returns
// RuleNone — there are no claims to cross-check. Behavior matches the
// Python server-side validator exactly.
func ValidateIntentDataCrossRules(
	intent *Intent,
	authorGovernanceIntent string,
	dataDependencies []DataDependency,
) CrossRuleViolation {
	if intent == nil {
		return RuleNone
	}
	if isAwarenessSentinel(intent.SideEffects) {
		return RuleNone
	}

	// Rule 1: destructive=true + governance_intent=green is incompatible.
	if intent.Destructive && authorGovernanceIntent == "green" {
		return RuleDestructiveGreen
	}

	// Rule 2: network=false but at least one HTTP-shaped data_dep contradicts.
	if intent.Network != nil && !*intent.Network {
		for _, dep := range dataDependencies {
			if dep.Kind == "http_endpoint" {
				return RuleNetworkFalseHttpDep
			}
		}
	}

	// Rule 3: write access without destructive intent is inconsistent.
	if !intent.Destructive {
		for _, dep := range dataDependencies {
			if dep.Access == "write" {
				return RuleWriteAccessNonDestructive
			}
		}
	}

	return RuleNone
}

// ValidateManifestCrossRules is the bundle-shaped wrapper around
// ValidateIntentDataCrossRules. LEGACY: Pack now gates on the stronger
// ValidateManifestDataScope (which also catches structural/vocab errors via
// datascope); this is kept for API compatibility. Returns RuleNone on a valid or
// sentinel-shaped manifest.
func ValidateManifestCrossRules(m BundleManifest) CrossRuleViolation {
	return ValidateIntentDataCrossRules(
		m.Intent,
		m.AuthorGovernanceIntent,
		m.DataDependencies,
	)
}

// ExitCodeForViolation maps a CrossRuleViolation to its skillctl exit code
// per S3.2 Q2 lock: green+destructive → 11 (missing_governance_intent);
// the other two consistency violations → 12 (intent_data_inconsistent).
// Returns 0 for RuleNone (no violation).
func ExitCodeForViolation(v CrossRuleViolation) int {
	switch v {
	case RuleNone:
		return 0
	case RuleDestructiveGreen:
		return 11
	case RuleNetworkFalseHttpDep, RuleWriteAccessNonDestructive:
		return 12
	default:
		// Forward-compat: an unknown violation surfaces as the broader
		// intent_data_inconsistent code rather than crashing the CLI.
		return 12
	}
}

// isAwarenessSentinel returns true iff side_effects is exactly the
// awareness path's missing-claims marker per SPEC-0196 §7. Single-element
// slice with value "UNKNOWN".
func isAwarenessSentinel(sideEffects []string) bool {
	return len(sideEffects) == 1 && sideEffects[0] == "UNKNOWN"
}
