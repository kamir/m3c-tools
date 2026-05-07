package skillbundle

// SPEC-0196 §3.3 — Intent / data-dependencies cross-rule validator.
//
// Go port of aims-core/flask/modules/skill_registry/skill_service.py
// `_validate_intent_data_cross_rules`. The two implementations MUST stay
// behavior-identical: the server uses this exact rule set at admission time
// (admit_from_scan step 1.5, intent-PATCH); skillctl pack must reject the
// same shapes pre-pack so the trainer sees the failure before signing.
//
// Locked decisions (S3-DECISIONS.md S3.2):
//   Q1 = A — pre-pack validation; same shape as the Python server-side rule.
//   Q2 = A — exit codes 11 (missing_governance_intent) for green+destructive,
//            12 (intent_data_inconsistent) for the other two cross-rules.
//   Q3 = A — no override flag in v1.

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

	// RuleNetworkFalseHttpDep — Rule 2: intent.network=false but a
	// data_dependency declares kind="http_endpoint". Maps to pack-time
	// exit 12 (intent_data_inconsistent).
	RuleNetworkFalseHttpDep CrossRuleViolation = "network_false_http_dep"

	// RuleWriteAccessNonDestructive — Rule 3: a data_dependency with
	// access="write" is inconsistent with intent.destructive=false. Maps
	// to pack-time exit 12 (intent_data_inconsistent).
	RuleWriteAccessNonDestructive CrossRuleViolation = "write_access_non_destructive"
)

// ValidateIntentDataCrossRules applies the three SPEC-0196 §3.3 cross-rules
// to a triplet of (intent, author_governance_intent, data_dependencies).
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
// ValidateIntentDataCrossRules. Pack-time callers (skillctl pack) use this
// to gate archive emission on a fully-formed BundleManifest. Returns
// RuleNone on a valid or sentinel-shaped manifest.
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
