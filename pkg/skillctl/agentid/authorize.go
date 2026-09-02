package agentid

import (
	"strconv"
	"strings"
)

// authorize.go — the SPEC-0277 §3 authorization predicate ("skill is verified
// AND within the agent's grant"). The crypto half (the AgentID verifies) lives
// in verify.go; THIS file is the pure set-membership half the runtime gate uses
// to DENY anything outside the grant (fail-closed). It is deliberately tiny and
// stdlib-only so the gate can call it without pulling in any dependency.

// SkillName extracts the matchable skill NAME from a grant entry or an invoked
// skill reference: the component before the first '@' (the version constraint).
// "fetch-contract@>=1.0.0" → "fetch-contract"; "fetch-contract" → "fetch-contract".
// Matching is by name in P0/P1 — version-constraint satisfaction is a P2 refinement
// (the grant entry's constraint is preserved verbatim in the signed payload so a
// later version-aware check needs no format change).
func SkillName(ref string) string {
	ref = strings.TrimSpace(ref)
	if i := strings.IndexByte(ref, '@'); i >= 0 {
		ref = ref[:i]
	}
	return strings.TrimSpace(ref)
}

// AllowsSkill reports whether the grant permits invoking skill (by name). The
// match is case-sensitive on the name component (skill names are case-sensitive
// directories under ~/.claude/skills). An empty grant.skills denies everything
// (fail-closed) — an AgentID with no skills granted can invoke no skills.
func (g Grant) AllowsSkill(skill string) bool {
	want := SkillName(skill)
	if want == "" {
		return false
	}
	for _, s := range g.Skills {
		if SkillName(s) == want {
			return true
		}
	}
	return false
}

// AllowsIntent reports whether the grant permits the given SPEC-0196 intent
// (e.g. "network:read"). Set-membership, case-sensitive (the intent vocabulary
// is lowercase by convention). An empty required intent is permitted (the caller
// had no intent to check); an empty grant.intents denies any non-empty intent.
func (g Grant) AllowsIntent(intent string) bool {
	intent = strings.TrimSpace(intent)
	if intent == "" {
		return true
	}
	for _, i := range g.Intents {
		if strings.TrimSpace(i) == intent {
			return true
		}
	}
	return false
}

// AllowsDataScope reports whether the grant permits touching the given SPEC-0196
// data-scope id (e.g. "ds:er1/plm/skill-creations"). Set-membership,
// case-sensitive, mirroring AllowsIntent. An empty required scope is permitted (no
// scope to check). NOTE: unlike intents, an EMPTY grant.data_scopes does NOT deny a
// declared scope — AuthorizeSkillScoped enforces data-scopes only when the grant
// RESTRICTS them (see there), so this predicate is only consulted when the grant is
// non-empty.
func (g Grant) AllowsDataScope(scope string) bool {
	scope = strings.TrimSpace(scope)
	if scope == "" {
		return true
	}
	for _, s := range g.DataScopes {
		if strings.TrimSpace(s) == scope {
			return true
		}
	}
	return false
}

// withinDeclaredLimits reports the first grant ceiling the skill's declared
// consumption would exceed. For each key the GRANT caps (Grant.Limits), if the
// skill declares a value for the SAME key, the declared value must be numerically
// <= the cap. A key the grant does not cap is unrestricted here (the grant only
// bounds what it names). A cap or a declared value that does not parse as a number
// fails CLOSED (returns that key, false) — a malformed ceiling can never be shown
// "satisfied". Returns ("", true) when every capped, declared value is within its
// ceiling. Example (Estonia's ask): grant {"spend_eur_max":"0"} + a skill declaring
// {"spend_eur_max":"5"} → ("spend_eur_max", false); a skill declaring nothing → ok.
func (g Grant) withinDeclaredLimits(declared map[string]string) (string, bool) {
	for key, capStr := range g.Limits {
		decStr, ok := declared[key]
		if !ok {
			continue // the skill declares no consumption of this capped resource
		}
		capVal, cerr := strconv.ParseFloat(strings.TrimSpace(capStr), 64)
		decVal, derr := strconv.ParseFloat(strings.TrimSpace(decStr), 64)
		if cerr != nil || derr != nil {
			return key, false // fail-closed: an unparseable ceiling/declaration is never satisfied
		}
		if decVal > capVal {
			return key, false
		}
	}
	return "", true
}

// SkillRequirements is the skill's author-signed declared scope, resolved from its
// DIGEST-VERIFIED bundle.json by the gate. Every field is optional; a zero value
// reproduces the pre-IS-T7 name-only check.
type SkillRequirements struct {
	// Intents are the capability tokens the skill's signed manifest implies (e.g.
	// "fs:write", "network:read"), checked against Grant.Intents (strict allowlist).
	Intents []string
	// DataScopes are the data-scope ids the skill declares (data_dependencies[].id),
	// checked against Grant.DataScopes — but only when the grant restricts scopes.
	DataScopes []string
	// Limits are the skill's declared resource ceilings, keyed like Grant.Limits
	// (e.g. {"spend_eur_max":"5"}), each checked against the grant's cap.
	Limits map[string]string
}

// AuthorizeSkillScoped is the full SPEC-0277 §3 authorization predicate the gate
// calls: the skill must be NAMED in the grant, and every capability intent, data
// scope, and declared resource ceiling in its signed manifest must be within the
// mandate's grant. Returns ("", true) when authorized; otherwise
// ("<reason>", false) with a stable reason token (skill_not_in_grant |
// intent_not_in_grant | data_scope_not_in_grant | limit_exceeded). Fail-closed by
// construction — any miss is a deny.
//
// Data-scope enforcement is GUARDED on a restricting grant (len(DataScopes) > 0):
// Grant.DataScopes is an optional, fine-grained allowlist, so a grant that names no
// scopes does not bound them here (they stay bounded by the skill's own SPEC-0202
// data-scope layer); otherwise every scope-declaring skill under a scope-silent
// grant would be denied. Intents and limits have no such guard — an empty
// grant.intents denies any declared intent (fail-closed allowlist), and an absent
// cap simply does not restrict that resource.
func (g Grant) AuthorizeSkillScoped(skill string, req SkillRequirements) (string, bool) {
	if !g.AllowsSkill(skill) {
		return "skill_not_in_grant", false
	}
	for _, intent := range req.Intents {
		if !g.AllowsIntent(intent) {
			return "intent_not_in_grant", false
		}
	}
	if len(g.DataScopes) > 0 {
		for _, scope := range req.DataScopes {
			if !g.AllowsDataScope(scope) {
				return "data_scope_not_in_grant", false
			}
		}
	}
	if _, ok := g.withinDeclaredLimits(req.Limits); !ok {
		return "limit_exceeded", false
	}
	return "", true
}

// AuthorizeSkill is the intent-only convenience predicate (skill NAME + required
// intents). It delegates to AuthorizeSkillScoped so there is ONE enforcement path.
//
// requiredIntents may be nil/empty (gate on skill membership only, letting the
// skill's own declared behaviour be bounded at the SPEC-0202 layer). When provided,
// each must be granted.
func (g Grant) AuthorizeSkill(skill string, requiredIntents []string) (string, bool) {
	return g.AuthorizeSkillScoped(skill, SkillRequirements{Intents: requiredIntents})
}
