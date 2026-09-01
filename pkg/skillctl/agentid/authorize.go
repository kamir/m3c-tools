package agentid

import "strings"

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

// AuthorizeSkill is the single predicate the gate calls: the skill must be in
// the grant AND every required intent must be in the grant. Returns ("", true)
// when authorized; otherwise ("<reason>", false) with a stable reason token the
// gate maps to a refusal_code. Fail-closed by construction — any miss is a deny.
//
// requiredIntents may be nil/empty (the common P1 case: we gate on skill
// membership and let the skill's own declared intents bound its behaviour at the
// existing SPEC-0202 layer). When provided (e.g. from the skill's signed
// data-scope), each must be granted.
func (g Grant) AuthorizeSkill(skill string, requiredIntents []string) (string, bool) {
	if !g.AllowsSkill(skill) {
		return "skill_not_in_grant", false
	}
	for _, intent := range requiredIntents {
		if !g.AllowsIntent(intent) {
			return "intent_not_in_grant", false
		}
	}
	return "", true
}
