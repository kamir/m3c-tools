package registry

import (
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
)

// The SPEC-0432 §4 namespace. The load-bearing property is that every call
// written before SPEC-0432 keeps its meaning: a bare name is a skill, and a
// registry item with no kind tag is a skill.

func TestSplitKindName(t *testing.T) {
	for _, tc := range []struct{ in, wantKind, wantName string }{
		{"review-plan", skillbundle.KindSkill, "review-plan"},       // unchanged
		{"skill:review-plan", skillbundle.KindSkill, "review-plan"}, // explicit
		{"agent:release-agent", skillbundle.KindAgent, "release-agent"},
		// A colon that is not a kind stays part of the name rather than
		// silently splitting a name nobody meant to split.
		{"weird:name", skillbundle.KindSkill, "weird:name"},
	} {
		k, n := SplitKindName(tc.in)
		if k != tc.wantKind || n != tc.wantName {
			t.Errorf("SplitKindName(%q) = (%q, %q), want (%q, %q)",
				tc.in, k, n, tc.wantKind, tc.wantName)
		}
	}
}

// TestItemKindDefaultsToSkill: the 78 bundles admitted before SPEC-0432 carry
// no kind tag and must keep reading as skills.
func TestItemKindDefaultsToSkill(t *testing.T) {
	legacy := map[string]any{"tags": "m3c-skill-bundle,skill:review-plan,skill-registry:self"}
	if got := ItemKind(legacy); got != skillbundle.KindSkill {
		t.Errorf("legacy item kind = %q, want %q", got, skillbundle.KindSkill)
	}
	agent := map[string]any{"tags": "m3c-skill-bundle,skill:release-agent,kind:agent"}
	if got := ItemKind(agent); got != skillbundle.KindAgent {
		t.Errorf("agent item kind = %q, want %q", got, skillbundle.KindAgent)
	}
}

// TestAdmittedTagsStampKindOnlyForAgents is the backwards-compatibility guard:
// a skill's tag set must not gain a single tag, or every existing item would
// differ from a freshly published one for no reason.
func TestAdmittedTagsStampKindOnlyForAgents(t *testing.T) {
	base := SkillMeta{
		Name: "x", Version: "1.0.0", BundleDigest: "sha256:ab",
		AuthorIdentity: "id:t", GovernanceLevel: "green", PackedOnHost: "h",
	}
	hasKindTag := func(tags []string) bool {
		for _, tg := range tags {
			if len(tg) > len(KindTagPrefix) && tg[:len(KindTagPrefix)] == KindTagPrefix {
				return true
			}
		}
		return false
	}

	skillTags := buildAdmittedTags(base, "er1-inline", "")
	if hasKindTag(skillTags) {
		t.Errorf("a skill was stamped with a kind tag: %v", skillTags)
	}

	explicit := base
	explicit.Kind = skillbundle.KindSkill
	if tags := buildAdmittedTags(explicit, "er1-inline", ""); hasKindTag(tags) {
		t.Errorf("an explicit skill was stamped with a kind tag: %v", tags)
	}

	agent := base
	agent.Kind = skillbundle.KindAgent
	agentTags := buildAdmittedTags(agent, "er1-inline", "")
	if !hasKindTag(agentTags) {
		t.Fatalf("an agent was NOT stamped with a kind tag: %v", agentTags)
	}
	if len(agentTags) != len(skillTags)+1 {
		t.Errorf("agent tags = %d, skill tags = %d; the kind must add exactly one",
			len(agentTags), len(skillTags))
	}
}

// TestSameNameDifferentKind is AC-6: a skill and an agent of the same name do
// not disturb each other, because the kind tag separates them.
func TestSameNameDifferentKind(t *testing.T) {
	skillItem := map[string]any{"tags": "skill:helper"}
	agentItem := map[string]any{"tags": "skill:helper,kind:agent"}

	if ItemKind(skillItem) == ItemKind(agentItem) {
		t.Fatal("a skill and an agent of the same name are indistinguishable")
	}
	k, n := SplitKindName("agent:helper")
	if k != skillbundle.KindAgent || n != "helper" {
		t.Fatalf("agent:helper resolved to (%q, %q)", k, n)
	}
	k, n = SplitKindName("helper")
	if k != skillbundle.KindSkill || n != "helper" {
		t.Fatalf("helper resolved to (%q, %q)", k, n)
	}
}
