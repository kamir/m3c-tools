package audit

import (
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/model"
	"github.com/kamir/m3c-tools/pkg/skillctl/scanner"
)

func mkSkill(name, tier, gov string, bundle *model.BundleAttestation) model.SkillDescriptor {
	fm := &model.Frontmatter{
		Name:            name,
		GovernanceLevel: gov,
	}
	return model.SkillDescriptor{
		Name:        name,
		Type:        model.SkillTypeClaudeCodeSkill,
		Tier:        tier,
		Frontmatter: fm,
		SourcePath:  "/tmp/.claude/skills/" + name,
		Bundle:      bundle,
	}
}

func mkBundle(chain string, errMsg string, exitCode int) *model.BundleAttestation {
	return &model.BundleAttestation{
		TrustChain:       chain,
		VerifierError:    errMsg,
		VerifierExitCode: exitCode,
		BundleDigest:     "sha256:abcdef",
	}
}

func TestCompute_AllOK(t *testing.T) {
	inv := &model.Inventory{
		Skills: []model.SkillDescriptor{
			mkSkill("foo", "user", "green", mkBundle(scanner.TrustVerified, "", 0)),
			mkSkill("bar", "user", "green", mkBundle(scanner.TrustVerified, "", 0)),
		},
	}
	r := Compute(inv, MinGreen)
	if r.ExitCode != 0 {
		t.Errorf("exit = %d, want 0", r.ExitCode)
	}
	if r.Counts[StateOK] != 2 {
		t.Errorf("OK count = %d, want 2", r.Counts[StateOK])
	}
}

func TestCompute_OneUnverified_Exit2(t *testing.T) {
	inv := &model.Inventory{
		Skills: []model.SkillDescriptor{
			mkSkill("foo", "user", "green", mkBundle(scanner.TrustVerified, "", 0)),
			mkSkill("bar", "user", "yellow", nil), // no bundle = unverified
		},
	}
	r := Compute(inv, MinYellow)
	if r.ExitCode != 2 {
		t.Errorf("exit = %d, want 2", r.ExitCode)
	}
	if r.Counts[StateUnverified] != 1 {
		t.Errorf("UNVERIFIED count = %d, want 1", r.Counts[StateUnverified])
	}
}

func TestCompute_OneBroken_Exit3(t *testing.T) {
	inv := &model.Inventory{
		Skills: []model.SkillDescriptor{
			mkSkill("foo", "user", "green", mkBundle(scanner.TrustVerified, "", 0)),
			mkSkill("hostile", "user", "green", mkBundle(scanner.TrustBroken, "digest mismatch", 0)),
			mkSkill("bar", "user", "yellow", nil),
		},
	}
	r := Compute(inv, MinYellow)
	if r.ExitCode != 3 {
		t.Errorf("exit = %d, want 3 (broken dominates)", r.ExitCode)
	}
	if r.Counts[StateBroken] != 1 {
		t.Errorf("BROKEN count = %d, want 1", r.Counts[StateBroken])
	}
}

func TestCompute_BelowMin(t *testing.T) {
	inv := &model.Inventory{
		Skills: []model.SkillDescriptor{
			mkSkill("yellow-skill", "user", "yellow", mkBundle(scanner.TrustVerified, "", 0)),
		},
	}
	r := Compute(inv, MinGreen)
	if r.ExitCode != 2 {
		t.Errorf("exit = %d, want 2", r.ExitCode)
	}
	if r.Counts[StateBelowMin] != 1 {
		t.Errorf("BELOW_MIN count = %d, want 1", r.Counts[StateBelowMin])
	}
	if r.Verdicts[0].State != StateBelowMin {
		t.Errorf("state = %q, want BELOW_MIN", r.Verdicts[0].State)
	}
}

func TestCompute_NoFloorPassesEverything(t *testing.T) {
	inv := &model.Inventory{
		Skills: []model.SkillDescriptor{
			mkSkill("yellow-skill", "user", "yellow", mkBundle(scanner.TrustVerified, "", 0)),
			mkSkill("red-skill", "user", "red", mkBundle(scanner.TrustVerified, "", 0)),
		},
	}
	r := Compute(inv, MinAny)
	if r.ExitCode != 0 {
		t.Errorf("exit = %d, want 0 (no floor)", r.ExitCode)
	}
}

func TestCompute_NonSkillTypesExcluded(t *testing.T) {
	inv := &model.Inventory{
		Skills: []model.SkillDescriptor{
			{Name: "agent-thing", Type: model.SkillTypeAgent, Tier: "user"},
			{Name: "mcp-thing", Type: model.SkillTypeMCPServer, Tier: "user"},
			mkSkill("real-skill", "user", "green", mkBundle(scanner.TrustVerified, "", 0)),
		},
	}
	r := Compute(inv, MinGreen)
	if r.Total != 1 {
		t.Errorf("total = %d, want 1 (only the claude_code_skill counted)", r.Total)
	}
}

func TestCompute_TierlessSkillsExcluded(t *testing.T) {
	// Legacy SPEC-0115 skills (no tier) are not part of the audit surface.
	inv := &model.Inventory{
		Skills: []model.SkillDescriptor{
			{
				Name:        "legacy",
				Type:        model.SkillTypeClaudeCodeSkill,
				Tier:        "",
				Frontmatter: &model.Frontmatter{Name: "legacy"},
			},
			mkSkill("real", "user", "green", mkBundle(scanner.TrustVerified, "", 0)),
		},
	}
	r := Compute(inv, MinGreen)
	if r.Total != 1 {
		t.Errorf("total = %d, want 1 (legacy skill excluded)", r.Total)
	}
}

func TestCompute_VerdictOrderingBrokenFirst(t *testing.T) {
	inv := &model.Inventory{
		Skills: []model.SkillDescriptor{
			mkSkill("zebra", "user", "green", mkBundle(scanner.TrustVerified, "", 0)),
			mkSkill("alpha", "user", "green", mkBundle(scanner.TrustBroken, "digest mismatch", 0)),
			mkSkill("middle", "user", "yellow", nil),
		},
	}
	r := Compute(inv, MinYellow)
	// BROKEN should sort first (highest severity), then UNVERIFIED, then OK.
	if r.Verdicts[0].State != StateBroken {
		t.Errorf("verdicts[0].state = %q, want BROKEN", r.Verdicts[0].State)
	}
	if r.Verdicts[1].State != StateUnverified {
		t.Errorf("verdicts[1].state = %q, want UNVERIFIED", r.Verdicts[1].State)
	}
	if r.Verdicts[2].State != StateOK {
		t.Errorf("verdicts[2].state = %q, want OK", r.Verdicts[2].State)
	}
}

func TestCleanupEligible(t *testing.T) {
	cases := []struct {
		state          State
		keepUnverified bool
		want           bool
	}{
		{StateBroken, false, true},
		{StateBroken, true, true},      // BROKEN always eligible regardless of flag
		{StateUnverified, false, true}, // default: clean unverified
		{StateUnverified, true, false}, // --keep-unverified preserves
		{StateBelowMin, false, false},  // BELOW_MIN never auto-cleaned
		{StateBelowMin, true, false},
		{StateOK, false, false},
	}
	for _, tc := range cases {
		t.Run(string(tc.state), func(t *testing.T) {
			v := Verdict{State: tc.state}
			if got := v.CleanupEligible(tc.keepUnverified); got != tc.want {
				t.Errorf("state=%s keepUnverified=%v: got %v, want %v",
					tc.state, tc.keepUnverified, got, tc.want)
			}
		})
	}
}

func TestMeetsFloor(t *testing.T) {
	cases := []struct {
		level   string
		minimum MinimumLevel
		want    bool
	}{
		{"green", MinGreen, true},
		{"yellow", MinGreen, false},
		{"red", MinGreen, false},
		{"green", MinYellow, true},
		{"yellow", MinYellow, true},
		{"red", MinYellow, false},
		{"", MinGreen, false},
		{"", MinAny, true},
		{"red", MinRed, true},
	}
	for _, tc := range cases {
		t.Run(tc.level+"_vs_"+string(tc.minimum), func(t *testing.T) {
			if got := meetsFloor(tc.level, tc.minimum); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
