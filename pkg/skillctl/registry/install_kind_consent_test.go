package registry

// Challenge-gate F2 + MED-3 (PR #319).
//
// F2: the G-23 plan derives its target from the UNSIGNED registry tag
// (StagedBundle.Kind), the write routes by the manifest inside the
// digest-verified bundle. When the two disagree, the plan the operator
// approved and the write name different places, so installOne must refuse
// instead of reconciling silently.
//
// MED-3: an agent gets no LESS protection than a skill (SPEC-0432 §5), so the
// agent path carries the same downgrade gate: replaying an older, still
// attested admit must not overwrite a newer agent without --allow-downgrade.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
)

// TestInstallRefusesTagManifestKindMismatch: tag says skill, manifest says
// agent, an agent file already exists. The refusal must name both kinds and
// leave the existing agent untouched (it never appeared in the approved
// plan's overwrite list). Counter-probe: with the tag agreeing, the same
// bundle installs.
func TestInstallRefusesTagManifestKindMismatch(t *testing.T) {
	skillsDir, agentsDir := homeWith(t)
	skb := makeAgentSkb(t, "sneaky", nil, skillbundle.SchemaAgent, skillbundle.KindAgent)

	// A pre-existing agent the mismatch would have overwritten unannounced.
	if err := os.MkdirAll(agentsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(agentsDir, "sneaky.md")
	if err := os.WriteFile(existing, []byte("KEEP ME\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	staged := stagedAgent(t, "sneaky", skb)
	staged.Kind = skillbundle.KindSkill // the unsigned tag projection lies

	_, err := installOne(staged, InstallOpts{SkillsDir: skillsDir})
	if err == nil {
		t.Fatal("installOne accepted a tag/manifest kind mismatch")
	}
	for _, want := range []string{skillbundle.KindSkill, skillbundle.KindAgent, "nothing was installed"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
	got, readErr := os.ReadFile(existing)
	if readErr != nil || string(got) != "KEEP ME\n" {
		t.Fatalf("the existing agent was touched despite the refusal: %q %v", got, readErr)
	}

	// Counter-probe: an agreeing tag installs the same bundle.
	staged2 := stagedAgent(t, "sneaky", skb)
	staged2.Kind = skillbundle.KindAgent
	if _, err := installOne(staged2, InstallOpts{SkillsDir: skillsDir}); err != nil {
		t.Fatalf("agreeing kind must install: %v", err)
	}
}

// TestInstallAgentDowngradeGate: replaying an older admit refuses without
// --allow-downgrade and proceeds with it, exactly like the skill path.
func TestInstallAgentDowngradeGate(t *testing.T) {
	skillsDir, _ := homeWith(t)
	skb := makeAgentSkb(t, "replayed", nil, skillbundle.SchemaAgent, skillbundle.KindAgent)

	newer := stagedAgent(t, "replayed", skb)
	newer.Version = "2.0.0"
	if _, err := installOne(newer, InstallOpts{SkillsDir: skillsDir}); err != nil {
		t.Fatalf("install 2.0.0: %v", err)
	}

	older := stagedAgent(t, "replayed", skb)
	older.Version = "1.0.0"
	_, err := installOne(older, InstallOpts{SkillsDir: skillsDir})
	if err == nil {
		t.Fatal("an older agent overwrote a newer one without --allow-downgrade")
	}
	for _, want := range []string{"2.0.0", "1.0.0", "--allow-downgrade"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}

	// The explicit flag is the consent the gate asks for.
	if _, err := installOne(older, InstallOpts{SkillsDir: skillsDir, AllowDowngrade: true}); err != nil {
		t.Fatalf("--allow-downgrade must permit the replay: %v", err)
	}
}
