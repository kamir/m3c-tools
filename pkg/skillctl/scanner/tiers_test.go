// SPEC-0189 S1 tests — tier resolution, plugin walker, shadow merge,
// SKILL.md anchoring, symlink-loop guard.
package scanner

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/model"
)

// makeSkillDir creates a Claude Code-conventional skill directory:
//
//	<root>/<name>/SKILL.md   (with optional frontmatter body)
//	<root>/<name>/scripts/foo.sh   (loose file — must NOT be a separate skill)
func makeSkillDir(t *testing.T, root, name, frontmatterBody string) {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(frontmatterBody), 0o644); err != nil {
		t.Fatalf("write SKILL.md: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "scripts"), 0o755); err != nil {
		t.Fatalf("mkdir scripts: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "scripts", "foo.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write foo.sh: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "REFERENCES.md"), []byte("# refs\n"), 0o644); err != nil {
		t.Fatalf("write REFERENCES.md: %v", err)
	}
}

// TestTierAware_AnchorsOnSkillMD verifies that the tier-aware path discovers
// EXACTLY one descriptor per directory containing SKILL.md, even when loose
// .md files (e.g. REFERENCES.md) exist alongside.
func TestTierAware_AnchorsOnSkillMD(t *testing.T) {
	tmp := t.TempDir()
	makeSkillDir(t, tmp, "alpha", "---\nname: alpha\ngovernance_level: green\n---\n")
	makeSkillDir(t, tmp, "beta", "")

	s := &Scanner{Roots: []ScanRoot{{Path: tmp, Tier: TierUser}}}
	inv, err := s.Scan()
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if got := len(inv.Skills); got != 2 {
		t.Fatalf("expected 2 skills (alpha, beta), got %d: %+v", got, summarize(inv.Skills))
	}
	for _, sk := range inv.Skills {
		if sk.Tier != string(TierUser) {
			t.Errorf("skill %s has tier %q, want %q", sk.Name, sk.Tier, TierUser)
		}
		if sk.SkillMDPath == "" {
			t.Errorf("skill %s missing SkillMDPath", sk.Name)
		}
		if sk.Type != model.SkillTypeClaudeCodeSkill {
			t.Errorf("skill %s has type %q", sk.Name, sk.Type)
		}
	}
}

// TestTierAware_GovernanceLevel verifies that governance_level in frontmatter
// is lifted into Frontmatter.GovernanceLevel.
func TestTierAware_GovernanceLevel(t *testing.T) {
	tmp := t.TempDir()
	makeSkillDir(t, tmp, "trusted", "---\nname: trusted\ngovernance_level: green\n---\n")
	makeSkillDir(t, tmp, "review", "---\nname: review\ngovernance_level: yellow\n---\n")

	s := &Scanner{Roots: []ScanRoot{{Path: tmp, Tier: TierUser}}}
	inv, err := s.Scan()
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	gov := map[string]string{}
	for _, sk := range inv.Skills {
		if sk.Frontmatter != nil {
			gov[sk.Name] = sk.Frontmatter.GovernanceLevel
		}
	}
	if gov["trusted"] != "green" {
		t.Errorf("trusted governance_level = %q, want green", gov["trusted"])
	}
	if gov["review"] != "yellow" {
		t.Errorf("review governance_level = %q, want yellow", gov["review"])
	}
}

// TestApplyShadowing verifies project > user > plugin precedence and
// shadow annotations.
func TestApplyShadowing(t *testing.T) {
	tmp := t.TempDir()
	projDir := filepath.Join(tmp, "project")
	userDir := filepath.Join(tmp, "user")
	plugDir := filepath.Join(tmp, "plugin")
	makeSkillDir(t, projDir, "qa", "")
	makeSkillDir(t, userDir, "qa", "")
	makeSkillDir(t, userDir, "didactic-session", "")
	makeSkillDir(t, plugDir, "qa", "")
	makeSkillDir(t, plugDir, "seed", "")

	s := &Scanner{
		Roots: []ScanRoot{
			{Path: projDir, Tier: TierProject},
			{Path: userDir, Tier: TierUser},
			{Path: plugDir, Tier: TierPlugin},
		},
	}
	inv, err := s.Scan()
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	// Without IncludeShadowed: 3 winners (qa/project, didactic-session/user, seed/plugin).
	winners := map[string]string{}
	for _, sk := range inv.Skills {
		winners[sk.Name] = sk.Tier
	}
	if winners["qa"] != string(TierProject) {
		t.Errorf("qa winner tier = %q, want project", winners["qa"])
	}
	if winners["didactic-session"] != string(TierUser) {
		t.Errorf("didactic-session winner tier = %q, want user", winners["didactic-session"])
	}
	if winners["seed"] != string(TierPlugin) {
		t.Errorf("seed winner tier = %q, want plugin", winners["seed"])
	}
	if got := len(inv.Skills); got != 3 {
		t.Errorf("default IncludeShadowed=false: expected 3 winners, got %d", got)
	}

	// Check Shadows array on the qa winner.
	for _, sk := range inv.Skills {
		if sk.Name == "qa" && sk.Tier == string(TierProject) {
			if len(sk.Shadows) != 2 {
				t.Errorf("project/qa Shadows count = %d, want 2", len(sk.Shadows))
			}
		}
	}
}

// TestApplyShadowing_IncludeAll verifies IncludeShadowed=true emits all
// occurrences with ShadowedBy populated on losers.
func TestApplyShadowing_IncludeAll(t *testing.T) {
	tmp := t.TempDir()
	projDir := filepath.Join(tmp, "project")
	userDir := filepath.Join(tmp, "user")
	makeSkillDir(t, projDir, "qa", "")
	makeSkillDir(t, userDir, "qa", "")

	s := &Scanner{
		IncludeShadowed: true,
		Roots: []ScanRoot{
			{Path: projDir, Tier: TierProject},
			{Path: userDir, Tier: TierUser},
		},
	}
	inv, err := s.Scan()
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if got := len(inv.Skills); got != 2 {
		t.Fatalf("IncludeShadowed=true: expected 2 rows, got %d", got)
	}
	var winnerID string
	for _, sk := range inv.Skills {
		if sk.Tier == string(TierProject) {
			winnerID = sk.ID
		}
	}
	for _, sk := range inv.Skills {
		if sk.Tier == string(TierUser) {
			if len(sk.ShadowedBy) != 1 || sk.ShadowedBy[0] != winnerID {
				t.Errorf("user/qa ShadowedBy = %v, want [%s]", sk.ShadowedBy, winnerID)
			}
		}
	}
}

// TestPluginCacheRoots verifies the plugin walker discovers a typical
// ~/.claude/plugins/cache/<o>/<p>/<v>/skills/ layout.
func TestPluginCacheRoots(t *testing.T) {
	tmp := t.TempDir()
	pluginsDir := filepath.Join(tmp, "plugins")
	skillsDir := filepath.Join(pluginsDir, "cache", "ouroboros", "ouroboros", "0.20.0", "skills")
	if err := os.MkdirAll(skillsDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	makeSkillDir(t, skillsDir, "seed", "")

	roots := pluginCacheRoots(pluginsDir)
	if len(roots) != 1 {
		t.Fatalf("expected 1 plugin cache root, got %d: %+v", len(roots), roots)
	}
	if roots[0].Tier != TierPlugin {
		t.Errorf("plugin root tier = %q, want %q", roots[0].Tier, TierPlugin)
	}
}

// TestMarketplaceRoots verifies both nested and direct marketplace layouts.
func TestMarketplaceRoots(t *testing.T) {
	tmp := t.TempDir()
	pluginsDir := filepath.Join(tmp, "plugins")
	directSkills := filepath.Join(pluginsDir, "marketplaces", "official", "skills")
	nestedSkills := filepath.Join(pluginsDir, "marketplaces", "official", "plugins", "foo", "skills")
	if err := os.MkdirAll(directSkills, 0o755); err != nil {
		t.Fatalf("mkdir direct: %v", err)
	}
	if err := os.MkdirAll(nestedSkills, 0o755); err != nil {
		t.Fatalf("mkdir nested: %v", err)
	}

	roots := marketplaceRoots(pluginsDir)
	if len(roots) != 2 {
		t.Fatalf("expected 2 marketplace roots (direct+nested), got %d: %+v", len(roots), roots)
	}
	for _, r := range roots {
		if r.Tier != TierPlugin {
			t.Errorf("marketplace root tier = %q, want %q", r.Tier, TierPlugin)
		}
	}
}

// TestResolveDefaults_SourceClaude_IncludesUserAndPlugin verifies that
// SourceClaude expands to user + plugin per SPEC-0189 §10 D3.
func TestResolveDefaults_SourceClaude_IncludesUserAndPlugin(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", tmp)

	// Set up user skills + a plugin cache.
	if err := os.MkdirAll(filepath.Join(tmp, "skills"), 0o755); err != nil {
		t.Fatalf("mkdir user skills: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(tmp, "plugins", "cache", "o", "p", "v", "skills"), 0o755); err != nil {
		t.Fatalf("mkdir plugin: %v", err)
	}

	roots := ResolveDefaults([]Source{SourceClaude})
	tierCounts := map[Tier]int{}
	for _, r := range roots {
		tierCounts[r.Tier]++
	}
	if tierCounts[TierUser] < 1 {
		t.Errorf("SourceClaude should yield ≥1 user-tier root; got %d", tierCounts[TierUser])
	}
	if tierCounts[TierPlugin] < 1 {
		t.Errorf("SourceClaude should yield ≥1 plugin-tier root; got %d", tierCounts[TierPlugin])
	}
}

// TestResolveDefaults_SourceUser_OnlyUser verifies SourceUser does NOT
// include plugin tier (matches SPEC-0189 §4 — user-only on demand).
func TestResolveDefaults_SourceUser_OnlyUser(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", tmp)
	if err := os.MkdirAll(filepath.Join(tmp, "skills"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(tmp, "plugins", "cache", "o", "p", "v", "skills"), 0o755); err != nil {
		t.Fatalf("mkdir plugin: %v", err)
	}
	roots := ResolveDefaults([]Source{SourceUser})
	for _, r := range roots {
		if r.Tier == TierPlugin {
			t.Errorf("SourceUser should not include plugin tier, got %v", r)
		}
	}
}

// TestSymlinkLoop_NoInfiniteWalk creates a symlink that points back into
// the scanned tree and asserts the scanner does not loop. macOS-only —
// Windows symlinks need elevated perms in some configurations.
func TestSymlinkLoop_NoInfiniteWalk(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink test requires POSIX")
	}
	tmp := t.TempDir()
	makeSkillDir(t, tmp, "real", "")
	if err := os.Symlink(filepath.Join(tmp, "real"), filepath.Join(tmp, "loop")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	// Add another symlink that points up — this would loop without guard.
	if err := os.Symlink(tmp, filepath.Join(tmp, "self")); err != nil {
		t.Fatalf("symlink self: %v", err)
	}

	done := make(chan *model.Inventory, 1)
	errc := make(chan error, 1)
	go func() {
		s := &Scanner{Roots: []ScanRoot{{Path: tmp, Tier: TierUser}}}
		inv, err := s.Scan()
		if err != nil {
			errc <- err
			return
		}
		done <- inv
	}()
	select {
	case <-done:
		// Pass: scan completed without hanging.
	case err := <-errc:
		t.Fatalf("scan errored: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatalf("scan did not complete within 5s — symlink-loop guard regressed")
	}
}

func summarize(skills []model.SkillDescriptor) []string {
	out := make([]string, 0, len(skills))
	for _, sk := range skills {
		out = append(out, sk.Tier+":"+sk.Name)
	}
	sort.Strings(out)
	return out
}
