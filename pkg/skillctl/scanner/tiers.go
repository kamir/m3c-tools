// Tier-aware scanning + shadow detection — SPEC-0189 Phase 1.
//
// Scans a ScanRoot anchored on SKILL.md (not loose *.md), then runs a
// shadow-merge across the union of inventories from all roots so that
// project-tier skills win over user-tier, which win over plugin-tier.
package scanner

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/hasher"
	"github.com/kamir/m3c-tools/pkg/skillctl/model"
	"github.com/kamir/m3c-tools/pkg/skillctl/parser"
)

// scanTierRoot walks a single ScanRoot and emits one descriptor per
// directory containing a SKILL.md file. Loose markdown files inside a
// skill dir are NOT separate skills (per SPEC-0189 §3).
func (s *Scanner) scanTierRoot(root ScanRoot, inv *model.Inventory) error {
	info, err := os.Stat(root.Path)
	if err != nil || !info.IsDir() {
		return nil
	}

	return filepath.WalkDir(root.Path, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		// Only look at files literally named SKILL.md.
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			// Symlink-loop guard.
			if d.Type()&fs.ModeSymlink != 0 {
				real, err := filepath.EvalSymlinks(path)
				if err != nil {
					return nil
				}
				if s.visited[real] {
					return filepath.SkipDir
				}
				s.visited[real] = true
			}
			return nil
		}
		if d.Name() != "SKILL.md" {
			return nil
		}
		// File-level symlink guard.
		if d.Type()&fs.ModeSymlink != 0 {
			real, err := filepath.EvalSymlinks(path)
			if err != nil {
				return nil
			}
			if s.visited[real] {
				return nil
			}
			s.visited[real] = true
		}
		s.addClaudeSkillTiered(path, root.Tier, inv)
		return nil
	})
}

// addClaudeSkillTiered reads a SKILL.md file and adds a descriptor with
// Tier + SkillMDPath populated.
func (s *Scanner) addClaudeSkillTiered(skillMDPath string, tier Tier, inv *model.Inventory) {
	data, err := os.ReadFile(skillMDPath)
	if err != nil {
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	hash := hasher.ContentHash(data)

	// The skill name is the parent directory's basename (the conventional
	// Claude Code shape: <name>/SKILL.md).
	parentDir := filepath.Dir(skillMDPath)
	name := filepath.Base(parentDir)
	project := projectLabelForTier(skillMDPath, tier)

	desc := model.SkillDescriptor{
		ID:               fmt.Sprintf("%s/%s", tier, name),
		Name:             name,
		Type:             model.SkillTypeClaudeCodeSkill,
		SourcePath:       parentDir,
		SourceProject:    project,
		DiscoveredAt:     now,
		ContentHash:      hash,
		ContentSizeBytes: int64(len(data)),
		Dependencies:     make([]string, 0),
		ConflictsWith:    make([]string, 0),
		Tier:             string(tier),
		SkillMDPath:      skillMDPath,
	}

	// Parse frontmatter — same path as the legacy mode.
	fm, _, parseErr := parser.Parse(data)
	if parseErr == nil && fm != nil {
		desc.Frontmatter = fm
		desc.HasYAMLFrontmatter = true
		// For tiered scans we deliberately do NOT override desc.Name from
		// fm.Name — the directory name is the canonical identifier in
		// Claude Code resolution. fm.Name often duplicates the dir name.
		if fm.GovernanceLevel == "" {
			// Backwards-compat: lift governance_level out of legacy
			// Metadata bag if present.
			if v, ok := fm.Metadata["governance_level"].(string); ok {
				fm.GovernanceLevel = v
			}
		}
	}
	inv.Skills = append(inv.Skills, desc)
}

// projectLabelForTier produces a useful SourceProject label for tier-scoped
// skills. For TierProject the existing detectProject (nearest .git) wins;
// for TierUser the label is "user-global"; for TierPlugin we extract the
// plugin owner/name/version from the path.
func projectLabelForTier(skillMDPath string, tier Tier) string {
	switch tier {
	case TierUser:
		return "user-global"
	case TierPlugin:
		return pluginLabel(skillMDPath)
	default:
		return detectProject(skillMDPath)
	}
}

// pluginLabel extracts a "<owner>/<plugin>@<version>" label from a path
// shaped ~/.claude/plugins/cache/<o>/<p>/<v>/skills/<n>/SKILL.md, or
// "marketplace:<m>" for marketplace-tier paths.
func pluginLabel(skillMDPath string) string {
	parts := strings.Split(filepath.ToSlash(skillMDPath), "/")
	for i := 0; i < len(parts); i++ {
		if parts[i] == "cache" && i+3 < len(parts) {
			return parts[i+1] + "/" + parts[i+2] + "@" + parts[i+3]
		}
		if parts[i] == "marketplaces" && i+1 < len(parts) {
			return "marketplace:" + parts[i+1]
		}
	}
	return "plugin-unknown"
}

// applyShadowing walks the inventory and resolves tier precedence per
// skill name: project > user > plugin. The winner per name keeps its
// row and gets Shadows[] populated; losers get ShadowedBy[] populated.
// If IncludeShadowed is false, losers are removed from inv.Skills.
//
// Only TierClaudeCodeSkill descriptors participate; other types
// (commands, agents, MCP, etc.) are passed through unchanged.
func applyShadowing(inv *model.Inventory, includeShadowed bool) {
	tierRank := map[string]int{
		string(TierProject): 3,
		string(TierUser):    2,
		string(TierPlugin):  1,
	}

	// Group claude_code_skills by name; non-claude rows pass through.
	type idx struct {
		i    int
		rank int
	}
	groups := map[string][]idx{}
	for i, sk := range inv.Skills {
		if sk.Type != model.SkillTypeClaudeCodeSkill || sk.Tier == "" {
			continue
		}
		groups[sk.Name] = append(groups[sk.Name], idx{i: i, rank: tierRank[sk.Tier]})
	}

	dropIdx := map[int]bool{}
	for name, members := range groups {
		if len(members) <= 1 {
			continue
		}
		// Find winner: highest rank; tie-break on first-seen.
		winner := members[0]
		for _, m := range members[1:] {
			if m.rank > winner.rank {
				winner = m
			}
		}
		// Annotate winner + losers.
		for _, m := range members {
			if m.i == winner.i {
				continue
			}
			loserID := inv.Skills[m.i].ID
			inv.Skills[m.i].ShadowedBy = []string{inv.Skills[winner.i].ID}
			inv.Skills[winner.i].Shadows = append(inv.Skills[winner.i].Shadows, loserID)
			if !includeShadowed {
				dropIdx[m.i] = true
			}
		}
		_ = name
	}

	if len(dropIdx) == 0 {
		return
	}
	out := make([]model.SkillDescriptor, 0, len(inv.Skills)-len(dropIdx))
	for i, sk := range inv.Skills {
		if dropIdx[i] {
			continue
		}
		out = append(out, sk)
	}
	inv.Skills = out
}
