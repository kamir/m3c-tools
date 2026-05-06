// Package scanner walks directories to discover Claude Code skill sources.
package scanner

import (
	"encoding/json"
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

// skipDirs lists directory names to skip during traversal.
var skipDirs = map[string]bool{
	".git":        true,
	"node_modules": true,
	"__pycache__": true,
	".venv":       true,
	"vendor":      true,
	"build":       true,
}

// Scanner walks filesystem paths to discover skill sources.
type Scanner struct {
	Paths       []string
	Recursive   bool
	IncludeHome bool

	// visited tracks resolved real paths to avoid symlink loops.
	visited map[string]bool
}

// Scan walks all configured paths and returns a complete Inventory.
func (s *Scanner) Scan() (*model.Inventory, error) {
	s.visited = make(map[string]bool)

	now := time.Now().UTC().Format(time.RFC3339)
	inv := &model.Inventory{
		ScannedAt: now,
		ScanPaths: make([]string, 0),
		Skills:    make([]model.SkillDescriptor, 0),
		ByType:    make(map[string]int),
		ByProject: make(map[string]int),
	}

	// Scan provided paths.
	for _, p := range s.Paths {
		abs, err := filepath.Abs(p)
		if err != nil {
			return nil, fmt.Errorf("resolving path %s: %w", p, err)
		}
		inv.ScanPaths = append(inv.ScanPaths, abs)
		if err := s.scanDir(abs, inv); err != nil {
			return nil, err
		}
	}

	// Scan home directory if requested.
	if s.IncludeHome {
		home, err := os.UserHomeDir()
		if err == nil {
			claudeHome := filepath.Join(home, ".claude")
			inv.ScanPaths = append(inv.ScanPaths, claudeHome)
			if err := s.scanHomeDir(claudeHome, inv); err != nil {
				// Non-fatal: home dir may not have .claude
				_ = err
			}
		}
	}

	// Run duplicate detection.
	hasher.DetectDuplicates(inv.Skills)

	// Compute summary stats.
	inv.TotalCount = len(inv.Skills)
	for _, sk := range inv.Skills {
		inv.ByType[string(sk.Type)]++
		inv.ByProject[sk.SourceProject]++
		if sk.DuplicateOf != nil {
			inv.Duplicates++
		}
		if sk.Type == model.SkillTypeSkillIndex {
			inv.SkillIndexCount++
		} else if !sk.HasYAMLFrontmatter {
			inv.NoFrontmatter++
		}
	}

	return inv, nil
}

// scanDir recursively walks a directory looking for skill sources.
func (s *Scanner) scanDir(root string, inv *model.Inventory) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip inaccessible entries
		}

		// Skip blacklisted directories.
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			// Handle symlink loops.
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

		// Check for symlink on files too.
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

		rel, _ := filepath.Rel(root, path)
		parts := strings.Split(filepath.ToSlash(rel), "/")

		// Detect skill type based on path pattern.
		switch {
		case s.matchClaudeSkill(parts, d.Name()):
			s.addSkill(path, model.SkillTypeClaudeCodeSkill, inv)

		case d.Name() == "CLAUDE.md":
			s.addSkill(path, model.SkillTypeSkillIndex, inv)

		case s.matchCommand(parts, d.Name()):
			s.addSkill(path, model.SkillTypeCommand, inv)

		case s.matchAgent(parts, d.Name()):
			s.addSkill(path, model.SkillTypeAgent, inv)

		case s.matchMCPConfig(parts, d.Name()):
			s.addMCPServers(path, inv)
		}

		return nil
	})
}

// scanHomeDir scans the user-global ~/.claude/ directory.
func (s *Scanner) scanHomeDir(claudeDir string, inv *model.Inventory) error {
	info, err := os.Stat(claudeDir)
	if err != nil || !info.IsDir() {
		return nil
	}

	// Skills: ~/.claude/skills/*/
	skillsDir := filepath.Join(claudeDir, "skills")
	if entries, err := os.ReadDir(skillsDir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				subDir := filepath.Join(skillsDir, e.Name())
				mdFiles, _ := filepath.Glob(filepath.Join(subDir, "*.md"))
				for _, md := range mdFiles {
					s.addSkillWithProject(md, model.SkillTypeClaudeCodeSkill, "user-global", inv)
				}
			}
		}
	}

	// Commands: ~/.claude/commands/*.md
	cmdsDir := filepath.Join(claudeDir, "commands")
	if mdFiles, err := filepath.Glob(filepath.Join(cmdsDir, "*.md")); err == nil {
		for _, md := range mdFiles {
			s.addSkillWithProject(md, model.SkillTypeCommand, "user-global", inv)
		}
	}

	// Agents: ~/.claude/agents/*.md
	agentsDir := filepath.Join(claudeDir, "agents")
	if mdFiles, err := filepath.Glob(filepath.Join(agentsDir, "*.md")); err == nil {
		for _, md := range mdFiles {
			s.addSkillWithProject(md, model.SkillTypeAgent, "user-global", inv)
		}
	}

	// MCP configs
	for _, name := range []string{"settings.json", "settings.local.json"} {
		cfgPath := filepath.Join(claudeDir, name)
		if _, err := os.Stat(cfgPath); err == nil {
			s.addMCPServersWithProject(cfgPath, "user-global", inv)
		}
	}

	return nil
}

// matchClaudeSkill checks if the path matches .claude/skills/<dir>/<file>.md
// Parts example: [".claude", "skills", "deploy", "deploy.md"]
func (s *Scanner) matchClaudeSkill(parts []string, name string) bool {
	if len(parts) < 4 || !strings.HasSuffix(name, ".md") {
		return false
	}
	// Look for ".claude" followed by "skills" anywhere in the path.
	for i := 0; i < len(parts)-3; i++ {
		if parts[i] == ".claude" && parts[i+1] == "skills" {
			return true
		}
	}
	return false
}

// matchCommand checks if the path matches .claude/commands/<file>.md
// Parts example: [".claude", "commands", "review.md"]
func (s *Scanner) matchCommand(parts []string, name string) bool {
	if len(parts) < 3 || !strings.HasSuffix(name, ".md") {
		return false
	}
	for i := 0; i < len(parts)-2; i++ {
		if parts[i] == ".claude" && parts[i+1] == "commands" {
			return true
		}
	}
	return false
}

// matchAgent checks if the path matches .claude/agents/<file>.md
// Parts example: [".claude", "agents", "researcher.md"]
func (s *Scanner) matchAgent(parts []string, name string) bool {
	if len(parts) < 3 || !strings.HasSuffix(name, ".md") {
		return false
	}
	for i := 0; i < len(parts)-2; i++ {
		if parts[i] == ".claude" && parts[i+1] == "agents" {
			return true
		}
	}
	return false
}

// matchMCPConfig checks if the path matches .claude/settings.json or .claude/settings.local.json
func (s *Scanner) matchMCPConfig(parts []string, name string) bool {
	if len(parts) < 2 {
		return false
	}
	return parts[len(parts)-2] == ".claude" &&
		(name == "settings.json" || name == "settings.local.json")
}

// addSkill reads a file, parses it, and adds it to the inventory.
func (s *Scanner) addSkill(path string, skillType model.SkillType, inv *model.Inventory) {
	project := detectProject(path)
	s.addSkillWithProject(path, skillType, project, inv)
}

// addSkillWithProject reads a file, parses it, and adds it with a specified project name.
func (s *Scanner) addSkillWithProject(path string, skillType model.SkillType, project string, inv *model.Inventory) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)
	hash := hasher.ContentHash(data)
	name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))

	desc := model.SkillDescriptor{
		ID:               fmt.Sprintf("%s/%s", project, name),
		Name:             name,
		Type:             skillType,
		SourcePath:       path,
		SourceProject:    project,
		DiscoveredAt:     now,
		ContentHash:      hash,
		ContentSizeBytes: int64(len(data)),
		Dependencies:     make([]string, 0),
		ConflictsWith:    make([]string, 0),
	}

	// Try parsing frontmatter for markdown files.
	if strings.HasSuffix(path, ".md") {
		fm, _, parseErr := parser.Parse(data)
		if parseErr == nil && fm != nil {
			desc.Frontmatter = fm
			desc.HasYAMLFrontmatter = true
			if fm.Name != "" {
				desc.Name = fm.Name
				desc.ID = fmt.Sprintf("%s/%s", project, fm.Name)
			}
		}
	}

	inv.Skills = append(inv.Skills, desc)
}

// addMCPServers parses a settings.json file and creates one SkillDescriptor per MCP server.
func (s *Scanner) addMCPServers(path string, inv *model.Inventory) {
	project := detectProject(path)
	s.addMCPServersWithProject(path, project, inv)
}

// addMCPServersWithProject parses a settings.json file with a specified project.
func (s *Scanner) addMCPServersWithProject(path string, project string, inv *model.Inventory) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	// Parse the JSON to extract mcpServers keys.
	var settings struct {
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
	}
	if err := json.Unmarshal(data, &settings); err != nil {
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)
	for serverName, rawConfig := range settings.MCPServers {
		configData, _ := json.Marshal(rawConfig)
		hash := hasher.ContentHash(configData)

		desc := model.SkillDescriptor{
			ID:               fmt.Sprintf("%s/mcp-%s", project, serverName),
			Name:             serverName,
			Type:             model.SkillTypeMCPServer,
			SourcePath:       path,
			SourceProject:    project,
			DiscoveredAt:     now,
			ContentHash:      hash,
			ContentSizeBytes: int64(len(configData)),
			Dependencies:     make([]string, 0),
			ConflictsWith:    make([]string, 0),
		}
		inv.Skills = append(inv.Skills, desc)
	}
}

// detectProject walks up from the file path to find the nearest .git/ directory
// and returns the containing directory name as the project name.
func detectProject(path string) string {
	dir := filepath.Dir(path)
	for {
		gitDir := filepath.Join(dir, ".git")
		if info, err := os.Stat(gitDir); err == nil && info.IsDir() {
			return filepath.Base(dir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "unknown"
}
