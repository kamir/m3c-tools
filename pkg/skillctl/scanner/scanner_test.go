package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/model"
)

// setupTestTree creates a temporary directory tree mimicking a project with
// Claude Code skills, commands, agents, CLAUDE.md, and MCP settings.
func setupTestTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()

	// Create a fake .git directory so project detection works.
	os.MkdirAll(filepath.Join(root, ".git"), 0o755)

	// Claude Code skill: .claude/skills/deploy/deploy.md
	skillDir := filepath.Join(root, ".claude", "skills", "deploy")
	os.MkdirAll(skillDir, 0o755)
	os.WriteFile(filepath.Join(skillDir, "deploy.md"), []byte(`---
name: deploy-stage
version: 1.0.0
description: Deploy to staging
allowed-tools:
  - Bash
category: deployment
---
Deploy the application to the staging environment.
`), 0o644)

	// Command: .claude/commands/review.md
	cmdDir := filepath.Join(root, ".claude", "commands")
	os.MkdirAll(cmdDir, 0o755)
	os.WriteFile(filepath.Join(cmdDir, "review.md"), []byte(`# Review command
Review all changes before merge.
`), 0o644)

	// Agent: .claude/agents/researcher.md
	agentDir := filepath.Join(root, ".claude", "agents")
	os.MkdirAll(agentDir, 0o755)
	os.WriteFile(filepath.Join(agentDir, "researcher.md"), []byte(`---
name: researcher
description: Research agent
---
Research topics thoroughly.
`), 0o644)

	// CLAUDE.md at root
	os.WriteFile(filepath.Join(root, "CLAUDE.md"), []byte(`# Project Instructions
Build stuff.
`), 0o644)

	// MCP settings: .claude/settings.json
	settings := map[string]interface{}{
		"mcpServers": map[string]interface{}{
			"filesystem": map[string]string{
				"command": "npx",
			},
			"github": map[string]string{
				"command": "gh-mcp",
			},
		},
	}
	settingsData, _ := json.Marshal(settings)
	os.WriteFile(filepath.Join(root, ".claude", "settings.json"), settingsData, 0o644)

	return root
}

func TestScanFindsAllTypes(t *testing.T) {
	root := setupTestTree(t)

	sc := &Scanner{
		Paths:     []string{root},
		Recursive: true,
	}

	inv, err := sc.Scan()
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}

	if inv.TotalCount < 5 {
		t.Errorf("total count = %d, want >= 5 (skill + command + agent + CLAUDE.md + 2 MCP)", inv.TotalCount)
	}

	// Check we found each type.
	wantTypes := map[model.SkillType]bool{
		model.SkillTypeClaudeCodeSkill: false,
		model.SkillTypeClaudeMD:        false,
		model.SkillTypeCommand:         false,
		model.SkillTypeMCPServer:       false,
		model.SkillTypeAgent:           false,
	}
	for _, sk := range inv.Skills {
		wantTypes[sk.Type] = true
	}
	for st, found := range wantTypes {
		if !found {
			t.Errorf("type %s not found in scan results", st)
		}
	}
}

func TestScanFrontmatterParsed(t *testing.T) {
	root := setupTestTree(t)

	sc := &Scanner{
		Paths:     []string{root},
		Recursive: true,
	}

	inv, err := sc.Scan()
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}

	var deploySkill *model.SkillDescriptor
	for i := range inv.Skills {
		if inv.Skills[i].Type == model.SkillTypeClaudeCodeSkill {
			deploySkill = &inv.Skills[i]
			break
		}
	}

	if deploySkill == nil {
		t.Fatal("deploy skill not found")
	}
	if !deploySkill.HasYAMLFrontmatter {
		t.Error("deploy skill should have YAML frontmatter")
	}
	if deploySkill.Frontmatter == nil {
		t.Fatal("deploy skill frontmatter is nil")
	}
	if deploySkill.Frontmatter.Name != "deploy-stage" {
		t.Errorf("name = %q, want %q", deploySkill.Frontmatter.Name, "deploy-stage")
	}
	if deploySkill.Name != "deploy-stage" {
		t.Errorf("skill name = %q, want %q (should use frontmatter name)", deploySkill.Name, "deploy-stage")
	}
}

func TestScanNoFrontmatterCounted(t *testing.T) {
	root := setupTestTree(t)

	sc := &Scanner{
		Paths:     []string{root},
		Recursive: true,
	}

	inv, err := sc.Scan()
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}

	if inv.NoFrontmatter == 0 {
		t.Error("expected at least one skill without frontmatter (review.md, CLAUDE.md)")
	}
}

func TestScanSkipsBlacklistedDirs(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, ".git"), 0o755)

	// Put a skill file inside node_modules — should be skipped.
	nmDir := filepath.Join(root, "node_modules", ".claude", "skills", "bad")
	os.MkdirAll(nmDir, 0o755)
	os.WriteFile(filepath.Join(nmDir, "bad.md"), []byte("# bad"), 0o644)

	// Also put a valid one at the root level.
	skillDir := filepath.Join(root, ".claude", "skills", "good")
	os.MkdirAll(skillDir, 0o755)
	os.WriteFile(filepath.Join(skillDir, "good.md"), []byte("# good"), 0o644)

	sc := &Scanner{
		Paths:     []string{root},
		Recursive: true,
	}
	inv, err := sc.Scan()
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}

	for _, sk := range inv.Skills {
		if sk.Name == "bad" {
			t.Error("found skill inside node_modules — should have been skipped")
		}
	}

	foundGood := false
	for _, sk := range inv.Skills {
		if sk.Name == "good" {
			foundGood = true
		}
	}
	if !foundGood {
		t.Error("good skill not found")
	}
}

func TestScanMCPServers(t *testing.T) {
	root := setupTestTree(t)

	sc := &Scanner{
		Paths:     []string{root},
		Recursive: true,
	}

	inv, err := sc.Scan()
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}

	mcpCount := 0
	for _, sk := range inv.Skills {
		if sk.Type == model.SkillTypeMCPServer {
			mcpCount++
		}
	}
	if mcpCount != 2 {
		t.Errorf("MCP server count = %d, want 2", mcpCount)
	}
}

func TestScanEmptyDir(t *testing.T) {
	root := t.TempDir()

	sc := &Scanner{
		Paths:     []string{root},
		Recursive: true,
	}

	inv, err := sc.Scan()
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if inv.TotalCount != 0 {
		t.Errorf("total count = %d, want 0 for empty dir", inv.TotalCount)
	}
}

func TestScanProjectDetection(t *testing.T) {
	root := setupTestTree(t)

	sc := &Scanner{
		Paths:     []string{root},
		Recursive: true,
	}

	inv, err := sc.Scan()
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}

	projectName := filepath.Base(root)
	for _, sk := range inv.Skills {
		if sk.SourceProject != projectName {
			t.Errorf("skill %q project = %q, want %q", sk.Name, sk.SourceProject, projectName)
		}
	}
}
