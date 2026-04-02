package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/model"
)

func sampleInventory() *model.Inventory {
	dupOf := "test-project/deploy-stage"
	return &model.Inventory{
		ScannedAt: "2026-04-02T10:00:00Z",
		ScanPaths: []string{"/tmp/test-project"},
		Skills: []model.SkillDescriptor{
			{
				ID:                 "test-project/deploy-stage",
				Name:               "deploy-stage",
				Type:               model.SkillTypeClaudeCodeSkill,
				SourcePath:         "/tmp/test-project/.claude/skills/deploy/deploy.md",
				SourceProject:      "test-project",
				DiscoveredAt:       "2026-04-02T10:00:00Z",
				ContentHash:        "abc123",
				ContentSizeBytes:   1024,
				HasYAMLFrontmatter: true,
				Frontmatter: &model.Frontmatter{
					Name:     "deploy-stage",
					Version:  "1.0.0",
					Category: "deployment",
				},
				Dependencies:  []string{},
				ConflictsWith: []string{},
			},
			{
				ID:                 "test-project/review",
				Name:               "review",
				Type:               model.SkillTypeCommand,
				SourcePath:         "/tmp/test-project/.claude/commands/review.md",
				SourceProject:      "test-project",
				DiscoveredAt:       "2026-04-02T10:00:00Z",
				ContentHash:        "def456",
				ContentSizeBytes:   512,
				HasYAMLFrontmatter: false,
				Dependencies:       []string{},
				ConflictsWith:      []string{},
			},
			{
				ID:                 "test-project/mcp-filesystem",
				Name:               "filesystem",
				Type:               model.SkillTypeMCPServer,
				SourcePath:         "/tmp/test-project/.claude/settings.json",
				SourceProject:      "test-project",
				DiscoveredAt:       "2026-04-02T10:00:00Z",
				ContentHash:        "ghi789",
				ContentSizeBytes:   256,
				HasYAMLFrontmatter: false,
				Dependencies:       []string{},
				ConflictsWith:      []string{},
			},
			{
				ID:                 "other-project/deploy-copy",
				Name:               "deploy-copy",
				Type:               model.SkillTypeClaudeCodeSkill,
				SourcePath:         "/tmp/other-project/.claude/skills/deploy/deploy.md",
				SourceProject:      "other-project",
				DiscoveredAt:       "2026-04-02T10:00:00Z",
				ContentHash:        "abc123", // same hash = duplicate
				ContentSizeBytes:   1024,
				HasYAMLFrontmatter: true,
				DuplicateOf:        &dupOf,
				Frontmatter: &model.Frontmatter{
					Name:     "deploy-copy",
					Version:  "1.0.0",
					Category: "deployment",
				},
				Dependencies:  []string{},
				ConflictsWith: []string{},
			},
		},
		TotalCount:    4,
		ByType:        map[string]int{"claude_code_skill": 2, "command": 1, "mcp_server": 1},
		ByProject:     map[string]int{"test-project": 3, "other-project": 1},
		Duplicates:    1,
		NoFrontmatter: 2,
	}
}

func TestGenerateHTML(t *testing.T) {
	inv := sampleInventory()
	var buf bytes.Buffer

	err := GenerateHTML(&buf, inv)
	if err != nil {
		t.Fatalf("GenerateHTML error: %v", err)
	}

	html := buf.String()

	// Check basic structure.
	if !strings.Contains(html, "<title>Skill Inventory Report</title>") {
		t.Error("missing title")
	}
	if !strings.Contains(html, "deploy-stage") {
		t.Error("missing deploy-stage skill name")
	}
	if !strings.Contains(html, "2026-04-02T10:00:00Z") {
		t.Error("missing scanned at timestamp")
	}
	if !strings.Contains(html, "test-project") {
		t.Error("missing project name")
	}

	// Check duplicates section appears.
	if !strings.Contains(html, "Duplicates") {
		t.Error("missing duplicates section")
	}
	if !strings.Contains(html, "deploy-copy") {
		t.Error("missing duplicate skill name")
	}

	// Check no frontmatter section appears.
	if !strings.Contains(html, "Without Frontmatter") {
		t.Error("missing no-frontmatter section")
	}

	// Check CSS is embedded.
	if !strings.Contains(html, "<style>") {
		t.Error("missing embedded CSS")
	}
}

func TestGenerateMarkdown(t *testing.T) {
	inv := sampleInventory()
	var buf bytes.Buffer

	err := GenerateMarkdown(&buf, inv)
	if err != nil {
		t.Fatalf("GenerateMarkdown error: %v", err)
	}

	md := buf.String()

	if !strings.Contains(md, "# Skill Inventory Report") {
		t.Error("missing report title")
	}
	if !strings.Contains(md, "deploy-stage") {
		t.Error("missing deploy-stage")
	}
	if !strings.Contains(md, "| Total Skills | 4 |") {
		t.Error("missing total skills count")
	}
	if !strings.Contains(md, "## Duplicates") {
		t.Error("missing duplicates section")
	}
	if !strings.Contains(md, "## Skills Without Frontmatter") {
		t.Error("missing no-frontmatter section")
	}
}

func TestGenerateHTMLEmpty(t *testing.T) {
	inv := &model.Inventory{
		ScannedAt:     "2026-04-02T10:00:00Z",
		ScanPaths:     []string{"/tmp/empty"},
		Skills:        []model.SkillDescriptor{},
		TotalCount:    0,
		ByType:        map[string]int{},
		ByProject:     map[string]int{},
		Duplicates:    0,
		NoFrontmatter: 0,
	}

	var buf bytes.Buffer
	err := GenerateHTML(&buf, inv)
	if err != nil {
		t.Fatalf("GenerateHTML error on empty inventory: %v", err)
	}
	if !strings.Contains(buf.String(), "Total Skills") {
		t.Error("missing stats in empty report")
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		input int64
		want  string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KB"},
		{2560, "2.5 KB"},
		{1048576, "1.0 MB"},
		{1572864, "1.5 MB"},
	}
	for _, tc := range tests {
		got := formatBytes(tc.input)
		if got != tc.want {
			t.Errorf("formatBytes(%d) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
