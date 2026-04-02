// Package model defines the data types for the skillctl skill inventory system.
package model

// SkillType classifies the kind of skill source discovered.
type SkillType string

const (
	SkillTypeClaudeCodeSkill  SkillType = "claude_code_skill"
	SkillTypeClaudeMD         SkillType = "claude_md"
	SkillTypeCommand          SkillType = "command"
	SkillTypeMCPServer        SkillType = "mcp_server"
	SkillTypeAgent            SkillType = "agent"
	SkillTypeSynthesisTemplate SkillType = "synthesis_template"
)

// Frontmatter holds parsed YAML frontmatter from skill markdown files.
type Frontmatter struct {
	Name         string                 `json:"name" yaml:"name"`
	Version      string                 `json:"version,omitempty" yaml:"version"`
	Description  string                 `json:"description,omitempty" yaml:"description"`
	AllowedTools []string               `json:"allowed_tools,omitempty" yaml:"allowed-tools"`
	Category     string                 `json:"category,omitempty" yaml:"category"`
	Intent       string                 `json:"intent,omitempty" yaml:"intent"`
	InputType    string                 `json:"input_type,omitempty" yaml:"input_type"`
	OutputFormat string                 `json:"output_format,omitempty" yaml:"output_format"`
	Tags         []string               `json:"tags,omitempty" yaml:"tags"`
	Model        string                 `json:"model,omitempty" yaml:"model"`
	Metadata     map[string]interface{} `json:"metadata,omitempty" yaml:"metadata"`
}

// SkillDescriptor represents a single discovered skill source.
type SkillDescriptor struct {
	ID                 string       `json:"id"`
	Name               string       `json:"name"`
	Type               SkillType    `json:"type"`
	SourcePath         string       `json:"source_path"`
	SourceProject      string       `json:"source_project"`
	DiscoveredAt       string       `json:"discovered_at"`
	Frontmatter        *Frontmatter `json:"frontmatter,omitempty"`
	ContentHash        string       `json:"content_hash"`
	ContentSizeBytes   int64        `json:"content_size_bytes"`
	HasYAMLFrontmatter bool         `json:"has_yaml_frontmatter"`
	Dependencies       []string     `json:"dependencies"`
	ConflictsWith      []string     `json:"conflicts_with"`
	DuplicateOf        *string      `json:"duplicate_of"`
}

// Inventory holds the complete results of a skill scan.
type Inventory struct {
	ScannedAt      string            `json:"scanned_at"`
	ScanPaths      []string          `json:"scan_paths"`
	Skills         []SkillDescriptor `json:"skills"`
	TotalCount     int               `json:"total_count"`
	ByType         map[string]int    `json:"by_type"`
	ByProject      map[string]int    `json:"by_project"`
	Duplicates     int               `json:"duplicates"`
	NoFrontmatter  int               `json:"no_frontmatter"`
	ClaudeMDCount  int               `json:"claude_md_count"`
}
