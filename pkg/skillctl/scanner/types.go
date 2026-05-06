// Tier + Source types and ResolveDefaults — SPEC-0189 Phase 1.
//
// Claude Code resolves skills from three precedence tiers (project > user >
// plugin). This file defines the canonical Tier and Source values and the
// path-resolution helper that maps a Source set to scan roots.
package scanner

import (
	"os"
	"path/filepath"
)

// Tier is the precedence layer a skill comes from. Project wins over user,
// user wins over plugin. See SPEC-0189 §3.
type Tier string

const (
	TierProject Tier = "project"
	TierUser    Tier = "user"
	TierPlugin  Tier = "plugin"
)

// Source is a logical scan-root selector. The CLI exposes this as
// `--source <claude|user|projects|plugins|all>` per SPEC-0189 §4.
type Source string

const (
	// SourceClaude is the default — user tier + plugin tier (matches
	// what Claude Code itself resolves at runtime per SPEC-0189 §10 D3).
	SourceClaude   Source = "claude"
	SourceUser     Source = "user"
	SourceProjects Source = "projects" // legacy SPEC-0115 mode
	SourcePlugins  Source = "plugins"
	SourceAll      Source = "all"
)

// ScanRoot pairs a filesystem path with the Tier of skills found beneath it.
type ScanRoot struct {
	Path string
	Tier Tier
}

// ResolveDefaults returns the Claude Code conventional roots for the
// requested source set. Honours $HOME and $CLAUDE_CONFIG_DIR overrides.
//
// User tier:    $CLAUDE_CONFIG_DIR/skills/  or  ~/.claude/skills/
// Plugin tier:  $CLAUDE_CONFIG_DIR/plugins/cache/<o>/<p>/<v>/skills/
//               $CLAUDE_CONFIG_DIR/plugins/marketplaces/<m>/skills/
//               $CLAUDE_CONFIG_DIR/plugins/marketplaces/<m>/plugins/<p>/skills/
// Project tier: caller supplies via explicit path arg (not auto-resolved).
//
// SourceClaude expands to user + plugin (SPEC-0189 §10 D3).
// SourceAll expands to user + plugin only (project tier requires explicit
// paths from the caller; auto-discovery is intentionally out of scope —
// see SPEC-0189 §12).
func ResolveDefaults(sources []Source) []ScanRoot {
	configDir := claudeConfigDir()
	if configDir == "" {
		return nil
	}

	wantUser := false
	wantPlugins := false
	for _, src := range sources {
		switch src {
		case SourceClaude:
			wantUser = true
			wantPlugins = true
		case SourceUser:
			wantUser = true
		case SourcePlugins:
			wantPlugins = true
		case SourceAll:
			wantUser = true
			wantPlugins = true
		}
	}

	var roots []ScanRoot
	if wantUser {
		userSkills := filepath.Join(configDir, "skills")
		if pathExists(userSkills) {
			roots = append(roots, ScanRoot{Path: userSkills, Tier: TierUser})
		}
	}
	if wantPlugins {
		pluginRoots := pluginScanRoots(configDir)
		roots = append(roots, pluginRoots...)
	}
	return roots
}

// claudeConfigDir returns the resolved Claude Code config dir. Honours
// $CLAUDE_CONFIG_DIR if set, else falls back to $HOME/.claude.
func claudeConfigDir() string {
	if dir := os.Getenv("CLAUDE_CONFIG_DIR"); dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".claude")
}

func pathExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
