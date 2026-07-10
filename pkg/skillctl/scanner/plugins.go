// Plugin-cache + marketplace walker — SPEC-0189 Phase 2.
//
// Walks ~/.claude/plugins/cache/<owner>/<plugin>/<version>/skills/ AND
// ~/.claude/plugins/marketplaces/<m>/{skills,plugins/<p>/skills}/ to find
// plugin-shipped skills.
package scanner

import (
	"os"
	"path/filepath"
)

// pluginScanRoots returns ScanRoots for every plugin-skill directory under
// the given Claude Code config dir.
func pluginScanRoots(configDir string) []ScanRoot {
	pluginsDir := filepath.Join(configDir, "plugins")
	if !pathExists(pluginsDir) {
		return nil
	}

	var roots []ScanRoot
	roots = append(roots, pluginCacheRoots(pluginsDir)...)
	roots = append(roots, marketplaceRoots(pluginsDir)...)
	return roots
}

// pluginCacheRoots walks ~/.claude/plugins/cache/<owner>/<plugin>/<version>/skills/.
func pluginCacheRoots(pluginsDir string) []ScanRoot {
	cacheDir := filepath.Join(pluginsDir, "cache")
	if !pathExists(cacheDir) {
		return nil
	}

	var roots []ScanRoot
	owners, err := os.ReadDir(cacheDir)
	if err != nil {
		return nil
	}
	for _, owner := range owners {
		if !owner.IsDir() {
			continue
		}
		ownerDir := filepath.Join(cacheDir, owner.Name())
		plugins, err := os.ReadDir(ownerDir)
		if err != nil {
			continue
		}
		for _, plugin := range plugins {
			if !plugin.IsDir() {
				continue
			}
			pluginDir := filepath.Join(ownerDir, plugin.Name())
			versions, err := os.ReadDir(pluginDir)
			if err != nil {
				continue
			}
			for _, version := range versions {
				if !version.IsDir() {
					continue
				}
				skillsDir := filepath.Join(pluginDir, version.Name(), "skills")
				if pathExists(skillsDir) {
					roots = append(roots, ScanRoot{Path: skillsDir, Tier: TierPlugin})
				}
			}
		}
	}
	return roots
}

// marketplaceRoots walks ~/.claude/plugins/marketplaces/<m>/skills/ AND
// ~/.claude/plugins/marketplaces/<m>/plugins/<p>/skills/.
func marketplaceRoots(pluginsDir string) []ScanRoot {
	marketsDir := filepath.Join(pluginsDir, "marketplaces")
	if !pathExists(marketsDir) {
		return nil
	}

	var roots []ScanRoot
	markets, err := os.ReadDir(marketsDir)
	if err != nil {
		return nil
	}
	for _, market := range markets {
		if !market.IsDir() {
			continue
		}
		marketDir := filepath.Join(marketsDir, market.Name())

		// Direct: .../marketplaces/<m>/skills/
		direct := filepath.Join(marketDir, "skills")
		if pathExists(direct) {
			roots = append(roots, ScanRoot{Path: direct, Tier: TierPlugin})
		}

		// Nested: .../marketplaces/<m>/plugins/<p>/skills/
		nestedPlugins := filepath.Join(marketDir, "plugins")
		if pluginsDirs, err := os.ReadDir(nestedPlugins); err == nil {
			for _, p := range pluginsDirs {
				if !p.IsDir() {
					continue
				}
				skills := filepath.Join(nestedPlugins, p.Name(), "skills")
				if pathExists(skills) {
					roots = append(roots, ScanRoot{Path: skills, Tier: TierPlugin})
				}
			}
		}
	}
	return roots
}
