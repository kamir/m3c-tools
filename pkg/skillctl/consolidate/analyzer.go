// Package consolidate analyzes a skill inventory for duplicates, orphans,
// drift, and missing frontmatter — then optionally fixes annotation gaps.
package consolidate

import (
	"os"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/delta"
	"github.com/kamir/m3c-tools/pkg/skillctl/model"
)

// DuplicateGroup represents a set of skills sharing the same lowercased name.
type DuplicateGroup struct {
	Name      string
	Instances []model.SkillDescriptor
	Canonical *model.SkillDescriptor // recommended canonical (highest priority)
	AllMatch  bool                   // true if all content hashes are identical
}

// OrphanSkill is a skill that lives outside any known git repository.
type OrphanSkill struct {
	Skill  model.SkillDescriptor
	Reason string // "no git repo" or "user-global only"
}

// DriftPair describes a skill whose user-global copy diverged from the
// project copy.
type DriftPair struct {
	SkillName string
	Source    model.SkillDescriptor // project copy (canonical)
	Copy     model.SkillDescriptor // user-global copy
	Diff     string                // unified diff
}

// AnnotationGap flags a skill that lacks YAML frontmatter and suggests
// category/tags based on its file path.
type AnnotationGap struct {
	Skill         model.SkillDescriptor
	SuggestedName string
	SuggestedCat  string
	SuggestedTags []string
}

// Summary holds aggregate counts for the consolidation report.
type Summary struct {
	DuplicateGroups    int
	TotalDuplicates    int
	OrphanCount        int
	DriftCount         int
	MissingFrontmatter int
}

// ConsolidationReport is the complete output of the consolidation analysis.
type ConsolidationReport struct {
	AnalyzedAt      string
	TotalSkills     int
	DuplicateGroups []DuplicateGroup
	Orphans         []OrphanSkill
	DriftPairs      []DriftPair
	AnnotationGaps  []AnnotationGap
	Summary         Summary
}

// Analyze inspects an inventory for duplicates, orphans, drift, and
// annotation gaps, returning a full consolidation report.
func Analyze(inv *model.Inventory) *ConsolidationReport {
	r := &ConsolidationReport{
		AnalyzedAt:  time.Now().UTC().Format(time.RFC3339),
		TotalSkills: inv.TotalCount,
	}

	r.DuplicateGroups = findDuplicates(inv)
	r.Orphans = findOrphans(inv)
	r.DriftPairs = findDrift(r.DuplicateGroups)
	r.AnnotationGaps = findAnnotationGaps(inv)

	// Compute summary.
	totalDups := 0
	for _, g := range r.DuplicateGroups {
		totalDups += len(g.Instances)
	}
	r.Summary = Summary{
		DuplicateGroups:    len(r.DuplicateGroups),
		TotalDuplicates:    totalDups,
		OrphanCount:        len(r.Orphans),
		DriftCount:         len(r.DriftPairs),
		MissingFrontmatter: len(r.AnnotationGaps),
	}

	return r
}

// findDuplicates groups skills by lowercased name and returns groups with 2+
// entries. Within each group, the canonical skill is chosen by priority:
// has frontmatter > in git repo > in project .claude/ > in user-global ~/.claude/.
func findDuplicates(inv *model.Inventory) []DuplicateGroup {
	groups := make(map[string][]model.SkillDescriptor)
	for _, s := range inv.Skills {
		key := strings.ToLower(s.Name)
		groups[key] = append(groups[key], s)
	}

	var result []DuplicateGroup
	for name, instances := range groups {
		if len(instances) < 2 {
			continue
		}

		g := DuplicateGroup{
			Name:      name,
			Instances: instances,
		}

		// Pick canonical by priority.
		g.Canonical = pickCanonical(instances)

		// Check if all content hashes match.
		g.AllMatch = true
		if len(instances) > 0 {
			first := instances[0].ContentHash
			for _, inst := range instances[1:] {
				if inst.ContentHash != first {
					g.AllMatch = false
					break
				}
			}
		}

		result = append(result, g)
	}
	return result
}

// pickCanonical selects the best representative from a group of duplicates.
// Priority: has frontmatter > known project (not "unknown") > project .claude/ > user-global.
func pickCanonical(instances []model.SkillDescriptor) *model.SkillDescriptor {
	best := &instances[0]
	bestScore := canonicalScore(&instances[0])

	for i := 1; i < len(instances); i++ {
		s := canonicalScore(&instances[i])
		if s > bestScore {
			best = &instances[i]
			bestScore = s
		}
	}
	return best
}

// canonicalScore assigns a numeric priority to a skill descriptor for
// canonical selection. Higher is better.
func canonicalScore(s *model.SkillDescriptor) int {
	score := 0
	if s.HasYAMLFrontmatter {
		score += 100
	}
	if s.SourceProject != "unknown" && s.SourceProject != "user-global" {
		score += 50
	}
	if s.SourceProject != "unknown" {
		score += 20
	}
	// Prefer project .claude/ over user-global.
	if strings.Contains(s.SourcePath, "/.claude/") && s.SourceProject != "user-global" {
		score += 10
	}
	return score
}

// findOrphans returns skills whose SourceProject is "unknown", meaning they
// are not inside any recognized git repository.
func findOrphans(inv *model.Inventory) []OrphanSkill {
	var result []OrphanSkill
	for _, s := range inv.Skills {
		if s.SourceProject == "unknown" {
			reason := "no git repo"
			result = append(result, OrphanSkill{
				Skill:  s,
				Reason: reason,
			})
		}
	}
	return result
}

// findDrift looks through duplicate groups for pairs where one copy is in a
// real project and another is in user-global, with differing content hashes.
// It reads both files from disk and produces a unified diff.
func findDrift(groups []DuplicateGroup) []DriftPair {
	var result []DriftPair
	for _, g := range groups {
		// Collect user-global and project copies.
		var globals []model.SkillDescriptor
		var projects []model.SkillDescriptor
		for _, inst := range g.Instances {
			if inst.SourceProject == "user-global" {
				globals = append(globals, inst)
			} else if inst.SourceProject != "unknown" {
				projects = append(projects, inst)
			}
		}

		// For each global+project pair with differing hashes, generate a diff.
		for _, gl := range globals {
			for _, pr := range projects {
				if gl.ContentHash == pr.ContentHash {
					continue
				}

				diff := computeFileDiff(pr.SourcePath, gl.SourcePath)
				result = append(result, DriftPair{
					SkillName: g.Name,
					Source:    pr,
					Copy:     gl,
					Diff:     diff,
				})
			}
		}
	}
	return result
}

// computeFileDiff reads two files from disk and returns a unified diff.
func computeFileDiff(sourcePath, copyPath string) string {
	sourceData, err := os.ReadFile(sourcePath)
	if err != nil {
		return "(could not read source: " + err.Error() + ")"
	}
	copyData, err := os.ReadFile(copyPath)
	if err != nil {
		return "(could not read copy: " + err.Error() + ")"
	}
	return delta.GenerateUnifiedDiff(
		string(sourceData), string(copyData),
		sourcePath, copyPath,
	)
}

// findAnnotationGaps returns skills that lack YAML frontmatter and are not
// skill index files, along with suggested annotations.
func findAnnotationGaps(inv *model.Inventory) []AnnotationGap {
	var result []AnnotationGap
	for _, s := range inv.Skills {
		if s.HasYAMLFrontmatter || s.Type == model.SkillTypeSkillIndex {
			continue
		}

		cat, tags := suggestCategoryAndTags(s.SourcePath, s.Name)
		result = append(result, AnnotationGap{
			Skill:         s,
			SuggestedName: s.Name,
			SuggestedCat:  cat,
			SuggestedTags: tags,
		})
	}
	return result
}

// suggestCategoryAndTags infers a category and tag set from the skill's file
// path and name using a keyword mapping.
func suggestCategoryAndTags(path, name string) (string, []string) {
	lp := strings.ToLower(path)
	ln := strings.ToLower(name)
	combined := lp + " " + ln

	type rule struct {
		keyword  string
		category string
		tag      string
	}

	rules := []rule{
		{"deploy", "ops", "deploy"},
		{"build", "ops", "build"},
		{"release", "ops", "release"},
		{"test", "quality", "test"},
		{"review", "quality", "review"},
		{"lint", "quality", "lint"},
		{"check", "quality", "check"},
		{"security", "security", "security"},
		{"scan", "security", "scan"},
		{"cohort", "education", "cohort"},
		{"session", "education", "session"},
		{"survey", "education", "survey"},
	}

	category := "uncategorized"
	var tags []string
	seen := make(map[string]bool)

	for _, r := range rules {
		if strings.Contains(combined, r.keyword) {
			if category == "uncategorized" {
				category = r.category
			}
			if !seen[r.tag] {
				tags = append(tags, r.tag)
				seen[r.tag] = true
			}
		}
	}

	// Always include the skill name as a tag if not already present.
	if !seen[ln] {
		tags = append(tags, ln)
	}

	return category, tags
}
