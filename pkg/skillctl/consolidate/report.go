package consolidate

import (
	"fmt"
	"strings"
)

// FormatTerminal renders a ConsolidationReport as readable terminal text.
func FormatTerminal(r *ConsolidationReport) string {
	var b strings.Builder

	// Header.
	b.WriteString(fmt.Sprintf("Skill Consolidation Report  %s\n\n", r.AnalyzedAt))

	// Summary block.
	b.WriteString("Summary:\n")
	b.WriteString(fmt.Sprintf("  Duplicate groups:    %3d  (%d total copies)\n",
		r.Summary.DuplicateGroups, r.Summary.TotalDuplicates))
	b.WriteString(fmt.Sprintf("  Orphan skills:       %3d  (not in any git repo)\n",
		r.Summary.OrphanCount))
	b.WriteString(fmt.Sprintf("  Drifted copies:      %3d  (user-global differs from source)\n",
		r.Summary.DriftCount))
	b.WriteString(fmt.Sprintf("  Missing frontmatter: %3d  (need annotation)\n",
		r.Summary.MissingFrontmatter))

	// Duplicates section.
	b.WriteString(fmt.Sprintf("\n--- Duplicates (%d groups) ---\n", r.Summary.DuplicateGroups))
	for _, g := range r.DuplicateGroups {
		b.WriteString(fmt.Sprintf("  %s (%d copies)\n", g.Name, len(g.Instances)))
		for _, inst := range g.Instances {
			marker := " "
			suffix := ""

			isCanonical := g.Canonical != nil && inst.ID == g.Canonical.ID
			if isCanonical {
				marker = "*"
				suffix = "  [canonical"
				if inst.HasYAMLFrontmatter {
					suffix += ", has FM"
				}
				suffix += "]"
			} else {
				// Show whether this copy matches the canonical.
				if g.Canonical != nil && inst.ContentHash == g.Canonical.ContentHash {
					suffix = "  (identical)"
				} else {
					suffix = "  (content differs)"
				}
			}

			b.WriteString(fmt.Sprintf("    %s %s%s\n", marker, inst.SourcePath, suffix))
		}
	}

	// Orphans section.
	b.WriteString(fmt.Sprintf("\n--- Orphans (%d skills) ---\n", r.Summary.OrphanCount))
	for _, o := range r.Orphans {
		b.WriteString(fmt.Sprintf("  %s  (%s)  %s\n", o.Skill.Name, o.Skill.Type, o.Skill.SourcePath))
	}

	// Drift section.
	b.WriteString(fmt.Sprintf("\n--- Drift (%d pairs) ---\n", r.Summary.DriftCount))
	for _, d := range r.DriftPairs {
		b.WriteString(fmt.Sprintf("  %s: user-global vs %s (content differs)\n",
			d.SkillName, d.Source.SourceProject))
	}

	// Annotation gaps section.
	b.WriteString(fmt.Sprintf("\n--- Annotation Gaps (%d skills) ---\n", r.Summary.MissingFrontmatter))
	for _, ag := range r.AnnotationGaps {
		tagStr := strings.Join(ag.SuggestedTags, ", ")
		b.WriteString(fmt.Sprintf("  %s (%s)  %s\n", ag.Skill.Name, ag.Skill.Type, ag.Skill.SourceProject))
		b.WriteString(fmt.Sprintf("    suggested: category=%s, tags=[%s]\n", ag.SuggestedCat, tagStr))
	}

	return b.String()
}

// FormatMarkdown renders a ConsolidationReport as Markdown suitable for
// writing to a file.
func FormatMarkdown(r *ConsolidationReport) string {
	var b strings.Builder

	b.WriteString("# Skill Consolidation Report\n\n")
	b.WriteString(fmt.Sprintf("Analyzed at: %s\n\n", r.AnalyzedAt))
	b.WriteString(fmt.Sprintf("Total skills: %d\n\n", r.TotalSkills))

	// Summary table.
	b.WriteString("## Summary\n\n")
	b.WriteString("| Metric | Count |\n|--------|-------|\n")
	b.WriteString(fmt.Sprintf("| Duplicate groups | %d |\n", r.Summary.DuplicateGroups))
	b.WriteString(fmt.Sprintf("| Total duplicates | %d |\n", r.Summary.TotalDuplicates))
	b.WriteString(fmt.Sprintf("| Orphan skills | %d |\n", r.Summary.OrphanCount))
	b.WriteString(fmt.Sprintf("| Drifted copies | %d |\n", r.Summary.DriftCount))
	b.WriteString(fmt.Sprintf("| Missing frontmatter | %d |\n", r.Summary.MissingFrontmatter))

	// Duplicates.
	b.WriteString(fmt.Sprintf("\n## Duplicates (%d groups)\n\n", r.Summary.DuplicateGroups))
	for _, g := range r.DuplicateGroups {
		allMatch := ""
		if g.AllMatch {
			allMatch = " (all identical)"
		}
		b.WriteString(fmt.Sprintf("### %s (%d copies)%s\n\n", g.Name, len(g.Instances), allMatch))
		b.WriteString("| Path | Project | Hash | Canonical |\n|------|---------|------|-----------|\n")
		for _, inst := range g.Instances {
			canonical := ""
			if g.Canonical != nil && inst.ID == g.Canonical.ID {
				canonical = "yes"
			}
			hash := inst.ContentHash
			if len(hash) > 12 {
				hash = hash[:12]
			}
			b.WriteString(fmt.Sprintf("| `%s` | %s | %s | %s |\n",
				inst.SourcePath, inst.SourceProject, hash, canonical))
		}
		b.WriteString("\n")
	}

	// Orphans.
	b.WriteString(fmt.Sprintf("## Orphans (%d skills)\n\n", r.Summary.OrphanCount))
	if len(r.Orphans) > 0 {
		b.WriteString("| Skill | Type | Path | Reason |\n|-------|------|------|--------|\n")
		for _, o := range r.Orphans {
			b.WriteString(fmt.Sprintf("| %s | %s | `%s` | %s |\n",
				o.Skill.Name, o.Skill.Type, o.Skill.SourcePath, o.Reason))
		}
		b.WriteString("\n")
	}

	// Drift.
	b.WriteString(fmt.Sprintf("## Drift (%d pairs)\n\n", r.Summary.DriftCount))
	for _, d := range r.DriftPairs {
		b.WriteString(fmt.Sprintf("### %s\n\n", d.SkillName))
		b.WriteString(fmt.Sprintf("- **Source**: `%s` (%s)\n", d.Source.SourcePath, d.Source.SourceProject))
		b.WriteString(fmt.Sprintf("- **Copy**: `%s` (user-global)\n\n", d.Copy.SourcePath))
		if d.Diff != "" {
			b.WriteString("```diff\n")
			b.WriteString(d.Diff)
			if !strings.HasSuffix(d.Diff, "\n") {
				b.WriteString("\n")
			}
			b.WriteString("```\n\n")
		}
	}

	// Annotation gaps.
	b.WriteString(fmt.Sprintf("## Annotation Gaps (%d skills)\n\n", r.Summary.MissingFrontmatter))
	if len(r.AnnotationGaps) > 0 {
		b.WriteString("| Skill | Type | Project | Suggested Category | Suggested Tags |\n")
		b.WriteString("|-------|------|---------|-------------------|----------------|\n")
		for _, ag := range r.AnnotationGaps {
			tagStr := strings.Join(ag.SuggestedTags, ", ")
			b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n",
				ag.Skill.Name, ag.Skill.Type, ag.Skill.SourceProject,
				ag.SuggestedCat, tagStr))
		}
	}

	return b.String()
}
