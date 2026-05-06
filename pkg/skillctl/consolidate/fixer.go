package consolidate

import (
	"fmt"
	"os"
	"strings"
)

// FixAnnotationGaps iterates over annotation gaps, generates frontmatter for
// each, and prepends it to the file on disk. Returns the count of fixed and
// skipped files.
func FixAnnotationGaps(gaps []AnnotationGap) (fixed int, skipped int, err error) {
	for _, gap := range gaps {
		fm := generateFrontmatter(gap)
		if err := prependFrontmatter(gap.Skill.SourcePath, fm); err != nil {
			// Log the error but continue with the rest.
			fmt.Fprintf(os.Stderr, "skipping %s: %v\n", gap.Skill.SourcePath, err)
			skipped++
			continue
		}
		fixed++
	}
	return fixed, skipped, nil
}

// generateFrontmatter builds a YAML frontmatter block from the annotation
// gap's suggested values and the first meaningful line of the file content.
func generateFrontmatter(gap AnnotationGap) string {
	description := extractDescription(gap.Skill.SourcePath)

	var b strings.Builder
	b.WriteString("---\n")
	b.WriteString(fmt.Sprintf("name: %s\n", gap.SuggestedName))
	b.WriteString("description: |\n")
	b.WriteString(fmt.Sprintf("  %s\n", description))
	b.WriteString("metadata:\n")
	b.WriteString("  version: 1.0.0\n")
	b.WriteString(fmt.Sprintf("  category: %s\n", gap.SuggestedCat))

	// Format tags as a YAML flow sequence.
	tagParts := make([]string, len(gap.SuggestedTags))
	copy(tagParts, gap.SuggestedTags)
	b.WriteString(fmt.Sprintf("  tags: [%s]\n", strings.Join(tagParts, ", ")))
	b.WriteString("---\n")

	return b.String()
}

// extractDescription reads the file at path and returns its first
// non-empty, non-heading line as a short description.
func extractDescription(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "No description available."
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		// Skip markdown headings and YAML frontmatter delimiters.
		if strings.HasPrefix(trimmed, "#") || trimmed == "---" {
			continue
		}
		// Clean up: remove leading markdown list markers.
		trimmed = strings.TrimPrefix(trimmed, "- ")
		trimmed = strings.TrimPrefix(trimmed, "* ")
		// Limit length.
		if len(trimmed) > 120 {
			trimmed = trimmed[:120] + "..."
		}
		return trimmed
	}

	return "No description available."
}

// prependFrontmatter reads the file at path, prepends the frontmatter string,
// and writes the result back to the same file.
func prependFrontmatter(path string, fm string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}

	content := string(data)

	// Safety check: do not prepend if the file already starts with frontmatter.
	if strings.HasPrefix(strings.TrimSpace(content), "---") {
		return fmt.Errorf("file already has frontmatter delimiter")
	}

	newContent := fm + "\n" + content

	// Write back with the same permissions.
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}

	if err := os.WriteFile(path, []byte(newContent), info.Mode()); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}

	return nil
}
