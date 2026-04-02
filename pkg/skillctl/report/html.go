// Package report generates HTML and Markdown reports from skill inventories.
package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/delta"
	"github.com/kamir/m3c-tools/pkg/skillctl/model"
)

//go:embed report.html.tmpl
var htmlTemplate string

//go:embed delta.html.tmpl
var deltaHTMLTemplate string

// funcMap provides template helper functions.
var funcMap = template.FuncMap{
	"badgeClass": badgeClass,
	"barWidth":   barWidth,
	"formatBytes": formatBytes,
	"deref":      deref,
	"string":     toString,
}

// badgeClass returns a CSS class name for a skill type string.
func badgeClass(t string) string {
	switch {
	case strings.Contains(t, "skill"):
		return "badge-skill"
	case strings.Contains(t, "command"):
		return "badge-cmd"
	case strings.Contains(t, "mcp"):
		return "badge-mcp"
	case strings.Contains(t, "agent"):
		return "badge-agent"
	case strings.Contains(t, "claude"):
		return "badge-claude"
	case strings.Contains(t, "synthesis"):
		return "badge-synth"
	default:
		return ""
	}
}

// barWidth computes the pixel width of a proportional bar (max 200px).
func barWidth(count, total int) int {
	if total == 0 {
		return 4
	}
	w := (count * 200) / total
	if w < 4 {
		w = 4
	}
	return w
}

// formatBytes returns a human-readable byte size string.
func formatBytes(b int64) string {
	switch {
	case b >= 1024*1024:
		return fmt.Sprintf("%.1f MB", float64(b)/(1024*1024))
	case b >= 1024:
		return fmt.Sprintf("%.1f KB", float64(b)/1024)
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// deref safely dereferences a string pointer.
func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// toString converts a SkillType to string for template use.
func toString(s model.SkillType) string {
	return string(s)
}

// GenerateHTML writes a self-contained HTML report to the writer.
func GenerateHTML(w io.Writer, inv *model.Inventory) error {
	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("parsing template: %w", err)
	}
	return tmpl.Execute(w, inv)
}

// deltaFuncMap provides template helper functions for delta reports.
var deltaFuncMap = template.FuncMap{
	"deltaClass":  deltaClass,
	"reviewClass": reviewClass,
	"truncHash":   truncHash,
	"formatDiff":  formatDiffHTML,
	"formatBytes": formatBytes,
}

// deltaClass returns a CSS class suffix for a delta type.
func deltaClass(dt delta.DeltaType) string {
	return string(dt)
}

// reviewClass returns a CSS class suffix for a review status.
func reviewClass(rs delta.ReviewStatus) string {
	return string(rs)
}

// truncHash returns the first 8 characters of a hash, or the full string if shorter.
func truncHash(h string) string {
	if len(h) > 8 {
		return h[:8]
	}
	return h
}

// formatDiffHTML converts a unified diff string into HTML with colored lines.
func formatDiffHTML(diff string) template.HTML {
	if diff == "" {
		return ""
	}
	var b strings.Builder
	for _, line := range strings.Split(diff, "\n") {
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "---") || strings.HasPrefix(line, "+++"):
			b.WriteString(fmt.Sprintf(`<span class="line-hdr">%s</span>`+"\n", template.HTMLEscapeString(line)))
		case strings.HasPrefix(line, "+"):
			b.WriteString(fmt.Sprintf(`<span class="line-add">%s</span>`+"\n", template.HTMLEscapeString(line)))
		case strings.HasPrefix(line, "-"):
			b.WriteString(fmt.Sprintf(`<span class="line-del">%s</span>`+"\n", template.HTMLEscapeString(line)))
		default:
			b.WriteString(fmt.Sprintf(`<span class="line-ctx">%s</span>`+"\n", template.HTMLEscapeString(line)))
		}
	}
	return template.HTML(b.String())
}

// GenerateDeltaReportHTML writes a self-contained HTML delta report to the writer.
func GenerateDeltaReportHTML(w io.Writer, dr *delta.DeltaReport) error {
	tmpl, err := template.New("delta").Funcs(deltaFuncMap).Parse(deltaHTMLTemplate)
	if err != nil {
		return fmt.Errorf("parsing delta template: %w", err)
	}
	return tmpl.Execute(w, dr)
}

// GenerateMarkdown writes a Markdown report to the writer.
func GenerateMarkdown(w io.Writer, inv *model.Inventory) error {
	fmt.Fprintf(w, "# Skill Inventory Report\n\n")
	fmt.Fprintf(w, "Scanned at: %s\n\n", inv.ScannedAt)
	fmt.Fprintf(w, "## Summary\n\n")
	fmt.Fprintf(w, "| Metric | Value |\n|--------|-------|\n")
	fmt.Fprintf(w, "| Total Skills | %d |\n", inv.TotalCount)
	fmt.Fprintf(w, "| Projects | %d |\n", len(inv.ByProject))
	fmt.Fprintf(w, "| Duplicates | %d |\n", inv.Duplicates)
	fmt.Fprintf(w, "| No Frontmatter | %d |\n", inv.NoFrontmatter)
	fmt.Fprintf(w, "\n## By Type\n\n")
	for t, c := range inv.ByType {
		fmt.Fprintf(w, "- **%s**: %d\n", t, c)
	}
	fmt.Fprintf(w, "\n## By Project\n\n")
	for p, c := range inv.ByProject {
		fmt.Fprintf(w, "- **%s**: %d\n", p, c)
	}
	fmt.Fprintf(w, "\n## Skills\n\n")
	fmt.Fprintf(w, "| Name | Type | Project | Frontmatter | Size |\n")
	fmt.Fprintf(w, "|------|------|---------|-------------|------|\n")
	for _, sk := range inv.Skills {
		hasFM := "no"
		if sk.HasYAMLFrontmatter {
			hasFM = "yes"
		}
		fmt.Fprintf(w, "| %s | %s | %s | %s | %s |\n",
			sk.Name, sk.Type, sk.SourceProject, hasFM, formatBytes(sk.ContentSizeBytes))
	}

	if inv.Duplicates > 0 {
		fmt.Fprintf(w, "\n## Duplicates\n\n")
		for _, sk := range inv.Skills {
			if sk.DuplicateOf != nil {
				fmt.Fprintf(w, "- **%s** is duplicate of **%s**\n", sk.Name, *sk.DuplicateOf)
			}
		}
	}

	if inv.NoFrontmatter > 0 {
		fmt.Fprintf(w, "\n## Skills Without Frontmatter\n\n")
		for _, sk := range inv.Skills {
			if !sk.HasYAMLFrontmatter {
				fmt.Fprintf(w, "- %s (%s) — `%s`\n", sk.Name, sk.Type, sk.SourcePath)
			}
		}
	}

	return nil
}
