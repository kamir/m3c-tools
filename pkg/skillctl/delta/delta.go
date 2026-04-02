// Package delta computes differences between two skill inventories and
// provides seal/baseline management for tracking skill changes over time.
package delta

import (
	"fmt"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/model"
)

// DeltaType classifies a change between two inventory snapshots.
type DeltaType string

const (
	DeltaAdded    DeltaType = "added"
	DeltaModified DeltaType = "modified"
	DeltaRemoved  DeltaType = "removed"
	DeltaMoved    DeltaType = "moved"
)

// ReviewStatus tracks human review state for a delta entry.
type ReviewStatus string

const (
	ReviewPending  ReviewStatus = "pending"
	ReviewApproved ReviewStatus = "approved"
	ReviewRejected ReviewStatus = "rejected"
	ReviewDeferred ReviewStatus = "deferred"
)

// DeltaEntry describes a single change between two inventory snapshots.
type DeltaEntry struct {
	SkillID             string             `json:"skill_id"`
	SkillName           string             `json:"skill_name"`
	DeltaType           DeltaType          `json:"delta_type"`
	BaselineHash        string             `json:"baseline_hash,omitempty"`
	CurrentHash         string             `json:"current_hash,omitempty"`
	BaselinePath        string             `json:"baseline_path,omitempty"`
	CurrentPath         string             `json:"current_path,omitempty"`
	BaselineFrontmatter *model.Frontmatter `json:"baseline_frontmatter,omitempty"`
	CurrentFrontmatter  *model.Frontmatter `json:"current_frontmatter,omitempty"`
	BaselineContent     string             `json:"baseline_content,omitempty"`
	CurrentContent      string             `json:"current_content,omitempty"`
	ContentDiff         string             `json:"content_diff"`
	ReviewStatus        ReviewStatus       `json:"review_status"`
	ReviewedBy          string             `json:"reviewed_by,omitempty"`
	ReviewedAt          string             `json:"reviewed_at,omitempty"`
}

// DeltaReport holds the full result of comparing two inventories.
type DeltaReport struct {
	ComputedAt   string       `json:"computed_at"`
	BaselinePath string       `json:"baseline_path"`
	CurrentPath  string       `json:"current_path"`
	Entries      []DeltaEntry `json:"entries"`
	Summary      DeltaSummary `json:"summary"`
}

// DeltaSummary provides aggregate counts of changes.
type DeltaSummary struct {
	Added    int `json:"added"`
	Modified int `json:"modified"`
	Removed  int `json:"removed"`
	Moved    int `json:"moved"`
	Total    int `json:"total"`
}

// ComputeDelta compares two inventories and returns a report of all changes.
// Skills are matched by ID (source_project/name). The algorithm also detects
// moves: a removed+added pair where the content hash is the same but the
// source path differs.
func ComputeDelta(baseline, current *model.Inventory) *DeltaReport {
	report := &DeltaReport{
		ComputedAt: time.Now().UTC().Format(time.RFC3339),
		Entries:    make([]DeltaEntry, 0),
	}

	// Index both inventories by skill ID.
	baseMap := make(map[string]*model.SkillDescriptor, len(baseline.Skills))
	for i := range baseline.Skills {
		baseMap[baseline.Skills[i].ID] = &baseline.Skills[i]
	}
	currMap := make(map[string]*model.SkillDescriptor, len(current.Skills))
	for i := range current.Skills {
		currMap[current.Skills[i].ID] = &current.Skills[i]
	}

	// Track removed and added entries for move detection.
	var removed []DeltaEntry
	var added []DeltaEntry

	// Find removed and modified skills.
	for id, base := range baseMap {
		curr, exists := currMap[id]
		if !exists {
			removed = append(removed, DeltaEntry{
				SkillID:             id,
				SkillName:           base.Name,
				DeltaType:           DeltaRemoved,
				BaselineHash:        base.ContentHash,
				BaselinePath:        base.SourcePath,
				BaselineFrontmatter: base.Frontmatter,
				ReviewStatus:        ReviewPending,
			})
			continue
		}
		// Skill exists in both — check for modifications.
		if base.ContentHash != curr.ContentHash {
			diff := GenerateUnifiedDiff(base.ContentHash, curr.ContentHash,
				fmt.Sprintf("baseline:%s", id), fmt.Sprintf("current:%s", id))

			entry := DeltaEntry{
				SkillID:             id,
				SkillName:           curr.Name,
				DeltaType:           DeltaModified,
				BaselineHash:        base.ContentHash,
				CurrentHash:         curr.ContentHash,
				BaselinePath:        base.SourcePath,
				CurrentPath:         curr.SourcePath,
				BaselineFrontmatter: base.Frontmatter,
				CurrentFrontmatter:  curr.Frontmatter,
				ContentDiff:         diff,
				ReviewStatus:        ReviewPending,
			}
			report.Entries = append(report.Entries, entry)
		}
	}

	// Find added skills.
	for id, curr := range currMap {
		if _, exists := baseMap[id]; !exists {
			added = append(added, DeltaEntry{
				SkillID:            id,
				SkillName:          curr.Name,
				DeltaType:          DeltaAdded,
				CurrentHash:        curr.ContentHash,
				CurrentPath:        curr.SourcePath,
				CurrentFrontmatter: curr.Frontmatter,
				ReviewStatus:       ReviewPending,
			})
		}
	}

	// Detect moves: match removed+added pairs with the same content hash.
	// A move is when a skill changed ID (project/name) but the content is identical.
	movedRemovedIdx := make(map[int]bool)
	movedAddedIdx := make(map[int]bool)

	for ri, rem := range removed {
		if movedRemovedIdx[ri] || rem.BaselineHash == "" {
			continue
		}
		for ai, add := range added {
			if movedAddedIdx[ai] || add.CurrentHash == "" {
				continue
			}
			if rem.BaselineHash == add.CurrentHash {
				// Same content, different ID — this is a move.
				entry := DeltaEntry{
					SkillID:             add.SkillID,
					SkillName:           add.SkillName,
					DeltaType:           DeltaMoved,
					BaselineHash:        rem.BaselineHash,
					CurrentHash:         add.CurrentHash,
					BaselinePath:        rem.BaselinePath,
					CurrentPath:         add.CurrentPath,
					BaselineFrontmatter: rem.BaselineFrontmatter,
					CurrentFrontmatter:  add.CurrentFrontmatter,
					ContentDiff:         fmt.Sprintf("moved: %s -> %s", rem.BaselinePath, add.CurrentPath),
					ReviewStatus:        ReviewPending,
				}
				report.Entries = append(report.Entries, entry)
				movedRemovedIdx[ri] = true
				movedAddedIdx[ai] = true
				break
			}
		}
	}

	// Append remaining (non-moved) removed and added entries.
	for i, entry := range removed {
		if !movedRemovedIdx[i] {
			report.Entries = append(report.Entries, entry)
		}
	}
	for i, entry := range added {
		if !movedAddedIdx[i] {
			report.Entries = append(report.Entries, entry)
		}
	}

	// Compute summary.
	for _, e := range report.Entries {
		switch e.DeltaType {
		case DeltaAdded:
			report.Summary.Added++
		case DeltaModified:
			report.Summary.Modified++
		case DeltaRemoved:
			report.Summary.Removed++
		case DeltaMoved:
			report.Summary.Moved++
		}
	}
	report.Summary.Total = len(report.Entries)

	return report
}

// GenerateUnifiedDiff produces a unified-diff-style string comparing two
// text blocks. It performs a simple line-by-line comparison with context.
func GenerateUnifiedDiff(oldContent, newContent, oldLabel, newLabel string) string {
	oldLines := splitLines(oldContent)
	newLines := splitLines(newContent)

	var b strings.Builder
	fmt.Fprintf(&b, "--- %s\n", oldLabel)
	fmt.Fprintf(&b, "+++ %s\n", newLabel)

	// Use a simple LCS-based diff to produce +/- hunks.
	lcs := computeLCS(oldLines, newLines)
	oi, ni, li := 0, 0, 0

	for oi < len(oldLines) || ni < len(newLines) {
		if li < len(lcs) && oi < len(oldLines) && ni < len(newLines) &&
			oldLines[oi] == lcs[li] && newLines[ni] == lcs[li] {
			// Common line.
			fmt.Fprintf(&b, " %s\n", oldLines[oi])
			oi++
			ni++
			li++
		} else {
			// Output removed lines from old until we hit the next LCS line.
			for oi < len(oldLines) && (li >= len(lcs) || oldLines[oi] != lcs[li]) {
				fmt.Fprintf(&b, "-%s\n", oldLines[oi])
				oi++
			}
			// Output added lines from new until we hit the next LCS line.
			for ni < len(newLines) && (li >= len(lcs) || newLines[ni] != lcs[li]) {
				fmt.Fprintf(&b, "+%s\n", newLines[ni])
				ni++
			}
		}
	}

	return b.String()
}

// splitLines splits text into lines, preserving empty trailing entries
// only when the input is non-empty.
func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	lines := strings.Split(s, "\n")
	// Remove trailing empty element from a trailing newline.
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// computeLCS returns the longest common subsequence of two string slices.
func computeLCS(a, b []string) []string {
	m, n := len(a), len(b)
	// Build the LCS length table.
	dp := make([][]int, m+1)
	for i := range dp {
		dp[i] = make([]int, n+1)
	}
	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if a[i-1] == b[j-1] {
				dp[i][j] = dp[i-1][j-1] + 1
			} else if dp[i-1][j] >= dp[i][j-1] {
				dp[i][j] = dp[i-1][j]
			} else {
				dp[i][j] = dp[i][j-1]
			}
		}
	}
	// Backtrack to find the LCS.
	lcs := make([]string, 0, dp[m][n])
	i, j := m, n
	for i > 0 && j > 0 {
		if a[i-1] == b[j-1] {
			lcs = append(lcs, a[i-1])
			i--
			j--
		} else if dp[i-1][j] >= dp[i][j-1] {
			i--
		} else {
			j--
		}
	}
	// Reverse.
	for left, right := 0, len(lcs)-1; left < right; left, right = left+1, right-1 {
		lcs[left], lcs[right] = lcs[right], lcs[left]
	}
	return lcs
}

// FormatSummary returns a human-readable summary string for a delta report.
func FormatSummary(r *DeltaReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Delta Report  %s\n", r.ComputedAt)
	fmt.Fprintf(&b, "  Baseline: %s\n", r.BaselinePath)
	fmt.Fprintf(&b, "  Current:  %s\n", r.CurrentPath)
	fmt.Fprintf(&b, "  Changes:  %d total\n", r.Summary.Total)
	fmt.Fprintf(&b, "    Added:    %d\n", r.Summary.Added)
	fmt.Fprintf(&b, "    Modified: %d\n", r.Summary.Modified)
	fmt.Fprintf(&b, "    Removed:  %d\n", r.Summary.Removed)
	fmt.Fprintf(&b, "    Moved:    %d\n", r.Summary.Moved)
	return b.String()
}

// FormatMarkdown returns a Markdown-formatted delta report.
func FormatMarkdown(r *DeltaReport) string {
	var b strings.Builder
	b.WriteString("# Skill Delta Report\n\n")
	b.WriteString(fmt.Sprintf("Computed at: %s\n\n", r.ComputedAt))
	b.WriteString("## Summary\n\n")
	b.WriteString("| Change | Count |\n|--------|-------|\n")
	b.WriteString(fmt.Sprintf("| Added | %d |\n", r.Summary.Added))
	b.WriteString(fmt.Sprintf("| Modified | %d |\n", r.Summary.Modified))
	b.WriteString(fmt.Sprintf("| Removed | %d |\n", r.Summary.Removed))
	b.WriteString(fmt.Sprintf("| Moved | %d |\n", r.Summary.Moved))
	b.WriteString(fmt.Sprintf("| **Total** | **%d** |\n", r.Summary.Total))

	if len(r.Entries) == 0 {
		b.WriteString("\nNo changes detected.\n")
		return b.String()
	}

	b.WriteString("\n## Changes\n\n")
	b.WriteString("| Skill | Type | Detail |\n|-------|------|--------|\n")
	for _, e := range r.Entries {
		detail := ""
		switch e.DeltaType {
		case DeltaAdded:
			detail = e.CurrentPath
		case DeltaRemoved:
			detail = e.BaselinePath
		case DeltaModified:
			bh := e.BaselineHash
			ch := e.CurrentHash
			if len(bh) > 8 {
				bh = bh[:8]
			}
			if len(ch) > 8 {
				ch = ch[:8]
			}
			detail = fmt.Sprintf("%s -> %s", bh, ch)
		case DeltaMoved:
			detail = fmt.Sprintf("%s -> %s", e.BaselinePath, e.CurrentPath)
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %s |\n", e.SkillName, e.DeltaType, detail))
	}

	return b.String()
}
