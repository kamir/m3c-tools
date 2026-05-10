// Tabwriter-based renderer for `skillctl scan` per SPEC-0189 §5.
//
// Two output formats live here:
//   - renderScanTable — TTY-friendly aligned columns
//   - renderScanTSV   — tab-separated for grep/awk pipelines
package main

import (
	"fmt"
	"io"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/kamir/m3c-tools/pkg/skillctl/model"
)

// renderScanTable writes a SPEC-0189 §5 row layout to w.
func renderScanTable(w io.Writer, inv *model.Inventory, withTrust bool) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if withTrust {
		fmt.Fprintln(tw, "NAME\tTIER\tVERSION\tGOV\tSIGNED\tTRUSTED\tPATH")
	} else {
		fmt.Fprintln(tw, "NAME\tTIER\tVERSION\tGOV\tPATH")
	}
	rows := tabRows(inv, withTrust)
	for _, r := range rows {
		fmt.Fprintln(tw, r)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(w, "\n%d skill(s) total.\n", inv.TotalCount)
	return nil
}

// renderScanTSV writes the same data with literal tabs for pipelines.
func renderScanTSV(w io.Writer, inv *model.Inventory, withTrust bool) error {
	if withTrust {
		fmt.Fprintln(w, "NAME\tTIER\tVERSION\tGOV\tSIGNED\tTRUSTED\tPATH")
	} else {
		fmt.Fprintln(w, "NAME\tTIER\tVERSION\tGOV\tPATH")
	}
	for _, r := range tabRows(inv, withTrust) {
		fmt.Fprintln(w, r)
	}
	return nil
}

// tabRows turns the inventory into a sorted []string of pre-tabbed rows.
func tabRows(inv *model.Inventory, withTrust bool) []string {
	tierRank := map[string]int{"project": 0, "user": 1, "plugin": 2}

	rows := make([]string, 0, len(inv.Skills))
	for _, sk := range inv.Skills {
		// Only emit claude_code_skills in the SPEC-0189 row layout. Other
		// types (commands, agents, MCP) keep flowing through JSON output
		// but are noisy in a tier-oriented table.
		if sk.Type != model.SkillTypeClaudeCodeSkill {
			continue
		}
		version := "-"
		gov := "-"
		if sk.Frontmatter != nil {
			if sk.Frontmatter.Version != "" {
				version = sk.Frontmatter.Version
			}
			if sk.Frontmatter.GovernanceLevel != "" {
				gov = sk.Frontmatter.GovernanceLevel
			}
		}
		tier := sk.Tier
		if tier == "" {
			tier = "-"
		}
		path := sk.SourcePath
		if len(sk.Shadows) > 0 {
			path = fmt.Sprintf("%s  (shadows: %d)", path, len(sk.Shadows))
		}
		var row string
		if withTrust {
			signed := "no"
			trusted := "n/a"
			if sk.Bundle != nil {
				if sk.Bundle.Signed {
					signed = "yes"
				}
				switch sk.Bundle.TrustChain {
				case "verified":
					trusted = "yes"
				case "broken":
					trusted = "BROKEN"
				case "unverified":
					trusted = "n/a"
				}
			}
			row = fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\t%s", sk.Name, tier, version, gov, signed, trusted, path)
		} else {
			row = fmt.Sprintf("%s\t%s\t%s\t%s\t%s", sk.Name, tier, version, gov, path)
		}
		rows = append(rows, row)
	}

	// Sort: tier first, then name. Stable so reruns give identical output.
	sort.SliceStable(rows, func(i, j int) bool {
		ai := tierFromRow(rows[i])
		aj := tierFromRow(rows[j])
		if tierRank[ai] != tierRank[aj] {
			return tierRank[ai] < tierRank[aj]
		}
		ni := nameFromRow(rows[i])
		nj := nameFromRow(rows[j])
		return ni < nj
	})
	return rows
}

func tierFromRow(row string) string {
	for i, ch := range row {
		if ch == '\t' {
			rest := row[i+1:]
			for j, ch2 := range rest {
				if ch2 == '\t' {
					return rest[:j]
				}
			}
			return rest
		}
	}
	return ""
}

func nameFromRow(row string) string {
	for i, ch := range row {
		if ch == '\t' {
			return row[:i]
		}
	}
	return row
}

// isTerminal returns true if w is a TTY. Used to default --format to
// table on TTY and json on pipe per SPEC-0189 §4.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
