package main

// cli.go — the terminal renderer. It turns the event stream into a coloured,
// presenter-friendly transcript: each scenario header, the live command, its
// streamed output, and a bold exit-code verdict badge.

import (
	"fmt"
	"io"
	"strings"
)

// CLIRenderer renders bus events to a writer. Colour is toggled by Color.
type CLIRenderer struct {
	W     io.Writer
	Color bool
}

const (
	cReset  = "\033[0m"
	cBold   = "\033[1m"
	cDim    = "\033[2m"
	cRed    = "\033[31m"
	cGreen  = "\033[32m"
	cYellow = "\033[33m"
	cBlue   = "\033[34m"
	cCyan   = "\033[36m"
	cGrey   = "\033[90m"
)

func (r *CLIRenderer) c(code, s string) string {
	if !r.Color {
		return s
	}
	return code + s + cReset
}

func (r *CLIRenderer) Render(e Event) {
	switch e.Kind {
	case "ready":
		fmt.Fprintln(r.W, r.c(cBold+cCyan, "\n  skillctl-demo — KuP / CISO skill-trust walkthrough"))
		if e.Text != "" {
			fmt.Fprintln(r.W, r.c(cGrey, "  "+e.Text))
		}
	case "scenario":
		r.renderScenario(e)
	case "step":
		fmt.Fprintln(r.W, "\n  "+r.c(cBold, e.Text))
	case "prep":
		fmt.Fprintln(r.W, "  "+r.c(cGrey, "· "+e.Text))
	case "cmd":
		fmt.Fprintln(r.W, "  "+r.c(cBold+cBlue, "$ "+e.Cmd))
	case "line":
		col := cDim
		if e.Stream == "stderr" {
			col = cYellow
		}
		fmt.Fprintln(r.W, "    "+r.c(col, e.Text))
	case "exit":
		r.renderExit(e)
	case "verdict":
		fmt.Fprintln(r.W, "    "+r.c(cCyan, "▸ "+e.Text+"  ("+verdictWord(e.Verdict)+", code "+itoa(e.Code)+")"))
	case "beat":
		// Kata-board chip: the mastery state after a recorded rep.
		col := cCyan
		if e.State == string(StateGruen) {
			col = cGreen
		} else if e.State == string(StateGelb) {
			col = cYellow
		}
		fmt.Fprintln(r.W, "    "+r.c(cBold+col, "◆ "+e.Text))
	case "note":
		fmt.Fprintln(r.W, "  "+r.c(cGrey, "  "+e.Text))
	case "reset":
		fmt.Fprintln(r.W, r.c(cGrey, "\n  — sandbox reset to clean state —"))
	case "done":
		fmt.Fprintln(r.W, r.c(cBold+cGreen, "\n  ✔ demo complete."))
		if e.Text != "" {
			fmt.Fprintln(r.W, r.c(cGrey, "  "+e.Text))
		}
	}
}

func (r *CLIRenderer) renderScenario(e Event) {
	bar := strings.Repeat("─", 72)
	fmt.Fprintln(r.W, "\n"+r.c(cGrey, bar))
	badge := tierBadge(e.Tier)
	if r.Color {
		badge = r.colorTier(e.Tier)
	}
	fmt.Fprintf(r.W, "  %s  %s\n", badge, r.c(cBold, e.ID+" · "+e.Title))
	if e.ExitDoc != "" {
		fmt.Fprintln(r.W, "  "+r.c(cGrey, "expected: "+e.ExitDoc))
	}
	if e.Story != "" {
		fmt.Fprintln(r.W, "  "+r.c(cReset, wrap(e.Story, 70, "  ")))
	}
	if e.Without != "" {
		fmt.Fprintln(r.W, "  "+r.c(cRed, "without skillctl: ")+r.c(cGrey, wrapCont(e.Without, 70, "  ")))
	}
	if e.Roadmap != "" {
		fmt.Fprintln(r.W, "  "+r.c(cYellow, wrap(e.Roadmap, 70, "  ")))
	}
	fmt.Fprintln(r.W, r.c(cGrey, bar))
}

func (r *CLIRenderer) renderExit(e Event) {
	word := verdictWord(e.Verdict)
	if e.OK {
		mark := "✅"
		fmt.Fprintf(r.W, "  %s  %s\n",
			r.c(cBold+cGreen, mark+" exit "+itoa(e.Code)),
			r.c(cGreen, word+" (expected "+itoa(e.Expected)+")"))
	} else {
		fmt.Fprintf(r.W, "  %s  %s\n",
			r.c(cBold+cRed, "✗ exit "+itoa(e.Code)),
			r.c(cRed, "UNEXPECTED — wanted "+itoa(e.Expected)))
	}
}

func (r *CLIRenderer) colorTier(tier string) string {
	switch tier {
	case "LIVE":
		return r.c(cBold+cGreen, "[LIVE]")
	case "PARTIAL":
		return r.c(cBold+cYellow, "[PARTIAL]")
	default:
		return r.c(cBold+cGrey, "[ROADMAP]")
	}
}

func tierBadge(tier string) string {
	switch tier {
	case "LIVE":
		return "[LIVE]"
	case "PARTIAL":
		return "[PARTIAL]"
	default:
		return "[ROADMAP]"
	}
}

func verdictWord(v string) string {
	switch v {
	case "blocked":
		return "BLOCKED"
	case "allowed":
		return "verified"
	case "refused":
		return "REFUSED"
	default:
		return v
	}
}

// wrap wraps s to width, prefixing continuation lines with indent.
func wrap(s string, width int, indent string) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	var b strings.Builder
	line := words[0]
	for _, w := range words[1:] {
		if len(line)+1+len(w) > width {
			b.WriteString(line + "\n" + indent)
			line = w
		} else {
			line += " " + w
		}
	}
	b.WriteString(line)
	return b.String()
}

func wrapCont(s string, width int, indent string) string { return wrap(s, width, indent) }
