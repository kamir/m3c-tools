package main

// SPEC-0246 §4.5 standalone verb: `skillctl scan --body [<skill-dir>]`.
//
// Runs the behavioural (prose) bodyscan over a single skill's SKILL.md body —
// the prompt-injection / exfiltration / tool-escalation / policy-subversion /
// obfuscation detector in pkg/skillctl/bodyscan. This is deliberately separate
// from the SPEC-0189 inventory scan (`skillctl scan` with no --body): that one
// walks an inventory and reports structural trust; this one reads ONE body and
// reports its Ampel verdict.
//
// Output: a human table on a TTY, JSON on a pipe (override either way with
// --json / --format). Exit codes:
//
//	0  bodyscan 🟢 green (no findings)
//	2  bodyscan 🟡 yellow or 🔴 red (at least one finding)
//
// The non-zero-on-finding contract lets CI gate a skill on `skillctl scan
// --body` without parsing stdout.

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/kamir/m3c-tools/pkg/skillctl/bodyscan"
	skillparser "github.com/kamir/m3c-tools/pkg/skillctl/parser"
)

// hasFlag reports whether token appears as a standalone argument in args. Used
// to route `scan --body` before the inventory flag parser runs.
func hasFlag(args []string, token string) bool {
	for _, a := range args {
		if a == token {
			return true
		}
	}
	return false
}

// runScanBody parses the `scan --body` flags, scans the resolved skill dir's
// SKILL.md body, renders the report, and returns the exit code (0 green, 2 on
// any finding). It is the testable core; cmdScan wires it to os.Exit.
func runScanBody(args []string, stdout, stderr io.Writer) int {
	var (
		dir      string
		jsonOut  bool
		forceTbl bool
	)
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "--body":
			// consumed (the route marker)
		case "--json":
			jsonOut = true
		case "--format":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "skillctl scan --body: --format requires an argument (table|json)")
				return exitUsage
			}
			i++
			switch strings.ToLower(args[i]) {
			case "json":
				jsonOut = true
			case "table":
				forceTbl = true
			default:
				fmt.Fprintf(stderr, "skillctl scan --body: unknown --format %q (use table|json)\n", args[i])
				return exitUsage
			}
		case "-h", "--help":
			fmt.Fprintln(stderr, "Usage: skillctl scan --body [<skill-dir>] [--json|--format table|json]")
			fmt.Fprintln(stderr, "")
			fmt.Fprintln(stderr, "Run the SPEC-0246 behavioural bodyscan over a skill's SKILL.md body.")
			fmt.Fprintln(stderr, "Default dir: the current working directory.")
			fmt.Fprintln(stderr, "Exit: 0 = 🟢 clean, 2 = 🟡/🔴 findings.")
			return exitOK
		default:
			if strings.HasPrefix(a, "-") {
				fmt.Fprintf(stderr, "skillctl scan --body: unknown flag %q\n", a)
				return exitUsage
			}
			if dir != "" {
				fmt.Fprintf(stderr, "skillctl scan --body: unexpected second positional %q\n", a)
				return exitUsage
			}
			dir = a
		}
	}

	// Resolve the skill directory: positional arg, else cwd.
	if dir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "skillctl scan --body: getwd: %v\n", err)
			return exitGeneric
		}
		dir = cwd
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		fmt.Fprintf(stderr, "skillctl scan --body: resolve %q: %v\n", dir, err)
		return exitGeneric
	}

	skillMD, err := resolveSkillMD(abs)
	if err != nil {
		fmt.Fprintf(stderr, "skillctl scan --body: %v\n", err)
		return exitGeneric
	}

	rep, err := scanBodyFile(skillMD)
	if err != nil {
		fmt.Fprintf(stderr, "skillctl scan --body: %v\n", err)
		return exitGeneric
	}

	// Format selection: explicit wins; else TTY heuristic.
	useJSON := jsonOut
	if !jsonOut && !forceTbl {
		useJSON = !isTerminal(os.Stdout)
	}
	if useJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			fmt.Fprintf(stderr, "skillctl scan --body: encode json: %v\n", err)
			return exitGeneric
		}
	} else {
		renderBodyScanTable(stdout, skillMD, rep)
	}

	return bodyScanExitCode(rep.Verdict)
}

// resolveSkillMD returns the path to the SKILL.md inside dir. If dir itself is a
// SKILL.md file it is returned directly; otherwise dir/SKILL.md must exist
// (case-insensitive fallback to skill.md for upstream packs).
func resolveSkillMD(dir string) (string, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return "", fmt.Errorf("stat %q: %w", dir, err)
	}
	if !info.IsDir() {
		// Caller pointed straight at a file.
		return dir, nil
	}
	candidates := []string{"SKILL.md", "skill.md"}
	for _, c := range candidates {
		p := filepath.Join(dir, c)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("no SKILL.md in %s", dir)
}

// scanBodyFile reads a SKILL.md, splits frontmatter from body, and runs the
// bodyscan with the declared allowed-tools + intent.
func scanBodyFile(skillMD string) (bodyscan.BodyScanReport, error) {
	raw, err := os.ReadFile(skillMD)
	if err != nil {
		return bodyscan.BodyScanReport{}, fmt.Errorf("read %s: %w", skillMD, err)
	}
	fm, body, perr := skillparser.Parse(raw)
	if perr != nil {
		// Unparseable frontmatter: scan the whole file as the body so a
		// hostile body hidden behind broken YAML still surfaces.
		body = string(raw)
	}
	in := bodyscan.Input{Body: body}
	if fm != nil {
		in.AllowedTools = fm.AllowedTools
		in.Intent = fm.Intent
	}
	return bodyscan.Scan(in), nil
}

// bodyScanExitCode maps a verdict to the process exit code (0 green, 2 otherwise).
func bodyScanExitCode(v bodyscan.Verdict) int {
	if v == bodyscan.VerdictGreen {
		return exitOK
	}
	return exitUsage
}

// verdictAmpel renders the Ampel glyph for a verdict.
func verdictAmpel(v bodyscan.Verdict) string {
	switch v {
	case bodyscan.VerdictRed:
		return "🔴 red"
	case bodyscan.VerdictYellow:
		return "🟡 yellow"
	default:
		return "🟢 green"
	}
}

// renderBodyScanTable prints a human-readable table of the bodyscan report.
func renderBodyScanTable(w io.Writer, skillMD string, rep bodyscan.BodyScanReport) {
	fmt.Fprintf(w, "bodyscan: %s\n", skillMD)
	fmt.Fprintf(w, "verdict:  %s  (%d finding(s))\n", verdictAmpel(rep.Verdict), len(rep.Findings))
	if len(rep.Findings) == 0 {
		fmt.Fprintln(w, "no behavioural findings.")
		return
	}
	fmt.Fprintln(w, "")
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "RULE\tCATEGORY\tVERDICT\tLINE\tMESSAGE")
	for _, f := range rep.Findings {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\n",
			f.RuleID, f.Category, f.Verdict, f.Span.Line, truncateMsg(f.Message, 70))
	}
	_ = tw.Flush()
}

// truncateMsg keeps a message single-line and bounded for table rendering.
func truncateMsg(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
