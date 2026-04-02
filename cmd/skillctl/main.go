// skillctl — Claude Code skill inventory scanner and reporter.
//
// Usage:
//
//	skillctl scan [--path <dir>] [--recursive] [--output json|md|html] [--include-home] [--out <file>]
//	skillctl report [--format html|md] [--input <scan.json>] [--out <file>]
//	skillctl review [--input <delta.json>] [--port 9115] [--no-browser]
//	skillctl diff <scan1.json> <scan2.json> [--output json|md|html] [--out <file>]
//	skillctl seal [--input <scan.json>] [--by <name>]
//	skillctl seal --list
//	skillctl seal --latest
//	skillctl seal --status
//	skillctl import --target <url> --api-key <key>
//	skillctl audit <skill-id>
//	skillctl version
//	skillctl help
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"

	"github.com/kamir/m3c-tools/pkg/skillctl/browse"
	"github.com/kamir/m3c-tools/pkg/skillctl/delta"
	"github.com/kamir/m3c-tools/pkg/skillctl/model"
	"github.com/kamir/m3c-tools/pkg/skillctl/report"
	"github.com/kamir/m3c-tools/pkg/skillctl/review"
	"github.com/kamir/m3c-tools/pkg/skillctl/scanner"
)

// version, commit, and date are set by goreleaser or release.sh via ldflags.
var (
	version = "0.2.0"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "scan":
		cmdScan(os.Args[2:])
	case "report":
		cmdReport(os.Args[2:])
	case "diff":
		cmdDiff(os.Args[2:])
	case "seal":
		cmdSeal(os.Args[2:])
	case "import":
		cmdImport(os.Args[2:])
	case "audit":
		cmdAudit(os.Args[2:])
	case "review":
		cmdReview(os.Args[2:])
	case "browse":
		cmdBrowse(os.Args[2:])
	case "menubar":
		cmdMenubar(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Printf("skillctl %s (commit=%s, built=%s)\n", version, commit, date)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

// cmdScan scans directories for skill sources and outputs an inventory.
func cmdScan(args []string) {
	var paths []string
	recursive := false
	includeHome := false
	output := "json"
	outFile := ""

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--path":
			if i+1 < len(args) {
				i++
				paths = append(paths, args[i])
			}
		case "--recursive":
			recursive = true
		case "--include-home":
			includeHome = true
		case "--output":
			if i+1 < len(args) {
				i++
				output = args[i]
			}
		case "--out":
			if i+1 < len(args) {
				i++
				outFile = args[i]
			}
		default:
			// Treat bare arguments as paths.
			if args[i] != "" && args[i][0] != '-' {
				paths = append(paths, args[i])
			} else {
				fmt.Fprintf(os.Stderr, "Unknown flag: %s\n", args[i])
				os.Exit(1)
			}
		}
	}

	// Default to current directory if no paths given.
	if len(paths) == 0 {
		cwd, err := os.Getwd()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting working directory: %v\n", err)
			os.Exit(1)
		}
		paths = []string{cwd}
	}

	sc := &scanner.Scanner{
		Paths:       paths,
		Recursive:   recursive,
		IncludeHome: includeHome,
	}

	inv, err := sc.Scan()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Scan error: %v\n", err)
		os.Exit(1)
	}

	// Determine output writer.
	w := os.Stdout
	if outFile != "" {
		f, err := os.Create(outFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		w = f
	}

	switch output {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(inv); err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
			os.Exit(1)
		}
	case "html":
		if err := report.GenerateHTML(w, inv); err != nil {
			fmt.Fprintf(os.Stderr, "Error generating HTML: %v\n", err)
			os.Exit(1)
		}
	case "md":
		if err := report.GenerateMarkdown(w, inv); err != nil {
			fmt.Fprintf(os.Stderr, "Error generating Markdown: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown output format: %s (use json, html, or md)\n", output)
		os.Exit(1)
	}

	// Print summary to stderr when writing to file.
	if outFile != "" {
		fmt.Fprintf(os.Stderr, "Scanned %d skills across %d projects. Output written to %s\n",
			inv.TotalCount, len(inv.ByProject), outFile)
	}
}

// cmdReport generates a report from a previously saved scan JSON.
func cmdReport(args []string) {
	format := "html"
	input := ""
	outFile := ""

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--format":
			if i+1 < len(args) {
				i++
				format = args[i]
			}
		case "--input":
			if i+1 < len(args) {
				i++
				input = args[i]
			}
		case "--out":
			if i+1 < len(args) {
				i++
				outFile = args[i]
			}
		default:
			// Treat bare argument as input file.
			if args[i] != "" && args[i][0] != '-' {
				input = args[i]
			} else {
				fmt.Fprintf(os.Stderr, "Unknown flag: %s\n", args[i])
				os.Exit(1)
			}
		}
	}

	if input == "" {
		fmt.Fprintln(os.Stderr, "Error: --input <scan.json> is required")
		fmt.Fprintln(os.Stderr, "Usage: skillctl report [--format html|md] --input <scan.json> [--out <file>]")
		os.Exit(1)
	}

	// Read scan JSON.
	data, err := os.ReadFile(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
		os.Exit(1)
	}

	var inv model.Inventory
	if err := json.Unmarshal(data, &inv); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing JSON: %v\n", err)
		os.Exit(1)
	}

	// Determine output writer.
	w := os.Stdout
	if outFile != "" {
		f, err := os.Create(outFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		w = f
	}

	switch format {
	case "html":
		if err := report.GenerateHTML(w, &inv); err != nil {
			fmt.Fprintf(os.Stderr, "Error generating HTML: %v\n", err)
			os.Exit(1)
		}
	case "md":
		if err := report.GenerateMarkdown(w, &inv); err != nil {
			fmt.Fprintf(os.Stderr, "Error generating Markdown: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown format: %s (use html or md)\n", format)
		os.Exit(1)
	}

	if outFile != "" {
		fmt.Fprintf(os.Stderr, "Report written to %s\n", outFile)
	}
}

// cmdReview starts a local web server for reviewing skill delta reports.
func cmdReview(args []string) {
	input := ""
	port := "9115"
	noBrowser := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--input":
			if i+1 < len(args) {
				i++
				input = args[i]
			}
		case "--port":
			if i+1 < len(args) {
				i++
				port = args[i]
			}
		case "--no-browser":
			noBrowser = true
		default:
			// Treat bare argument as input file.
			if args[i] != "" && args[i][0] != '-' {
				input = args[i]
			} else {
				fmt.Fprintf(os.Stderr, "Unknown flag: %s\n", args[i])
				os.Exit(1)
			}
		}
	}

	if input == "" {
		fmt.Fprintln(os.Stderr, "Error: --input <delta.json> is required")
		fmt.Fprintln(os.Stderr, "Usage: skillctl review [--input <delta.json>] [--port 9115] [--no-browser]")
		os.Exit(1)
	}

	addr := ":" + port
	srv := review.NewServer(addr, input)
	srv.NoBrowser = noBrowser

	fmt.Fprintf(os.Stderr, "Starting review UI for %s on port %s\n", input, port)
	if err := srv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}

// cmdBrowse launches an interactive skill graph browser.
func cmdBrowse(args []string) {
	input := ""
	port := "9116"
	noBrowser := false
	var paths []string
	recursive := false
	includeHome := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--input":
			if i+1 < len(args) {
				i++
				input = args[i]
			}
		case "--port":
			if i+1 < len(args) {
				i++
				port = args[i]
			}
		case "--path":
			if i+1 < len(args) {
				i++
				paths = append(paths, args[i])
			}
		case "--recursive":
			recursive = true
		case "--include-home":
			includeHome = true
		case "--no-browser":
			noBrowser = true
		default:
			if args[i] != "" && args[i][0] != '-' {
				input = args[i]
			} else {
				fmt.Fprintf(os.Stderr, "Unknown flag: %s\n", args[i])
				os.Exit(1)
			}
		}
	}

	var inv *model.Inventory
	var err error

	if input != "" {
		inv, err = loadInventory(input)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading inventory: %v\n", err)
			os.Exit(1)
		}
	} else {
		if len(paths) == 0 {
			cwd, err := os.Getwd()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error getting working directory: %v\n", err)
				os.Exit(1)
			}
			paths = []string{cwd}
		}
		sc := &scanner.Scanner{
			Paths:       paths,
			Recursive:   recursive,
			IncludeHome: includeHome,
		}
		inv, err = sc.Scan()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Scan error: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Scanned %d skills across %d projects\n", inv.TotalCount, len(inv.ByProject))
	}

	addr := ":" + port
	srv := browse.NewServer(addr, inv)
	srv.NoBrowser = noBrowser

	if err := srv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}

// cmdDiff compares two scan snapshots and outputs a delta report.
func cmdDiff(args []string) {
	output := "text"
	outFile := ""
	var positional []string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--output":
			if i+1 < len(args) {
				i++
				output = args[i]
			}
		case "--out":
			if i+1 < len(args) {
				i++
				outFile = args[i]
			}
		default:
			if args[i] != "" && args[i][0] != '-' {
				positional = append(positional, args[i])
			} else {
				fmt.Fprintf(os.Stderr, "Unknown flag: %s\n", args[i])
				os.Exit(1)
			}
		}
	}

	if len(positional) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: skillctl diff <scan1.json> <scan2.json> [--output json|md|html|text] [--out <file>]")
		os.Exit(1)
	}

	baseline, err := loadInventory(positional[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading baseline %s: %v\n", positional[0], err)
		os.Exit(1)
	}
	current, err := loadInventory(positional[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading current %s: %v\n", positional[1], err)
		os.Exit(1)
	}

	dr := delta.ComputeDelta(baseline, current)
	dr.BaselinePath = positional[0]
	dr.CurrentPath = positional[1]

	// Determine output writer.
	w := os.Stdout
	if outFile != "" {
		f, err := os.Create(outFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		w = f
	}

	switch output {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(dr); err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
			os.Exit(1)
		}
	case "md":
		fmt.Fprint(w, delta.FormatMarkdown(dr))
	case "html":
		if err := report.GenerateDeltaReportHTML(w, dr); err != nil {
			fmt.Fprintf(os.Stderr, "Error generating HTML: %v\n", err)
			os.Exit(1)
		}
	case "text":
		fmt.Fprint(w, delta.FormatSummary(dr))
		if len(dr.Entries) > 0 {
			fmt.Fprintln(w)
			for _, e := range dr.Entries {
				switch e.DeltaType {
				case delta.DeltaAdded:
					fmt.Fprintf(w, "  + %-30s  %s\n", e.SkillName, e.CurrentPath)
				case delta.DeltaRemoved:
					fmt.Fprintf(w, "  - %-30s  %s\n", e.SkillName, e.BaselinePath)
				case delta.DeltaModified:
					fmt.Fprintf(w, "  ~ %-30s  %s -> %s\n", e.SkillName, truncate(e.BaselineHash, 8), truncate(e.CurrentHash, 8))
				case delta.DeltaMoved:
					fmt.Fprintf(w, "  > %-30s  %s -> %s\n", e.SkillName, e.BaselinePath, e.CurrentPath)
				}
			}
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown output format: %s (use json, md, html, or text)\n", output)
		os.Exit(1)
	}

	if outFile != "" {
		fmt.Fprintf(os.Stderr, "Delta report (%d changes) written to %s\n", dr.Summary.Total, outFile)
	}
}

// cmdSeal manages sealed inventory baselines.
func cmdSeal(args []string) {
	input := ""
	sealedBy := ""
	listSeals := false
	showLatest := false
	showStatus := false
	var paths []string
	includeHome := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--input":
			if i+1 < len(args) {
				i++
				input = args[i]
			}
		case "--by":
			if i+1 < len(args) {
				i++
				sealedBy = args[i]
			}
		case "--path":
			if i+1 < len(args) {
				i++
				paths = append(paths, args[i])
			}
		case "--include-home":
			includeHome = true
		case "--list":
			listSeals = true
		case "--latest":
			showLatest = true
		case "--status":
			showStatus = true
		default:
			if args[i] != "" && args[i][0] != '-' {
				input = args[i]
			} else {
				fmt.Fprintf(os.Stderr, "Unknown flag: %s\n", args[i])
				os.Exit(1)
			}
		}
	}

	store, err := delta.NewSealStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening seal store: %v\n", err)
		os.Exit(1)
	}

	// Default sealed-by to current OS user.
	if sealedBy == "" {
		if u, err := user.Current(); err == nil {
			sealedBy = u.Username
		} else {
			sealedBy = "unknown"
		}
	}

	switch {
	case listSeals:
		seals, err := store.ListSeals()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error listing seals: %v\n", err)
			os.Exit(1)
		}
		if len(seals) == 0 {
			fmt.Println("No seals found.")
			return
		}
		fmt.Printf("%-28s  %-20s  %6s  %s\n", "SEAL ID", "SEALED AT", "SKILLS", "HASH")
		for _, s := range seals {
			hash := s.InventoryHash
			if len(hash) > 12 {
				hash = hash[:12]
			}
			fmt.Printf("%-28s  %-20s  %6d  %s\n", s.SealID, s.SealedAt, s.SkillCount, hash)
		}

	case showLatest:
		record, _, err := store.LatestSeal()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading latest seal: %v\n", err)
			os.Exit(1)
		}
		if record == nil {
			fmt.Println("No seals found.")
			return
		}
		fmt.Printf("Seal ID:    %s\n", record.SealID)
		fmt.Printf("Sealed at:  %s\n", record.SealedAt)
		fmt.Printf("Sealed by:  %s\n", record.SealedBy)
		fmt.Printf("Skills:     %d\n", record.SkillCount)
		fmt.Printf("Hash:       %s\n", record.InventoryHash)
		fmt.Printf("Inventory:  %s\n", record.InventoryPath)

	case showStatus:
		record, baselineInv, err := store.LatestSeal()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading latest seal: %v\n", err)
			os.Exit(1)
		}
		if record == nil {
			fmt.Fprintln(os.Stderr, "No baseline seal found. Run 'skillctl seal' first.")
			os.Exit(1)
		}

		// Scan current state.
		scanPaths := paths
		if len(scanPaths) == 0 {
			cwd, err := os.Getwd()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error getting working directory: %v\n", err)
				os.Exit(1)
			}
			scanPaths = []string{cwd}
		}
		sc := &scanner.Scanner{
			Paths:       scanPaths,
			Recursive:   true,
			IncludeHome: includeHome,
		}
		currentInv, err := sc.Scan()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Scan error: %v\n", err)
			os.Exit(1)
		}

		dr := delta.ComputeDelta(baselineInv, currentInv)
		dr.BaselinePath = record.InventoryPath
		dr.CurrentPath = "(live scan)"

		fmt.Printf("Baseline: %s (%s)\n\n", record.SealID, record.SealedAt)
		fmt.Print(delta.FormatSummary(dr))
		if len(dr.Entries) > 0 {
			fmt.Println()
			for _, e := range dr.Entries {
				switch e.DeltaType {
				case delta.DeltaAdded:
					fmt.Printf("  + %-30s  %s\n", e.SkillName, e.CurrentPath)
				case delta.DeltaRemoved:
					fmt.Printf("  - %-30s  %s\n", e.SkillName, e.BaselinePath)
				case delta.DeltaModified:
					fmt.Printf("  ~ %-30s  %s -> %s\n", e.SkillName, truncate(e.BaselineHash, 8), truncate(e.CurrentHash, 8))
				case delta.DeltaMoved:
					fmt.Printf("  > %-30s  %s -> %s\n", e.SkillName, e.BaselinePath, e.CurrentPath)
				}
			}
		}

	default:
		// Seal: create a new baseline.
		var inv *model.Inventory

		if input != "" {
			// Seal from existing scan JSON.
			inv, err = loadInventory(input)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error loading inventory %s: %v\n", input, err)
				os.Exit(1)
			}
		} else {
			// Run a scan, then seal.
			scanPaths := paths
			if len(scanPaths) == 0 {
				cwd, err := os.Getwd()
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error getting working directory: %v\n", err)
					os.Exit(1)
				}
				scanPaths = []string{cwd}
			}
			sc := &scanner.Scanner{
				Paths:       scanPaths,
				Recursive:   true,
				IncludeHome: includeHome,
			}
			inv, err = sc.Scan()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Scan error: %v\n", err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "Scanned %d skills across %d projects\n", inv.TotalCount, len(inv.ByProject))
		}

		record, err := store.Seal(inv, sealedBy)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error sealing inventory: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Sealed %d skills as %s\n", record.SkillCount, record.SealID)
		fmt.Printf("  Sealed by: %s\n", record.SealedBy)
		fmt.Printf("  Hash:      %s\n", record.InventoryHash)
		fmt.Printf("  Inventory: %s\n", record.InventoryPath)
	}
}

// loadInventory reads and parses an inventory JSON file.
func loadInventory(path string) (*model.Inventory, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}
	var inv model.Inventory
	if err := json.Unmarshal(data, &inv); err != nil {
		return nil, fmt.Errorf("parsing JSON: %w", err)
	}
	return &inv, nil
}

// truncate returns the first n characters of s, or s itself if shorter.
func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// cmdImport pushes skills to a remote registry (Phase 3 stub).
func cmdImport(args []string) {
	// TODO: Phase 3 — push skill descriptors to a remote registry API.
	fmt.Fprintln(os.Stderr, "import: not yet implemented (Phase 3)")
	os.Exit(0)
}

// cmdAudit inspects a single skill in detail (Phase 2 stub).
func cmdAudit(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: skillctl audit <skill-id>")
		os.Exit(1)
	}
	// TODO: Phase 2 — deep inspection of a single skill: dependencies, conflicts,
	// version history, content diff, frontmatter validation.
	fmt.Fprintln(os.Stderr, "audit: not yet implemented (Phase 2)")
	os.Exit(0)
}

func printUsage() {
	fmt.Print(`skillctl — Claude Code skill inventory scanner

Usage:
  skillctl scan [options]          Scan directories for skill sources
  skillctl report [options]        Generate report from scan JSON
  skillctl review [options]        Review skill deltas in a local web UI
  skillctl diff <a.json> <b.json>  Compare two scan snapshots
  skillctl seal [options]          Seal current inventory as baseline
  skillctl import [options]        Push skills to remote registry
  skillctl audit <skill-id>        Deep-inspect a single skill
  skillctl browse [options]        Launch interactive skill graph browser
  skillctl menubar [options]       Launch macOS menu bar skill monitor
  skillctl version                 Show version
  skillctl help                    Show this help

Scan options:
  --path <dir>       Directory to scan (can be repeated; default: cwd)
  --recursive        Walk directories recursively (default: false)
  --include-home     Also scan ~/.claude/ for user-global skills
  --output <format>  Output format: json (default), html, md
  --out <file>       Write output to file instead of stdout

Report options:
  --format <fmt>     Report format: html (default), md
  --input <file>     Input scan JSON file (required)
  --out <file>       Write report to file instead of stdout

Diff options:
  --output <format>  Output format: text (default), json, md, html
  --out <file>       Write output to file instead of stdout

Seal options:
  --input <file>     Seal from existing scan JSON (default: run scan)
  --by <name>        Name of person sealing (default: OS user)
  --list             List all sealed baselines
  --latest           Show latest seal info
  --status           Diff current state against latest seal

Review options:
  --input <file>     Delta report JSON file (required)
  --port <port>      HTTP server port (default: 9115)
  --no-browser       Do not open browser automatically

Browse options:
  --input <file>     Use existing scan JSON (default: run live scan)
  --path <dir>       Directory to scan (can be repeated; default: cwd)
  --recursive        Walk directories recursively
  --include-home     Also scan ~/.claude/ for user-global skills
  --port <port>      HTTP server port (default: 9116)
  --no-browser       Do not open browser automatically

Menubar options (macOS only):
  --path <dir>       Directory to watch (can be repeated; default: cwd)
  --interval <dur>   Scan interval (default: 30m)
  --include-home     Also scan ~/.claude/ for user-global skills

Examples:
  skillctl scan --recursive --output json --out scan.json
  skillctl scan --path ~/projects/my-app --include-home --output html --out report.html
  skillctl report --input scan.json --format html --out report.html
  skillctl diff scan-old.json scan-new.json --output html --out delta.html
  skillctl seal --by kamir
  skillctl seal --input scan.json
  skillctl seal --status
  skillctl seal --list
  skillctl review --input delta.json --port 9115
  skillctl browse --input scan.json
  skillctl browse --path ~/projects --recursive --include-home
  skillctl menubar --path ~/projects --interval 15m --include-home
`)
}
