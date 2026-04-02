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
//	skillctl consolidate [--input <file>] [--path <dir>] [--recursive] [--include-home] [--report-only] [--fix] [--output text|md|json] [--out <file>]
//	skillctl import --target <url> --api-key <key>
//	skillctl sync-usage [--target <url>] [--api-key <key>]
//	skillctl audit <skill-id>
//	skillctl version
//	skillctl help
package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/internal/dbdriver"
	"github.com/kamir/m3c-tools/pkg/skillctl/browse"
	"github.com/kamir/m3c-tools/pkg/skillctl/consolidate"
	"github.com/kamir/m3c-tools/pkg/skillctl/delta"
	"github.com/kamir/m3c-tools/pkg/skillctl/hasher"
	"github.com/kamir/m3c-tools/pkg/skillctl/importer"
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
	case "consolidate":
		cmdConsolidate(os.Args[2:])
	case "menubar":
		cmdMenubar(os.Args[2:])
	case "sync-usage":
		cmdSyncUsage(os.Args[2:])
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

	// Compute inventory hash for cache staleness detection.
	invJSON, err := json.Marshal(inv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling inventory for hash: %v\n", err)
		os.Exit(1)
	}
	invHash := hasher.ContentHash(invJSON)

	// Open graph store.
	store, err := browse.OpenGraphStore(browse.DefaultGraphDBPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not open graph store: %v (building without cache)\n", err)
		// Fall back to uncached path.
		addr := ":" + port
		srv := browse.NewServer(addr, inv)
		srv.NoBrowser = noBrowser
		if err := srv.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
			os.Exit(1)
		}
		return
	}
	defer store.Close()

	var graph *browse.SkillGraph

	if !store.IsStale(invHash) {
		// Cache hit — load graph from SQLite.
		fmt.Fprintf(os.Stderr, "Loading cached graph...\n")
		graph, err = store.LoadGraph()
		if err != nil || graph == nil {
			// Fallback: rebuild if load fails.
			fmt.Fprintf(os.Stderr, "Cache load failed, rebuilding graph...\n")
			graph = browse.BuildGraph(inv)
			if err := store.SaveGraphWithHash(graph, invHash); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not save graph to cache: %v\n", err)
			}
		}
	} else {
		// Cache miss — build and persist.
		fmt.Fprintf(os.Stderr, "Building graph...\n")
		graph = browse.BuildGraph(inv)
		if err := store.SaveGraphWithHash(graph, invHash); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not save graph to cache: %v\n", err)
		}
	}

	addr := ":" + port
	srv := browse.NewServerWithCache(addr, inv, graph, store, invHash)
	srv.NoBrowser = noBrowser

	if err := srv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}

// cmdConsolidate analyzes skill sprawl across scanned directories and suggests
// consolidation actions (duplicates, annotation gaps, naming issues).
func cmdConsolidate(args []string) {
	input := ""
	var paths []string
	recursive := false
	includeHome := false
	reportOnly := false
	fix := false
	output := "text"
	outFile := ""

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--input":
			if i+1 < len(args) {
				i++
				input = args[i]
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
		case "--report-only":
			reportOnly = true
		case "--fix":
			fix = true
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
				input = args[i]
			} else {
				fmt.Fprintf(os.Stderr, "Unknown flag: %s\n", args[i])
				os.Exit(1)
			}
		}
	}

	// Load inventory from --input or run live scan.
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

	// Analyze the inventory for consolidation opportunities.
	rpt := consolidate.Analyze(inv)

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

	// Render output based on format.
	switch output {
	case "text":
		fmt.Fprint(w, consolidate.FormatTerminal(rpt))
	case "md":
		fmt.Fprint(w, consolidate.FormatMarkdown(rpt))
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rpt); err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown output format: %s (use text, md, or json)\n", output)
		os.Exit(1)
	}

	if outFile != "" {
		fmt.Fprintf(os.Stderr, "Consolidation report written to %s\n", outFile)
	}

	// If --fix is set and --report-only is NOT set, offer to fix annotation gaps.
	if fix && !reportOnly {
		if len(rpt.AnnotationGaps) == 0 {
			fmt.Fprintln(os.Stderr, "No annotation gaps to fix.")
			return
		}
		fmt.Fprintf(os.Stderr, "\nFound %d annotation gaps. Apply frontmatter fixes? [y/N] ", len(rpt.AnnotationGaps))
		var answer string
		fmt.Scanln(&answer)
		if answer == "y" || answer == "Y" || answer == "yes" {
			fixed, skipped, err := consolidate.FixAnnotationGaps(rpt.AnnotationGaps)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error fixing annotation gaps: %v\n", err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "Fixed %d skills, skipped %d\n", fixed, skipped)
		} else {
			fmt.Fprintln(os.Stderr, "Skipped. Re-run with --fix to apply later.")
		}
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

// cmdImport pushes a skill inventory to the aims-core skill profile API.
func cmdImport(args []string) {
	target := ""
	apiKey := ""
	input := ""
	var paths []string
	recursive := false
	includeHome := false
	dryRun := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--target":
			if i+1 < len(args) {
				i++
				target = args[i]
			}
		case "--api-key":
			if i+1 < len(args) {
				i++
				apiKey = args[i]
			}
		case "--input":
			if i+1 < len(args) {
				i++
				input = args[i]
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
		case "--dry-run":
			dryRun = true
		default:
			if args[i] != "" && args[i][0] != '-' {
				input = args[i]
			} else {
				fmt.Fprintf(os.Stderr, "Unknown flag: %s\n", args[i])
				os.Exit(1)
			}
		}
	}

	// --target is required.
	if target == "" {
		fmt.Fprintln(os.Stderr, "Error: --target <url> is required")
		fmt.Fprintln(os.Stderr, "Usage: skillctl import --target <url> [--api-key <key>] [--input <scan.json>] [--dry-run]")
		os.Exit(1)
	}

	// Resolve API key: flag > env var > session file.
	if apiKey == "" {
		apiKey = os.Getenv("M3C_API_KEY")
	}
	if apiKey == "" {
		apiKey = readAPIKeyFromSession()
	}

	// Load inventory from --input or run live scan.
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

	// Create API client.
	client, err := importer.NewClient(target, apiKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Dry-run mode: print summary and exit.
	if dryRun {
		fmt.Print(client.DryRun(inv))
		return
	}

	// Health check before import.
	fmt.Fprintf(os.Stderr, "Checking connectivity to %s ...\n", target)
	if err := client.HealthCheck(); err != nil {
		fmt.Fprintf(os.Stderr, "Health check failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "Health check OK")

	// Import.
	fmt.Fprintf(os.Stderr, "Importing %d skills ...\n", len(inv.Skills))
	resp, err := client.Import(inv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Import failed: %v\n", err)
		os.Exit(1)
	}

	// Print result summary.
	fmt.Printf("Import complete:\n")
	fmt.Printf("  Imported:       %d\n", resp.Imported)
	fmt.Printf("  New candidates: %d\n", resp.NewCandidates)
	fmt.Printf("  Already known:  %d\n", resp.AlreadyKnown)
	if resp.Message != "" {
		fmt.Printf("  Message:        %s\n", resp.Message)
	}
}

// readAPIKeyFromSession attempts to read the api_key field from
// ~/.m3c-tools/er1_session.json. Returns empty string on any error.
func readAPIKeyFromSession() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(home, ".m3c-tools", "er1_session.json"))
	if err != nil {
		return ""
	}
	var session struct {
		APIKey string `json:"api_key"`
	}
	if err := json.Unmarshal(data, &session); err != nil {
		return ""
	}
	return session.APIKey
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

// cmdSyncUsage reads unsynced skill usage events from the local SQLite database
// and POSTs each to aims-core /api/v2/skills/usage. Successfully synced rows are
// marked synced=1 so they are not re-sent.
func cmdSyncUsage(args []string) {
	target := ""
	apiKey := ""

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--target":
			if i+1 < len(args) {
				i++
				target = args[i]
			}
		case "--api-key":
			if i+1 < len(args) {
				i++
				apiKey = args[i]
			}
		default:
			fmt.Fprintf(os.Stderr, "Unknown flag: %s\n", args[i])
			os.Exit(1)
		}
	}

	// Resolve target URL: flag > env var > default.
	if target == "" {
		target = os.Getenv("M3C_API_URL")
	}
	if target == "" {
		target = "https://onboarding.guide"
	}
	target = strings.TrimRight(target, "/")

	// Resolve API key: flag > env var > session file.
	if apiKey == "" {
		apiKey = os.Getenv("M3C_API_KEY")
	}
	if apiKey == "" {
		apiKey = readAPIKeyFromSession()
	}
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "Error: no API key found (use --api-key, M3C_API_KEY, or ~/.m3c-tools/er1_session.json)")
		os.Exit(1)
	}

	// Open the local usage database.
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting home directory: %v\n", err)
		os.Exit(1)
	}
	dbPath := filepath.Join(home, ".m3c-tools", "skill-usage.db")

	db, err := sql.Open(dbdriver.DriverName(), dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening usage database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// Read all unsynced rows.
	rows, err := db.Query("SELECT id, skill_id, user_id, timestamp, project, session_id FROM skill_usage WHERE synced = 0 ORDER BY id")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error querying unsynced events: %v\n", err)
		os.Exit(1)
	}

	type usageRow struct {
		ID        int64
		SkillID   string
		UserID    string
		Timestamp string
		Project   string
		SessionID string
	}

	var pending []usageRow
	for rows.Next() {
		var r usageRow
		if err := rows.Scan(&r.ID, &r.SkillID, &r.UserID, &r.Timestamp, &r.Project, &r.SessionID); err != nil {
			fmt.Fprintf(os.Stderr, "Error scanning row: %v\n", err)
			continue
		}
		pending = append(pending, r)
	}
	rows.Close()

	if len(pending) == 0 {
		fmt.Println("No unsynced usage events.")
		return
	}

	fmt.Fprintf(os.Stderr, "Found %d unsynced usage events. Syncing to %s ...\n", len(pending), target)

	httpClient := &http.Client{Timeout: 10 * time.Second}
	synced := 0

	for _, r := range pending {
		event := map[string]interface{}{
			"skill_id":  r.SkillID,
			"user_id":   r.UserID,
			"timestamp": r.Timestamp,
			"context": map[string]string{
				"project":    r.Project,
				"session_id": r.SessionID,
				"source":     "claude_code_hook",
			},
		}

		body, err := json.Marshal(event)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  [SKIP] id=%d: marshal error: %v\n", r.ID, err)
			continue
		}

		url := target + "/api/v2/skills/usage"
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			fmt.Fprintf(os.Stderr, "  [SKIP] id=%d: request error: %v\n", r.ID, err)
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-KEY", apiKey)
		req.Header.Set("X-User-ID", r.UserID)

		resp, err := httpClient.Do(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  [FAIL] id=%d (%s): %v\n", r.ID, r.SkillID, err)
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			now := time.Now().UTC().Format(time.RFC3339)
			_, err := db.Exec("UPDATE skill_usage SET synced = 1, synced_at = ? WHERE id = ?", now, r.ID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  [WARN] id=%d: synced but failed to update local DB: %v\n", r.ID, err)
			}
			synced++
		} else {
			fmt.Fprintf(os.Stderr, "  [FAIL] id=%d (%s): HTTP %d\n", r.ID, r.SkillID, resp.StatusCode)
		}
	}

	fmt.Printf("Synced %d/%d usage events\n", synced, len(pending))
}

func printUsage() {
	fmt.Print(`skillctl — Claude Code skill inventory scanner

Usage:
  skillctl scan [options]          Scan directories for skill sources
  skillctl report [options]        Generate report from scan JSON
  skillctl review [options]        Review skill deltas in a local web UI
  skillctl diff <a.json> <b.json>  Compare two scan snapshots
  skillctl seal [options]          Seal current inventory as baseline
  skillctl import [options]        Import skills to aims-core profile API
  skillctl audit <skill-id>        Deep-inspect a single skill
  skillctl browse [options]        Launch interactive skill graph browser
  skillctl consolidate [options]   Analyze skill sprawl and suggest fixes
  skillctl sync-usage [options]    Sync local skill usage events to aims-core
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

Consolidate options:
  --input <file>     Use existing scan JSON (default: run live scan)
  --path <dir>       Directory to scan (can be repeated; default: cwd)
  --recursive        Walk directories recursively
  --include-home     Also scan ~/.claude/ for user-global skills
  --report-only      Analysis only, do not apply any fixes
  --fix              Auto-add frontmatter to unannotated skills
  --output <format>  Output format: text (default), md, json
  --out <file>       Write output to file instead of stdout

Import options:
  --target <url>     Target aims-core URL (required)
  --api-key <key>    API key (or set M3C_API_KEY, or ~/.m3c-tools/er1_session.json)
  --input <file>     Use existing scan JSON (default: run live scan)
  --path <dir>       Directory to scan (can be repeated; default: cwd)
  --recursive        Walk directories recursively
  --include-home     Also scan ~/.claude/ for user-global skills
  --dry-run          Print import summary without sending data

Sync-usage options:
  --target <url>     Target aims-core URL (default: M3C_API_URL or https://onboarding.guide)
  --api-key <key>    API key (or set M3C_API_KEY, or ~/.m3c-tools/er1_session.json)

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
  skillctl consolidate --path /Users/kamir --recursive --include-home --fix
  skillctl consolidate --input scan.json --output md --out sprawl-report.md
  skillctl import --target https://onboarding.guide --api-key $KEY --input scan.json
  skillctl import --target https://onboarding.guide --dry-run --recursive --include-home
  skillctl menubar --path ~/projects --interval 15m --include-home
  skillctl sync-usage
  skillctl sync-usage --target https://onboarding.guide --api-key $KEY
`)
}
