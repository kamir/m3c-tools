// Code imported from feature/thinking-engine-phase1 cmd/skillctl/main.go
// as part of SPEC-0189 S0a (scanner family baseline).
// No behavioural changes from feature-branch HEAD.
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
	"github.com/kamir/m3c-tools/pkg/skillctl/awareness"
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

func cmdScan(args []string) {
	// SPEC-0246 §4.5 standalone verb: `skillctl scan --body [<skill-dir>]`
	// runs the behavioural bodyscan over a single skill's SKILL.md body and
	// is wholly separate from the SPEC-0189 inventory scan below. Detect it
	// up front so none of the inventory flags interfere; the inventory scan
	// is left completely untouched when --body is absent.
	if hasFlag(args, "--body") {
		os.Exit(runScanBody(args, os.Stdout, os.Stderr))
	}

	// SPEC-0189 §4 flag set + SPEC-0115 legacy flags + SPEC-0189 §13
	// `--push-to-registry` shorthand (delegates to awareness.Sync).
	var (
		paths           []string
		sources         []string
		recursive       = false
		includeHome     = false
		includeShadowed = false
		withTrust       = false
		verbose         = false
		output          = ""
		outFile         = ""
		// SPEC-0189 §13 amendment.
		pushToRegistry  = false
		dryRunPush      = false
		pushRegistryURL = ""
		pushAttestStr   = "none"
	)

	for i := 0; i < len(args); i++ {
		switch args[i] {
		// SPEC-0189 flags.
		case "--source":
			if i+1 < len(args) {
				i++
				sources = append(sources, args[i])
			}
		case "--include-shadowed":
			includeShadowed = true
		case "--with-trust":
			withTrust = true
		case "--verbose":
			verbose = true
		case "--format":
			if i+1 < len(args) {
				i++
				output = args[i]
			}
		// Legacy SPEC-0115 flags.
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
		// SPEC-0189 §13 amendment: push-to-registry shorthand.
		case "--push-to-registry":
			pushToRegistry = true
			withTrust = true // §13.2: implies --with-trust
		case "--dry-run-push":
			dryRunPush = true
		case "--registry":
			if i+1 < len(args) {
				i++
				pushRegistryURL = args[i]
			}
		case "--default-attest":
			if i+1 < len(args) {
				i++
				pushAttestStr = args[i]
			}
		case "--default-attest-yellow":
			pushAttestStr = "yellow"
		case "--default-attest-green":
			pushAttestStr = "green"
		case "--no-default-attest":
			pushAttestStr = "none"
		default:
			if args[i] != "" && args[i][0] != '-' {
				paths = append(paths, args[i])
			} else {
				fmt.Fprintf(os.Stderr, "Unknown flag: %s\n", args[i])
				os.Exit(1)
			}
		}
	}

	// SPEC-0189 §4: default --source claude when no flags supplied.
	// Legacy SPEC-0115 paths (--path / cwd) is implicitly --source projects.
	useTierAware := len(sources) > 0 && !containsString(sources, string(scanner.SourceProjects))
	if len(sources) == 0 && len(paths) == 0 && !includeHome {
		// True default invocation: scan Claude Code surfaces.
		sources = []string{string(scanner.SourceClaude)}
		useTierAware = true
	}

	var sc *scanner.Scanner
	if useTierAware {
		// SPEC-0189 tier-aware mode.
		var srcs []scanner.Source
		for _, s := range sources {
			srcs = append(srcs, scanner.Source(s))
		}
		roots := scanner.ResolveDefaults(srcs)
		// Append explicit --path roots as TierProject.
		for _, p := range paths {
			abs, _ := filepath.Abs(p)
			roots = append(roots, scanner.ScanRoot{Path: abs, Tier: scanner.TierProject})
		}
		sc = &scanner.Scanner{
			Roots:           roots,
			IncludeShadowed: includeShadowed,
			WithTrust:       withTrust,
		}
	} else {
		// Legacy SPEC-0115 mode.
		if len(paths) == 0 {
			cwd, err := os.Getwd()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error getting working directory: %v\n", err)
				os.Exit(1)
			}
			paths = []string{cwd}
		}
		sc = &scanner.Scanner{
			Paths:       paths,
			Recursive:   recursive,
			IncludeHome: includeHome,
		}
	}

	inv, err := sc.Scan()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Scan error: %v\n", err)
		os.Exit(1)
	}

	// Determine output format default per SPEC-0189 §4: table on TTY, json on pipe.
	if output == "" {
		if isTerminal(os.Stdout) {
			output = "table"
		} else {
			output = "json"
		}
	}

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
	case "table":
		if err := renderScanTable(w, inv, withTrust); err != nil {
			fmt.Fprintf(os.Stderr, "Error rendering table: %v\n", err)
			os.Exit(1)
		}
	case "tsv":
		if err := renderScanTSV(w, inv, withTrust); err != nil {
			fmt.Fprintf(os.Stderr, "Error rendering TSV: %v\n", err)
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
		fmt.Fprintf(os.Stderr, "Unknown output format: %s (use json, table, tsv, html, or md)\n", output)
		os.Exit(1)
	}

	if outFile != "" {
		fmt.Fprintf(os.Stderr, "Scanned %d skills across %d projects. Output written to %s\n",
			inv.TotalCount, len(inv.ByProject), outFile)
	}
	if verbose {
		fmt.Fprintf(os.Stderr, "Scan paths: %v\n", inv.ScanPaths)
	}

	// SPEC-0189 §13 amendment — post-scan push to registry. Delegates
	// to awareness.Sync (Sprint 2 / Stream M1) so both entry points
	// share the same wire contract.
	if pushToRegistry {
		exit := runScanPushToRegistry(inv, pushRegistryURL, pushAttestStr, dryRunPush)
		if exit != 0 {
			os.Exit(exit)
		}
	}
}

// runScanPushToRegistry is the post-scan delegate that backs
// `--push-to-registry`. Pulled out of cmdScan so the inline cmdScan
// flow stays readable AND tests can drive the delegate without
// reproducing the full scan pipeline.
func runScanPushToRegistry(inv *model.Inventory, registryURL, attestStr string, dryRunPush bool) int {
	if !dryRunPush {
		// Per §13.4 acceptance #7 the dry-run-push path is the one
		// pinned by tests. The non-dry-run shorthand is convenience —
		// for now we route it through the same code path with
		// confirm=true. A future op-mode flag can split them.
		fmt.Fprintln(os.Stderr,
			"scan --push-to-registry: live push not yet supported via --push-to-registry; "+
				"pipe `skillctl scan --format json` into `skillctl awareness sync --inventory - --confirm` instead.")
		return exitGeneric
	}
	attestLevel, err := parseAttestLevel(attestStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitUsage
	}

	trustRoots, _ := loadTrustRootsBestEffort()
	resolvedRegistry, regErr := awareness.ResolveRegistry(registryURL, trustRoots)
	if regErr != nil && !dryRunPush {
		fmt.Fprintln(os.Stderr, regErr)
		return exitGeneric
	}
	if resolvedRegistry == "" && dryRunPush {
		// In dry-run-push we don't NEED a registry URL — the envelope
		// dump just needs a placeholder so BuildEnvelope's caller-side
		// validation doesn't complain.
		resolvedRegistry = "https://dryrun.invalid/api/skills"
	}

	signer, identity, fingerprint, sErr := resolveAuthor("", "")
	if sErr != nil {
		fmt.Fprintln(os.Stderr, sErr)
		return exitGeneric
	}

	res, err := awareness.Sync(awareness.Opts{
		Inventory:               inv,
		RegistryURL:             resolvedRegistry,
		TrustRoots:              trustRoots,
		AuthorIdentity:          identity,
		AuthorPubkeyFingerprint: fingerprint,
		AuthorSigner:            signer,
		DefaultAttest:           attestLevel,
		DryRun:                  true, // §13.4 #7: dry-run-push emits envelope to stderr, no HTTP
		Stdout:                  os.Stderr,
		Stderr:                  os.Stderr,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitGeneric
	}
	fmt.Fprintf(os.Stderr, "scan --push-to-registry: dry-run; %d skill(s) in envelope\n",
		len(res.Envelope.Skills))
	return exitOK
}

// containsString returns true if s contains x.
func containsString(s []string, x string) bool {
	for _, v := range s {
		if v == x {
			return true
		}
	}
	return false
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
	userID := "" // BUG-0084: Required for aims-core auth
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
		case "--user-id":
			if i+1 < len(args) {
				i++
				userID = args[i]
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

	// BUG-0084: Resolve user ID: flag > env var.
	if userID == "" {
		userID = os.Getenv("ER1_CONTEXT_ID")
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
	client, err := importer.NewClient(target, apiKey, userID)
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
