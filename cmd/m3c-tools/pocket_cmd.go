//go:build darwin

package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/auth"
	"github.com/kamir/m3c-tools/pkg/er1"
	"github.com/kamir/m3c-tools/pkg/httpsafe"
	"github.com/kamir/m3c-tools/pkg/impression"
	"github.com/kamir/m3c-tools/pkg/menubar"
	"github.com/kamir/m3c-tools/pkg/pocket"
)

func cmdPocket(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: m3c-tools pocket <list|sync|usb-sync|api|cloud-sync|backfill|mappings> [args]")
		os.Exit(1)
	}

	cmd, ok := pocket.CanonicalCLI(args[0])
	if !ok {
		fmt.Fprintf(os.Stderr, "Unknown pocket subcommand: %s\nUsage: m3c-tools pocket <list|sync|usb-sync|api|cloud-sync|backfill|mappings> [args]\n", args[0])
		os.Exit(1)
	}
	switch cmd {
	case "list":
		cmdPocketList(args[1:])
	case "sync":
		cmdPocketSync(args[1:])
	case "api":
		cmdPocketAPI(args[1:])
	case "cloud-sync":
		cmdPocketCloudSync(args[1:])
	case "backfill":
		cmdPocketBackfill(args[1:])
	case "mappings":
		cmdPocketMappings(args[1:])
	}
}

// cmdPocketBackfill registers a pocket-sync mapping for a recording that was
// already uploaded to ER1 outside the normal sync flow (e.g. when /map was
// returning 4xx because the server module wasn't deployed yet).
//
// Usage: m3c-tools pocket backfill <recording_id> <er1_doc_id> <title> <duration_seconds>
func cmdPocketBackfill(args []string) {
	if len(args) < 4 {
		fmt.Fprintln(os.Stderr, "Usage: m3c-tools pocket backfill <recording_id> <er1_doc_id> <title> <duration_seconds>")
		os.Exit(2)
	}
	rid := args[0]
	docID := args[1]
	title := args[2]
	duration, err := strconv.Atoi(args[3])
	if err != nil {
		fmt.Fprintf(os.Stderr, "duration must be an integer (seconds): %v\n", err)
		os.Exit(2)
	}

	pcfg := pocket.LoadConfig()
	if pcfg.APIKey == "" {
		fmt.Fprintln(os.Stderr, "Error: POCKET_API_KEY not set")
		os.Exit(1)
	}
	er1Cfg := er1.LoadConfig()
	if er1Cfg.ContextID == "" {
		fmt.Fprintln(os.Stderr, "Error: ER1_CONTEXT_ID not set")
		os.Exit(1)
	}

	accountID := pocket.DeriveAccountID(pcfg.APIKey)
	syncClient := pocket.NewSyncAPIClient(er1Cfg.APIURL, er1Cfg.APIKey, "", !er1Cfg.VerifySSL)

	if err := syncClient.RegisterMapping(pocket.SyncMapping{
		PocketAccountID:   accountID,
		PocketRecordingID: rid,
		ER1DocID:          docID,
		ER1ContextID:      er1Cfg.ContextID,
		RecordingTitle:    title,
		RecordingDuration: duration,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "backfill failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("OK: registered pocket://%s → %s (account=%s)\n", rid, docID, accountID)
}

// cmdPocketMappings dumps the current contents of _pocket_sync_map for the
// active user + Pocket account. Useful for debugging dedup state.
func cmdPocketMappings(_ []string) {
	pcfg := pocket.LoadConfig()
	er1Cfg := er1.LoadConfig()
	if pcfg.APIKey == "" {
		fmt.Fprintln(os.Stderr, "Error: POCKET_API_KEY not set")
		os.Exit(1)
	}
	accountID := pocket.DeriveAccountID(pcfg.APIKey)
	base := strings.TrimSuffix(strings.TrimSuffix(er1Cfg.APIURL, "/upload_2"), "/upload")
	u := base + "/api/pocket-sync/mappings?pocket_account_id=" + accountID
	req, _ := http.NewRequest("GET", u, nil)
	auth.ApplyAuth(req, er1Cfg.APIKey)
	transport := &http.Transport{}
	if !er1Cfg.VerifySSL {
		// #nosec G402 -- gegated durch pkg/er1.applyTLSVerificationPolicy (SEC-M7),
		// die beim Laden der Config VerifySSL fuer JEDEN Nicht-Loopback-Host
		// fail-closed auf true zwingt. Nach BUG-0445 nimmt kein Aufrufer diesen
		// Wert mehr nachtraeglich zurueck; wer es wieder tut, muss hier neu pruefen.
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	// R-01 / Release It! "Integration Points": ohne Timeout blockiert Do()
	// unbegrenzt, wenn der Server die Verbindung annimmt und nicht antwortet.
	// Die uebrigen 40+ Clients in diesem Repo setzen es korrekt: diese Stelle
	// war die einzige Ausnahme (Scan ueber alle *.go, 2026-09-01).
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: httpsafe.NoCredentialRedirect}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "request failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("URL: %s\nHTTP %d\nAccount: %s\n\n", u, resp.StatusCode, accountID)
	fmt.Println(string(body))
}

// cmdPocketAPI handles Pocket Cloud API subcommands (Phase 2).
func cmdPocketAPI(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: m3c-tools pocket api <list|get|search|health>")
		os.Exit(1)
	}

	client := pocket.NewAPIClient()
	if !client.IsConfigured() {
		fmt.Fprintln(os.Stderr, "Error: POCKET_API_KEY not set")
		fmt.Fprintln(os.Stderr, "Get your key: Pocket app → Settings → Developer → API Keys")
		fmt.Fprintln(os.Stderr, "Then: export POCKET_API_KEY=pk_xxx")
		os.Exit(1)
	}

	switch args[0] {
	case "health":
		if err := client.HealthCheck(); err != nil {
			fmt.Fprintf(os.Stderr, "Pocket API health check failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Pocket Cloud API: OK")

	case "list":
		limit := 20
		page := 1
		recordings, pagination, err := client.ListRecordings(page, limit)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if len(recordings) == 0 {
			fmt.Println("No cloud recordings found.")
			if pagination != nil {
				fmt.Printf("Total: %d\n", pagination.Total)
			}
			return
		}
		fmt.Printf("%-4s %-20s %-8s %-40s\n", "#", "Date", "Duration", "Title")
		fmt.Println(strings.Repeat("-", 76))
		for i, rec := range recordings {
			dur := fmt.Sprintf("%.0fs", rec.Duration)
			title := rec.Title
			if len(title) > 40 {
				title = title[:37] + "..."
			}
			fmt.Printf("%-4d %-20s %-8s %-40s\n", i+1, rec.CreatedAt.Format("2006-01-02 15:04"), dur, title)
		}
		if pagination != nil {
			fmt.Printf("\nPage %d/%d (total: %d)\n", pagination.Page, pagination.TotalPages, pagination.Total)
		}

	case "get":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: m3c-tools pocket api get <recording-id>")
			os.Exit(1)
		}
		rec, err := client.GetRecording(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Title:    %s\n", rec.Title)
		fmt.Printf("Date:     %s\n", rec.CreatedAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("Duration: %.0fs\n", rec.Duration)
		fmt.Printf("State:    %s\n", rec.State)
		fmt.Printf("Language: %s\n", rec.LanguageOrEmpty())
		if md := rec.SummaryMarkdown(); md != "" {
			fmt.Printf("\nSummary:\n%s\n", md)
		}
		if rec.Transcript.Text != "" {
			fmt.Printf("\nTranscript:\n%s\n", rec.Transcript.Text)
		}

	case "search":
		fmt.Fprintln(os.Stderr, "Error: 'search' subcommand removed: Pocket REST search endpoint returns 404 on personal API keys.")
		fmt.Fprintln(os.Stderr, "Use the Pocket MCP server instead: claude mcp add pocket --transport http https://public.heypocketai.com/mcp --header \"Authorization: Bearer $POCKET_API_KEY\"")
		os.Exit(1)

	default:
		fmt.Fprintf(os.Stderr, "Unknown pocket api subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

// cmdPocketCloudSync is the CLI wrapper around runPocketCloudSync.
// Exits non-zero on error; safe for shell scripting.
func cmdPocketCloudSync(args []string) {
	dryRun := false
	for _, a := range args {
		if a == "--dry-run" || a == "-n" {
			dryRun = true
		}
	}
	if err := runPocketCloudSync(dryRun); err != nil {
		fmt.Fprintf(os.Stderr, "pocket cloud-sync: %v\n", err)
		os.Exit(1)
	}
}

// runPocketCloudSync is the Path-B (SPEC-0173) trigger for ingesting Pocket
// Cloud recordings into ER1. Mirrors the Plaud sync flow:
//
//  1. List all recordings via the Pocket Cloud API (paginated client-side)
//  2. Filter to state=="completed" && duration >= POLL_MIN_DURATION (default 10s)
//  3. Cross-device dedup via /api/pocket-sync/check
//  4. For each unsynced recording: GetRecording → build composite doc →
//     er1.Upload (placeholder audio + image, real transcript+summary) →
//     /api/pocket-sync/map register
//
// Returns an error instead of os.Exit so it's safe to call from the menubar.
func runPocketCloudSync(dryRun bool) error {
	pcfg := pocket.LoadConfig()
	if pcfg.APIKey == "" {
		return fmt.Errorf("POCKET_API_KEY not set: get your key from the Pocket app: Settings → Developer → API Keys")
	}

	er1Cfg := er1.LoadConfig()
	if er1Cfg.ContextID == "" {
		return fmt.Errorf("ER1_CONTEXT_ID not set (or no active sign-in)")
	}
	if er1Cfg.APIKey == "" && os.Getenv("ER1_DEVICE_TOKEN") == "" {
		return fmt.Errorf("no ER1 authentication configured: run 'm3c-tools setup' or sign in via the menubar")
	}

	minDuration := 10.0
	if v := os.Getenv("POLL_MIN_DURATION"); v != "" {
		if n, err := strconv.ParseFloat(v, 64); err == nil && n > 0 {
			minDuration = n
		}
	}

	apiClient := pocket.NewAPIClient()
	apiClient.BaseURL = strings.TrimRight(pcfg.APIURL, "/")
	if !apiClient.IsConfigured() {
		return fmt.Errorf("pocket API client not configured")
	}

	syncClient := pocket.NewSyncAPIClient(er1Cfg.APIURL, er1Cfg.APIKey, "", !er1Cfg.VerifySSL)
	accountID := pocket.DeriveAccountID(pcfg.APIKey)

	fmt.Printf("Pocket Cloud Sync: account=%s\n", accountID)
	fmt.Printf("ER1 base URL:    %s\n", syncClient.BaseURL())
	fmt.Printf("Min duration:    %.0fs\n", minDuration)
	if dryRun {
		fmt.Println("MODE: dry-run (no uploads, no mapping writes)")
	}
	fmt.Println(strings.Repeat("-", 60))

	all, err := apiClient.ListRecordingsAll()
	if err != nil {
		return fmt.Errorf("list recordings: %w", err)
	}
	fmt.Printf("Total recordings on account: %d\n", len(all))

	var eligible []pocket.APIRecording
	skippedShort := 0
	skippedPending := 0
	for _, r := range all {
		if !r.IsCompleted() {
			skippedPending++
			continue
		}
		if r.Duration < minDuration {
			skippedShort++
			continue
		}
		eligible = append(eligible, r)
	}
	fmt.Printf("Eligible (completed >= %.0fs): %d  (skipped: %d pending, %d too-short)\n",
		minDuration, len(eligible), skippedPending, skippedShort)

	if len(eligible) == 0 {
		fmt.Println("Nothing to sync.")
		return nil
	}

	ids := make([]string, 0, len(eligible))
	for _, r := range eligible {
		ids = append(ids, r.ID)
	}
	check, err := syncClient.CheckRecordings(accountID, ids)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[warn] sync API check failed: %v\n", err)
	}
	already := map[string]bool{}
	if check != nil {
		for rid := range check.Synced {
			already[rid] = true
		}
	}

	var todo []pocket.APIRecording
	for _, r := range eligible {
		if !already[r.ID] {
			todo = append(todo, r)
		}
	}
	fmt.Printf("Already synced server-side: %d\nTo sync now: %d\n", len(already), len(todo))
	fmt.Println(strings.Repeat("-", 60))

	if dryRun {
		for _, r := range todo {
			fmt.Printf("[dry-run] would sync %s  %q  (%.0fs)\n", r.ID, r.Title, r.Duration)
		}
		return nil
	}

	hostname, _ := os.Hostname()
	synced := 0
	failed := 0

	for _, summary := range todo {
		rec, err := apiClient.GetRecording(summary.ID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[fail] get %s: %v\n", summary.ID, err)
			failed++
			continue
		}

		composite := buildPocketCompositeDoc(rec)
		extra := []string{
			fmt.Sprintf("source:%s", rec.DedupKey()),
		}
		if hostname != "" {
			extra = append(extra, "host:"+hostname)
		}
		for _, t := range rec.Tags {
			t = strings.TrimSpace(t)
			if t != "" && !strings.Contains(t, ",") {
				extra = append(extra, t)
			}
		}
		tags := impression.BuildPocketFieldnoteTags(rec.Title, extra...)

		payload := &er1.UploadPayload{
			TranscriptData:     []byte(strings.TrimSpace(composite) + "\n"),
			TranscriptFilename: fmt.Sprintf("pocket_%s.txt", rec.ID),
			AudioFilename:      fmt.Sprintf("pocket_%s.wav", rec.ID),
			ImageFilename:      "pocket-placeholder.png",
			Tags:               tags,
			ContentType:        pcfg.ContentType,
			DoTranscribe:       false,
		}
		resp, err := er1.Upload(er1Cfg, payload)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[fail] upload %s: %v\n", rec.ID, err)
			failed++
			continue
		}

		mapErr := syncClient.RegisterMapping(pocket.SyncMapping{
			PocketAccountID:   accountID,
			PocketRecordingID: rec.ID,
			ER1DocID:          resp.DocID,
			ER1ContextID:      er1Cfg.ContextID,
			RecordingTitle:    rec.Title,
			RecordingDuration: int(rec.Duration),
			TranscriptLength:  len(rec.Transcript.Text),
		})
		if mapErr != nil {
			fmt.Fprintf(os.Stderr, "[warn] mapping for %s: %v (item is uploaded; dedup may double-fire)\n", rec.ID, mapErr)
		}

		fmt.Printf("[ok]   %s  %q  (%.0fs)  → %s\n", rec.ID, rec.Title, rec.Duration, resp.DocID)
		synced++
	}

	fmt.Println(strings.Repeat("-", 60))
	fmt.Printf("Done. synced=%d  failed=%d  account=%s\n", synced, failed, accountID)
	if failed > 0 {
		return fmt.Errorf("%d recording(s) failed to sync", failed)
	}
	return nil
}

// buildPocketCompositeDoc assembles the transcript+summary text uploaded to ER1
// as transcript_file_ext. Mirrors the Plaud composite-doc convention.
func buildPocketCompositeDoc(rec *pocket.APIRecording) string {
	var b strings.Builder
	b.WriteString("=== POCKET FIELDNOTE ===\n")
	b.WriteString("Title: " + rec.Title + "\n")
	b.WriteString(fmt.Sprintf("Recorded: %s\n", rec.RecordingAt.Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("Duration: %.0fs\n", rec.Duration))
	b.WriteString("Source: " + rec.DedupKey() + "\n")
	if lang := rec.LanguageOrEmpty(); lang != "" {
		b.WriteString("Language: " + lang + "\n")
	}
	b.WriteString("\n=== TRANSCRIPT ===\n")
	if rec.Transcript.Text != "" {
		b.WriteString(rec.Transcript.Text)
		b.WriteString("\n")
	} else {
		b.WriteString("[no transcript]\n")
	}
	if md := rec.SummaryMarkdown(); md != "" {
		b.WriteString("\n=== SUMMARY ===\n")
		b.WriteString(md)
		b.WriteString("\n")
	}
	return b.String()
}

func cmdPocketList(args []string) {
	cfg := pocket.LoadConfig()

	// Parse optional --path flag
	for i := 0; i < len(args); i++ {
		if args[i] == "--path" && i+1 < len(args) {
			cfg.RecordPath = args[i+1]
			i++
		}
	}

	if !cfg.IsDeviceConnected() {
		fmt.Fprintf(os.Stderr, "Pocket not connected at %s\n", cfg.RecordPath)
		os.Exit(1)
	}

	recordings, err := pocket.Scan(cfg.RecordPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error scanning: %v\n", err)
		os.Exit(1)
	}

	if len(recordings) == 0 {
		fmt.Println("No recordings found.")
		return
	}

	// Check staged and grouped status
	staged, _ := pocket.ListStaged(cfg)
	stagedKeys := make(map[string]bool)
	for _, s := range staged {
		stagedKeys[s.DedupeKey()] = true
	}
	groupState := pocket.LoadGroupState(cfg)

	fmt.Printf("Pocket recordings (%d):\n\n", len(recordings))
	fmt.Printf("  %3s  %-12s  %-10s  %8s  %8s  %s\n", "#", "Date", "Time", "Duration", "Size", "Status")
	fmt.Printf("  %3s  %-12s  %-10s  %8s  %8s  %s\n", "---", "----------", "--------", "--------", "--------", "--------")

	newCount := 0
	for i, rec := range recordings {
		status := "new"
		if stagedKeys[rec.DedupeKey()] {
			status = "staged"
		}
		if pocket.FindGroupByFilePath(rec.FilePath, cfg) != nil || pocket.FindGroupByStagedPath(rec, cfg, groupState) != nil {
			status = "grouped"
		}
		if status == "new" {
			newCount++
		}
		fmt.Printf("  %3d  %-12s  %-10s  %8s  %8s  %s\n",
			i+1,
			rec.Date,
			rec.Time,
			menubar.FormatPocketDuration(rec.DurationSec),
			menubar.FormatPocketSize(rec.SizeBytes),
			status,
		)
	}
	fmt.Printf("\nTotal: %d recordings (%d new)\n", len(recordings), newCount)
}

func cmdPocketSync(args []string) {
	cfg := pocket.LoadConfig()
	syncAll := false

	// Parse flags
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--all":
			syncAll = true
		case "--path":
			if i+1 < len(args) {
				cfg.RecordPath = args[i+1]
				i++
			}
		}
	}

	if !syncAll {
		fmt.Fprintln(os.Stderr, "Usage: m3c-tools pocket sync --all [--path <dir>]")
		os.Exit(1)
	}

	if !cfg.IsDeviceConnected() {
		fmt.Fprintf(os.Stderr, "Pocket not connected at %s\n", cfg.RecordPath)
		os.Exit(1)
	}

	recordings, err := pocket.Scan(cfg.RecordPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error scanning: %v\n", err)
		os.Exit(1)
	}

	if len(recordings) == 0 {
		fmt.Println("No recordings found.")
		return
	}

	// Determine which are new (not staged, not grouped)
	staged, _ := pocket.ListStaged(cfg)
	stagedKeys := make(map[string]bool)
	for _, s := range staged {
		stagedKeys[s.DedupeKey()] = true
	}
	groupState := pocket.LoadGroupState(cfg)

	var newRecordings []pocket.Recording
	for _, rec := range recordings {
		if stagedKeys[rec.DedupeKey()] {
			continue
		}
		if pocket.FindGroupByFilePath(rec.FilePath, cfg) != nil || pocket.FindGroupByStagedPath(rec, cfg, groupState) != nil {
			continue
		}
		newRecordings = append(newRecordings, rec)
	}

	if len(newRecordings) == 0 {
		fmt.Printf("All %d recordings already synced.\n", len(recordings))
		return
	}

	fmt.Printf("Found %d recordings, %d new. Syncing...\n", len(recordings), len(newRecordings))

	if err := cfg.EnsureDirs(); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating dirs: %v\n", err)
		os.Exit(1)
	}

	er1Cfg := er1.LoadConfig()
	tags := strings.Join(cfg.DefaultTags, ",")
	success, failed := 0, 0

	for i := range newRecordings {
		rec := &newRecordings[i]
		fmt.Printf("  [%d/%d] %s %s (%s)... ",
			i+1, len(newRecordings), rec.Date, rec.Time,
			menubar.FormatPocketDuration(rec.DurationSec))

		// Stage locally
		if err := pocket.StageRecording(rec, cfg); err != nil {
			fmt.Printf("STAGE FAILED: %v\n", err)
			failed++
			continue
		}

		// Upload to ER1
		stagedPath := pocket.StagedPath(*rec, cfg)
		audioBytes, readErr := os.ReadFile(stagedPath)
		if readErr != nil {
			fmt.Printf("READ FAILED: %v\n", readErr)
			failed++
			continue
		}

		doc := &impression.CompositeDoc{
			ObsType:           impression.PocketFieldnote,
			RecordingTitle:    fmt.Sprintf("Pocket %s %s", rec.Date, rec.Time),
			RecordingDuration: menubar.FormatPocketDuration(rec.DurationSec),
			Timestamp:         rec.Timestamp,
			VideoURL:          rec.FilePath,
		}
		docText := doc.Build()

		payload := &er1.UploadPayload{
			TranscriptData:     []byte(docText),
			TranscriptFilename: fmt.Sprintf("pocket_%s_%s.txt", rec.Date, strings.ReplaceAll(rec.Time, ":", "")),
			AudioData:          audioBytes,
			AudioFilename:      filepath.Base(stagedPath),
			ContentType:        cfg.ContentType,
			Tags:               tags,
		}
		resp, uploadErr := er1.Upload(er1Cfg, payload)
		if uploadErr != nil {
			fmt.Printf("UPLOAD FAILED: %v\n", uploadErr)
			failed++
		} else {
			docID := ""
			if resp != nil {
				docID = resp.DocID
			}
			if docID != "" {
				fmt.Printf("OK → %s\n", docID[:min(8, len(docID))])
			} else {
				fmt.Println("OK")
			}
			success++
		}
	}

	fmt.Printf("\nDone. %d synced, %d failed.\n", success, failed)
}
