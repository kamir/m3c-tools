// main_other.go — CLI + system tray entry point for non-macOS platforms.
// The system tray (menubar command) uses fyne.io/systray via pkg/tray.
// GUI features that require macOS (observation window, recording) are not available.
//
//go:build !darwin

package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/kamir/m3c-tools/pkg/auth"
	"github.com/kamir/m3c-tools/pkg/config"
	"github.com/kamir/m3c-tools/pkg/er1"
	"github.com/kamir/m3c-tools/pkg/impression"
	"github.com/kamir/m3c-tools/pkg/plaud"
	"github.com/kamir/m3c-tools/pkg/tracking"
	"github.com/kamir/m3c-tools/pkg/transcript"
	"github.com/kamir/m3c-tools/pkg/tray"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	// Load config: layered per SPEC-0175 (mirrors darwin main.go).
	//   1. Active profile (account-scoped)
	//   2. Global preferences (~/.m3c-tools/preferences.env, legacy fallback)
	//   3. Project-local .env
	if _, migErr := config.MigrateLegacyPreferences(); migErr != nil {
		log.Printf("[config] preferences migration warning: %v", migErr)
	}
	pm := config.NewProfileManager()
	if activeProfile, err := pm.ActiveProfile(); err == nil {
		_ = pm.ApplyProfile(activeProfile)
		log.Printf("[config] profile: %s", activeProfile.Name)
	}
	for _, p := range []string{config.PreferencesPath(), config.LegacyPreferencesPath(), ".env"} {
		if p != "" {
			_ = er1.LoadDotenv(p)
		}
	}

	// Load saved device token if available (SPEC-0127).
	// This enables uploads via Bearer auth without API key.
	if cfg := er1.LoadConfig(); cfg.ContextID != "" {
		if dt, err := auth.Load(auth.DeviceID(), strings.SplitN(cfg.ContextID, "___", 2)[0]); err == nil && dt != nil && !dt.IsExpired() {
			os.Setenv("ER1_DEVICE_TOKEN", dt.Token)
			os.Setenv("ER1_CONTEXT_ID", dt.ContextID)
			log.Printf("[auth] device token loaded for user=%s", truncateForLog(dt.UserID, 20))
		}
	}

	switch os.Args[1] {
	case "config":
		cmdConfig(os.Args[2:])
	case "transcript":
		cmdTranscript(os.Args[2:])
	case "plaud":
		cmdPlaud(os.Args[2:])
	case "setup":
		cmdSetup(os.Args[2:])
	case "check-er1":
		cmdCheckER1()
	case "doctor":
		cmdDoctor()
	case "login":
		cmdLogin()
	case "menubar":
		cmdTrayApp(os.Args[2:])
	case "record", "devices":
		fmt.Fprintln(os.Stderr, "Error: audio recording requires macOS with PortAudio")
		os.Exit(1)
	case "screenshot":
		fmt.Fprintln(os.Stderr, "Error: screenshot capture requires macOS")
		os.Exit(1)
	case "version", "--version", "-v":
		printVersion()
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

// cmdSetup runs the interactive ER1 onboarding wizard.
func cmdSetup(args []string) {
	noBrowser := false
	er1URL := ""
	tags := ""

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--no-browser":
			noBrowser = true
		case "--er1-url":
			if i+1 < len(args) {
				i++
				er1URL = args[i]
			}
		case "--tags":
			if i+1 < len(args) {
				i++
				tags = args[i]
			}
		}
	}

	reader := bufio.NewReader(os.Stdin)

	fmt.Println()
	fmt.Println("  m3c-tools Setup")
	fmt.Println("  ================")
	fmt.Println()

	// 1. ER1 Server URL
	if er1URL == "" {
		fmt.Print("  ER1 Server URL [https://onboarding.guide/upload_2]: ")
		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line != "" {
			er1URL = line
		} else {
			er1URL = "https://onboarding.guide/upload_2"
		}
	}
	fmt.Printf("  Using: %s\n\n", er1URL)

	// 2. Login to capture context ID
	var contextID string
	if noBrowser {
		fmt.Print("  Enter your ER1 User ID: ")
		line, _ := reader.ReadString('\n')
		contextID = strings.TrimSpace(line)
		if contextID == "" {
			fmt.Fprintln(os.Stderr, "Error: context ID is required")
			os.Exit(1)
		}
	} else {
		// Use CDP to capture context ID from browser login.
		contextID = captureER1ContextID(reader, er1URL)
	}
	fmt.Printf("\n  User ID: %s\n\n", contextID)

	// 3. Default tags
	if tags == "" {
		fmt.Print("  Default tags for Plaud sync [plaud,fieldnote]: ")
		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line != "" {
			tags = line
		} else {
			tags = "plaud,fieldnote"
		}
	}

	// 4. API key
	fmt.Print("  ER1 API Key (leave blank if none): ")
	apiKeyLine, _ := reader.ReadString('\n')
	apiKey := strings.TrimSpace(apiKeyLine)

	// 5. Write config (legacy path for backward compat).
	if err := er1.WriteConfig(er1URL, apiKey, contextID, true, tags); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing config: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\n  Configuration saved to %s\n\n", er1.ConfigPath())

	// BUG-0093: Also update the active profile if the profile system is in use.
	// Without this, the profile's empty ER1_API_KEY overrides the setup values.
	setupPM := config.NewProfileManager()
	if activeP, pmErr := setupPM.ActiveProfile(); pmErr == nil {
		activeP.Vars["ER1_API_URL"] = er1URL
		if apiKey != "" {
			activeP.Vars["ER1_API_KEY"] = apiKey
		}
		activeP.Vars["ER1_CONTEXT_ID"] = contextID
		activeP.Vars["PLAUD_DEFAULT_TAGS"] = tags
		if createErr := setupPM.CreateProfile(activeP.Name, activeP.Description, activeP.Vars); createErr != nil {
			fmt.Fprintf(os.Stderr, "  Warning: could not update profile %q: %v\n", activeP.Name, createErr)
		} else {
			fmt.Printf("  Profile %q updated with new settings.\n", activeP.Name)
		}
	}

	// 6. Reload config and check connectivity
	_ = er1.LoadDotenv(er1.ConfigPath())
	cfg := er1.LoadConfig()
	if er1.IsReachable(cfg) {
		fmt.Println("  ER1 server: REACHABLE")
	} else {
		fmt.Println("  ER1 server: UNREACHABLE (check URL and network)")
	}
	fmt.Println("  Ready to sync. Try: m3c-tools plaud list")
	fmt.Println()
}

// captureER1ContextID opens the ER1 login page in Chrome and captures the user's
// context ID via CDP. Falls back to manual entry if Chrome is unavailable.
func captureER1ContextID(reader *bufio.Reader, er1URL string) string {
	// Derive the base URL from the upload endpoint.
	baseURL := er1URL
	if idx := strings.LastIndex(baseURL, "/upload"); idx > 0 {
		baseURL = baseURL[:idx]
	}

	fmt.Println("  Opening login page in your browser...")

	// Try to launch Chrome with CDP for context ID extraction.
	chromePath := plaud.FindChrome()
	if chromePath == "" {
		// No Chrome — open in default browser and ask for manual entry.
		_ = openURL(baseURL)
		fmt.Println("  Please log in, then enter your User ID from the dashboard.")
		fmt.Print("  User ID: ")
		line, _ := reader.ReadString('\n')
		return strings.TrimSpace(line)
	}

	// Launch Chrome with debug port.
	// FIX C-H01: Use random temp dir instead of predictable path to prevent symlink attacks.
	debugDir, err := os.MkdirTemp("", "m3c-tools-er1-setup-*")
	if err != nil {
		fmt.Printf("  Could not create temp dir: %v\n", err)
		fmt.Print("  Enter your User ID manually: ")
		line, _ := reader.ReadString('\n')
		return strings.TrimSpace(line)
	}
	defer os.RemoveAll(debugDir)
	cmd := cmdExec(chromePath,
		"--remote-debugging-port=9222",
		"--user-data-dir="+debugDir,
		baseURL,
	)
	if err := cmd.Start(); err != nil {
		fmt.Printf("  Could not launch Chrome: %v\n", err)
		fmt.Print("  Enter your User ID manually: ")
		line, _ := reader.ReadString('\n')
		return strings.TrimSpace(line)
	}

	fmt.Println("  Please log in, then press Enter to continue...")
	_, _ = reader.ReadString('\n')

	// Try to extract context ID from the page.
	// ER1 stores the user ID in various places — try common patterns.
	expressions := []string{
		`localStorage.getItem("user_id")`,
		`localStorage.getItem("context_id")`,
		`document.querySelector('[data-user-id]')?.getAttribute('data-user-id')`,
		`document.querySelector('.user-id')?.textContent`,
	}

	for _, expr := range expressions {
		val, err := plaud.CDPEvaluateOnFirstTab(expr)
		if err == nil && val != "" && val != "null" {
			return strings.Trim(val, "\"")
		}
	}

	// CDP extraction failed — fall back to manual entry.
	fmt.Println("  Could not auto-detect User ID from browser.")
	fmt.Println("  Your User ID is shown at the top of the dashboard after login.")
	fmt.Print("  Enter your User ID: ")
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}

// cmdTranscript fetches a YouTube transcript.
func cmdTranscript(args []string) {
	lang := "en"
	format := "text"
	listOnly := false

	// Simple flag parsing
	var videoID string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--lang":
			if i+1 < len(args) {
				i++
				lang = args[i]
			}
		case "--format":
			if i+1 < len(args) {
				i++
				format = args[i]
			}
		case "--list":
			listOnly = true
		default:
			if videoID == "" {
				videoID = args[i]
			}
		}
	}

	if videoID == "" {
		fmt.Fprintln(os.Stderr, "Usage: m3c-tools transcript [--lang en] [--format text|json|srt|webvtt] [--list] <video_id>")
		os.Exit(1)
	}

	api := transcript.New()

	if listOnly {
		list, err := api.List(videoID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error listing transcripts: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(list)
		return
	}

	fetched, err := api.Fetch(videoID, []string{lang}, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching transcript: %v\n", err)
		os.Exit(1)
	}

	var output string
	switch format {
	case "json":
		output = transcript.JSONFormatter{Pretty: true}.FormatTranscript(fetched)
	case "srt":
		output = transcript.SRTFormatter{}.FormatTranscript(fetched)
	case "webvtt":
		output = transcript.WebVTTFormatter{}.FormatTranscript(fetched)
	default:
		output = transcript.TextFormatter{}.FormatTranscript(fetched)
	}
	fmt.Print(output)
}

// cmdPlaud handles plaud subcommands: auth, list, sync.
func cmdPlaud(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: m3c-tools plaud <auth|list|sync> [args...]")
		os.Exit(1)
	}

	switch args[0] {
	case "auth":
		cmdPlaudAuth(args[1:])
	case "list":
		cmdPlaudList()
	case "sync":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: m3c-tools plaud sync <#|ID|--all> [-f]")
			fmt.Fprintln(os.Stderr, "  -f    Force re-sync: re-download and re-upload (overwrite)")
			os.Exit(1)
		}
		syncArg := args[1]
		force := false
		for _, a := range args[1:] {
			if a == "-f" || a == "--force" {
				force = true
			}
		}
		if syncArg == "-f" || syncArg == "--force" {
			if len(args) < 3 {
				fmt.Fprintln(os.Stderr, "Usage: m3c-tools plaud sync <#|ID|--all> -f")
				os.Exit(1)
			}
			syncArg = args[2]
		}
		if syncArg == "--all" {
			syncArg = "all"
		}
		cmdPlaudSync(syncArg, force)
	default:
		fmt.Fprintf(os.Stderr, "Unknown plaud subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

// cmdPlaudAuth handles token authentication.
func cmdPlaudAuth(args []string) {
	cfg := plaud.LoadConfig()

	if len(args) > 0 && args[0] == "login" {
		// Extract token from Chrome via CDP
		fmt.Println("Extracting token from Chrome...")
		token, err := plaud.ExtractTokenFromChrome()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error extracting token: %v\n", err)
			os.Exit(1)
		}
		session := &plaud.TokenSession{Token: token, SavedAt: time.Now()}
		if err := plaud.SaveToken(cfg.TokenPath, session); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving token: %v\n", err)
			os.Exit(1)
		}
		// Verify the token works
		client := plaud.NewClient(cfg, token)
		recordings, err := client.ListRecordings()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: token saved but verification failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Token saved. Verified: %d recordings found.\n", len(recordings))
		return
	}

	if len(args) > 0 {
		// Direct token
		session := &plaud.TokenSession{Token: args[0], SavedAt: time.Now()}
		if err := plaud.SaveToken(cfg.TokenPath, session); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving token: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Token saved.")
		return
	}

	fmt.Fprintln(os.Stderr, "Usage: m3c-tools plaud auth <login|TOKEN>")
	os.Exit(1)
}

// cmdPlaudList lists all Plaud recordings.
func cmdPlaudList() {
	cfg := plaud.LoadConfig()
	session, err := plaud.LoadToken(cfg.TokenPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading token: %v\nRun: m3c-tools plaud auth login\n", err)
		os.Exit(1)
	}

	client := plaud.NewClient(cfg, session.Token)
	recordings, err := client.ListRecordings()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing recordings: %v\n", err)
		os.Exit(1)
	}

	if len(recordings) == 0 {
		fmt.Println("No recordings found.")
		return
	}

	// Check tracking DB for sync status + ER1 doc IDs.
	dbPath := defaultFilesDBPath()
	filesDB, dbErr := tracking.OpenFilesDB(dbPath)
	if dbErr != nil {
		log.Printf("[plaud] warning: cannot open tracking DB: %v", dbErr)
	}
	defer func() {
		if filesDB != nil {
			filesDB.Close()
		}
	}()

	fmt.Printf("  %3s  %-32s  %-40s  %6s  %s  %-10s  %s\n", "#", "ID", "Title", "Dur", "Date", "Status", "ER1 Doc")
	fmt.Println("  ---  --------------------------------  ----------------------------------------  ------  ----------  ----------  --------")
	for i, r := range recordings {
		id := r.ID
		if len(id) > 32 {
			id = id[:32]
		}
		status := "new"
		docID := ""
		if filesDB != nil {
			if tracked, lookupErr := filesDB.GetByPath("plaud://" + r.ID); lookupErr == nil && tracked != nil {
				status = tracked.Status
				docID = tracked.UploadDocID
			}
		}
		title := r.Title
		if len(title) > 40 {
			title = title[:37] + "..."
		}
		fmt.Printf("  %3d  %-32s  %-40s  %6d  %s  [%-8s]  %s\n", i+1, id, title, r.Duration, r.CreatedAt.Format("2006-01-02"), status, docID)
	}
	fmt.Printf("\nTotal: %d recordings\n", len(recordings))
	fmt.Println("Use: m3c-tools plaud sync <#>   or   m3c-tools plaud sync <ID>")
}

// cmdPlaudSync syncs a recording (or all) to ER1 with detailed statistics (FR-0009),
// two-layer duplicate prevention (FR-0010), and a summary for tray notifications (FR-0011).
func cmdPlaudSync(recordingID string, force bool) {
	cfg := plaud.LoadConfig()
	session, err := plaud.LoadToken(cfg.TokenPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading token: %v\nRun: m3c-tools plaud auth login\n", err)
		os.Exit(1)
	}

	client := plaud.NewClient(cfg, session.Token)

	// Resolve numeric display index (e.g. "33") to real Plaud recording ID.
	if idx, numErr := strconv.Atoi(recordingID); numErr == nil && idx > 0 {
		recordings, listErr := client.ListRecordings()
		if listErr != nil {
			fmt.Fprintf(os.Stderr, "Error listing recordings: %v\n", listErr)
			os.Exit(1)
		}
		if idx > len(recordings) {
			fmt.Fprintf(os.Stderr, "Recording #%d not found (have %d recordings)\n", idx, len(recordings))
			os.Exit(1)
		}
		recordingID = recordings[idx-1].ID
		fmt.Printf("Resolved #%d → %s\n", idx, recordingID)
	}

	if force {
		fmt.Println("Force mode: re-downloading and re-uploading (overwriting existing)")
	}

	dbPath := defaultFilesDBPath()

	stats := plaud.NewSyncStats()

	var ids []string
	if recordingID == "all" {
		recordings, listErr := client.ListRecordings()
		if listErr != nil {
			fmt.Fprintf(os.Stderr, "Error listing recordings: %v\n", listErr)
			os.Exit(1)
		}
		stats.LocalTotal = len(recordings)

		if force {
			// Force: sync ALL, skip dedup
			for _, rec := range recordings {
				ids = append(ids, rec.ID)
			}
			stats.LocalNew = len(ids)
			fmt.Printf("Force syncing all %d recordings...\n", len(ids))
		} else {
			// FR-0010 Layer 1: Local DB dedup check.
			// Items with no ER1 doc_id (upload failed) are retried.
			filesDB, dbErr := tracking.OpenFilesDB(dbPath)
			if dbErr != nil {
				log.Printf("[plaud] warning: cannot open tracking DB: %v", dbErr)
			}
			retryCount := 0
			for _, rec := range recordings {
				if filesDB != nil {
					if tracked, lookupErr := filesDB.GetByPath("plaud://" + rec.ID); lookupErr == nil && tracked != nil {
						if tracked.UploadDocID == "" {
							// Tracked but no doc_id — upload failed, retry
							ids = append(ids, rec.ID)
							retryCount++
							continue
						}
						stats.LocalExisting++
						continue // fully synced, skip
					}
				}
				ids = append(ids, rec.ID)
			}
			if retryCount > 0 {
				fmt.Printf("Retrying %d recordings with missing ER1 doc_id.\n", retryCount)
			}
			if filesDB != nil {
				filesDB.Close()
			}
			stats.LocalNew = len(ids)

			fmt.Printf("Found %d recordings, %d already in local DB.\n", stats.LocalTotal, stats.LocalExisting)

			// FR-0010 Layer 2: Server-side dedup check.
			er1Cfg := er1.LoadConfig()
			if er1Cfg.APIKey != "" && session.Token != "" && len(ids) > 0 {
				syncAPI := plaud.NewSyncAPIClient(er1Cfg.APIURL, er1Cfg.APIKey, er1Cfg.ContextID, !er1Cfg.VerifySSL)
				plaudAccountID := plaud.DeriveAccountID(session.Token)
				checkResult, checkErr := syncAPI.CheckRecordings(plaudAccountID, ids)
				if checkErr == nil && checkResult != nil && len(checkResult.Synced) > 0 {
					stats.AlreadyInER1 = len(checkResult.Synced)
					var filtered []string
					for _, id := range ids {
						if _, alreadySynced := checkResult.Synced[id]; alreadySynced {
							log.Printf("[plaud] [skip] %s already in ER1 (cross-device)", id)
						} else {
							filtered = append(filtered, id)
						}
					}
					ids = filtered
					fmt.Printf("Server check: %d already in ER1 (cross-device dedup).\n", stats.AlreadyInER1)
				}
			}

			if len(ids) == 0 {
				fmt.Println("All recordings already synced.")
				fmt.Print(stats.FormatSummary())
				return
			}
			fmt.Printf("Syncing %d new recordings...\n", len(ids))
		}
	} else {
		ids = []string{recordingID}
		stats.LocalTotal = 1
		stats.LocalNew = 1
	}

	// Run the sync pipeline and get stats back (FR-0011).
	pipelineStats := runPlaudSyncPipeline(client, cfg, ids, dbPath, session.Token, stats)

	// Device pairing + heartbeat (SPEC-0126).
	if pipelineStats.UploadedNew > 0 {
		er1Cfg := er1.LoadConfig()
		pairBaseURL := trayER1BaseURL(er1Cfg.APIURL)
		if pairBaseURL != "" {
			hostname, _ := os.Hostname()
			// Pair Plaud device on first sync.
			_ = er1.PairDevice(context.Background(), pairBaseURL, er1Cfg.APIKey, er1.PairRequest{
				DeviceType:    "plaud",
				DeviceID:      hostname,
				DeviceName:    "Plaud.ai Recorder",
				ClientVersion: version,
			})
			// Heartbeat with sync count.
			if hbErr := er1.DeviceHeartbeat(context.Background(), pairBaseURL, er1Cfg.APIKey, er1.HeartbeatRequest{
				DeviceType:       "plaud",
				DeviceID:         hostname,
				ItemsSyncedDelta: pipelineStats.UploadedNew,
				ClientVersion:    version,
			}); hbErr != nil {
				log.Printf("[device] plaud heartbeat failed (non-fatal): %v", hbErr)
			}
		}
	}

	// Print summary (FR-0009).
	fmt.Print(pipelineStats.FormatSummary())
}

// runPlaudSyncPipeline processes a list of recording IDs through the full
// download -> build -> upload pipeline. It populates the provided SyncStats
// and returns it for use in tray notifications (FR-0011).
func runPlaudSyncPipeline(client *plaud.Client, cfg *plaud.Config, recordingIDs []string, dbPath string, plaudToken string, stats *plaud.SyncStats) *plaud.SyncStats {
	if stats == nil {
		stats = plaud.NewSyncStats()
	}

	filesDB, dbErr := tracking.OpenFilesDB(dbPath)
	if dbErr != nil {
		log.Printf("[plaud] warning: cannot open tracking DB: %v", dbErr)
	}
	defer func() {
		if filesDB != nil {
			filesDB.Close()
		}
	}()

	er1Cfg := er1.LoadConfig()
	er1Cfg.ContentType = cfg.ContentType

	// Set up server-side sync API for mapping registration (SPEC-0117).
	var syncAPI *plaud.SyncAPIClient
	var plaudAccountID string
	if er1Cfg.APIKey != "" && plaudToken != "" {
		syncAPI = plaud.NewSyncAPIClient(er1Cfg.APIURL, er1Cfg.APIKey, er1Cfg.ContextID, !er1Cfg.VerifySSL)
		plaudAccountID = plaud.DeriveAccountID(plaudToken)
	}

	total := len(recordingIDs)
	for i, recID := range recordingIDs {
		prefix := fmt.Sprintf("[%d/%d]", i+1, total)

		// 1. Get recording metadata.
		fmt.Printf("%s %s -> fetching metadata...\n", prefix, recID)
		rec, recErr := client.GetRecording(recID)
		if recErr != nil {
			fmt.Fprintf(os.Stderr, "%s %s -> FAILED (metadata): %v\n", prefix, recID, recErr)
			stats.RecordUploadError(recErr)
			continue
		}
		fmt.Printf("%s %s -> %s (%ds)\n", prefix, recID, rec.Title, rec.Duration)

		// 2. Download audio.
		fmt.Printf("%s %s -> downloading audio...\n", prefix, recID)
		audioData, audioFmt, dlErr := client.DownloadAudio(recID)
		if dlErr != nil {
			fmt.Fprintf(os.Stderr, "%s %s -> FAILED (download): %v\n", prefix, recID, dlErr)
			stats.RecordUploadError(dlErr)
			continue
		}
		fmt.Printf("%s %s -> downloaded %d KB\n", prefix, recID, len(audioData)/1024)

		// 3. Get transcript.
		var transcriptText string
		tx, txErr := client.GetTranscript(recID)
		if txErr != nil {
			fmt.Printf("%s %s -> transcript not available (audio only)\n", prefix, recID)
			transcriptText = "[No transcript available — audio only]"
		} else {
			transcriptText = tx.Text
			if tx.Summary != "" {
				transcriptText = transcriptText + "\n\n=== SUMMARY ===\n" + tx.Summary
			}
			fmt.Printf("%s %s -> transcript OK (%d chars)\n", prefix, recID, len(transcriptText))
		}

		// 4. Build composite document.
		now := time.Now()
		doc := (&impression.CompositeDoc{
			ObsType:           impression.Fieldnote,
			Timestamp:         now,
			RecordingTitle:    rec.Title,
			RecordingDuration: plaud.FormatDuration(rec.Duration),
			TranscriptText:    strings.TrimSpace(transcriptText),
		}).Build()

		tags := impression.BuildFieldnoteTags(rec.Title)
		if cfg.DefaultTags != "" {
			tags = cfg.DefaultTags + "," + tags
		}

		// 5. Upload to ER1.
		fmt.Printf("%s %s -> uploading to ER1...\n", prefix, recID)

		payload := &er1.UploadPayload{
			TranscriptData:     []byte(strings.TrimSpace(doc) + "\n"),
			TranscriptFilename: fmt.Sprintf("fieldnote_%s.txt", now.Format("20060102_150405")),
			AudioData:          audioData,
			AudioFilename:      fmt.Sprintf("plaud_%s.%s", recID, audioFmt),
			ImageData:          er1.PlaudLogoPNG(),
			ImageFilename:      "plaud-logo.png",
			Tags:               tags,
			ContentType:        cfg.ContentType,
		}

		resp, upErr := er1.Upload(er1Cfg, payload)
		if upErr != nil {
			fmt.Fprintf(os.Stderr, "%s %s -> upload FAILED: %v\n", prefix, recID, upErr)
			// Save locally as fallback.
			localErr := savePlaudLocally(recID, rec, audioData, audioFmt, doc, transcriptText, tags)
			if localErr != nil {
				fmt.Fprintf(os.Stderr, "%s %s -> local save also FAILED: %v\n", prefix, recID, localErr)
				stats.RecordUploadError(upErr)
				continue
			}
			fmt.Printf("%s %s -> saved locally to ~/plaud-sync/%s/\n", prefix, recID, recID[:min(8, len(recID))])
			// Track as locally saved.
			if filesDB != nil {
				audioHash := fmt.Sprintf("%x", sha256.Sum256(audioData))
				_, _ = filesDB.RecordFile("plaud://"+recID, audioHash, int64(len(audioData)), "plaud", "")
				_ = filesDB.RecordTranscript(audioHash, "plaud", strings.TrimSpace(transcriptText), "")
			}
			stats.SavedLocally++
			continue
		}

		fmt.Printf("%s %s -> uploaded OK (doc_id: %s)\n", prefix, recID, resp.DocID)

		// 6. Record in tracking DB.
		if filesDB != nil {
			audioHash := fmt.Sprintf("%x", sha256.Sum256(audioData))
			_, _ = filesDB.RecordFile("plaud://"+recID, audioHash, int64(len(audioData)), "plaud", "")
			_ = filesDB.RecordTranscript(audioHash, "plaud", strings.TrimSpace(transcriptText), "")
			_ = filesDB.RecordUploadSuccess(audioHash, "plaud", resp.DocID)
		}

		// 7. Register mapping on server (SPEC-0117).
		if syncAPI != nil {
			mapErr := syncAPI.RegisterMapping(plaud.SyncMapping{
				PlaudAccountID:    plaudAccountID,
				PlaudRecordingID:  recID,
				ER1DocID:          resp.DocID,
				ER1ContextID:      er1Cfg.ContextID,
				RecordingTitle:    rec.Title,
				RecordingDuration: rec.Duration,
				AudioFormat:       audioFmt,
				AudioSizeBytes:    len(audioData),
				TranscriptLength:  len(transcriptText),
			})
			if mapErr != nil {
				log.Printf("[plaud] server mapping failed (non-fatal): %v", mapErr)
			}
		}

		stats.UploadedNew++
	}

	return stats
}

// savePlaudLocally saves recording data to ~/plaud-sync/<recID>/ for later re-upload.
func savePlaudLocally(recID string, rec *plaud.Recording, audioData []byte, audioFmt, compositeDoc, transcriptText, tags string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("get home dir: %w", err)
	}
	dir := filepath.Join(home, "plaud-sync", recID)
	if err := os.MkdirAll(dir, 0700); err != nil { // FIX-17: restrictive perms for user data
		return fmt.Errorf("create dir: %w", err)
	}

	if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("audio.%s", audioFmt)), audioData, 0600); err != nil {
		return fmt.Errorf("write audio: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fieldnote.txt"), []byte(compositeDoc), 0600); err != nil {
		return fmt.Errorf("write doc: %w", err)
	}
	if transcriptText != "" {
		if err := os.WriteFile(filepath.Join(dir, "transcript.txt"), []byte(transcriptText), 0600); err != nil {
			return fmt.Errorf("write transcript: %w", err)
		}
	}

	meta := map[string]interface{}{
		"recording_id": recID,
		"title":        rec.Title,
		"duration":     rec.Duration,
		"created_at":   rec.CreatedAt.Format(time.RFC3339),
		"synced_at":    time.Now().Format(time.RFC3339),
		"tags":         tags,
		"audio_format": audioFmt,
		"audio_size":   len(audioData),
	}
	metaJSON, _ := json.MarshalIndent(meta, "", "  ")
	return os.WriteFile(filepath.Join(dir, "metadata.json"), metaJSON, 0600)
}

func defaultFilesDBPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "m3c-tools-files.db")
	}
	return filepath.Join(home, ".m3c-tools", "files.db")
}

// cmdCheckER1 checks ER1 server connectivity.
func cmdCheckER1() {
	cfg := er1.LoadConfig()
	fmt.Println(cfg.Summary())
	if er1.IsReachable(cfg) {
		fmt.Println("ER1 server: REACHABLE")
	} else {
		fmt.Println("ER1 server: UNREACHABLE")
		os.Exit(1)
	}
}

// cmdLogin runs the CLI login flow: starts a local callback server,
// opens the browser to /v2/signin, waits for the callback with context_id
// and device token. Same flow as the tray menubar login but for headless CLI use.
func cmdLogin() {
	cfg := er1.LoadConfig()
	baseURL := trayER1BaseURL(cfg.APIURL)
	if baseURL == "" {
		fmt.Fprintln(os.Stderr, "Error: cannot derive ER1 base URL from ER1_API_URL")
		fmt.Fprintln(os.Stderr, "Run 'm3c-tools setup' first or set ER1_API_URL in your profile.")
		os.Exit(1)
	}

	// Start local callback server on a random port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: could not start callback server: %v\n", err)
		os.Exit(1)
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		ln.Close()
		fmt.Fprintf(os.Stderr, "Error: could not generate callback nonce: %v\n", err)
		os.Exit(1)
	}
	callbackPath := "/m3c-login-" + hex.EncodeToString(nonce)
	addr := ln.Addr().String()
	callbackURL := "http://" + addr + callbackPath

	type loginResult struct {
		ContextID   string
		DeviceToken string
		UserID      string
		UserName    string
		UserEmail   string
		Err         error
	}
	resultCh := make(chan loginResult, 1)

	mux := http.NewServeMux()
	mux.HandleFunc(callbackPath, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		ctxID := strings.TrimSpace(q.Get("context_id"))
		if ctxID == "" {
			ctxID = strings.TrimSpace(q.Get("user_id"))
		}
		if ctxID == "" {
			ctxID = strings.TrimSpace(q.Get("uid"))
		}
		select {
		case resultCh <- loginResult{
			ContextID:   ctxID,
			DeviceToken: strings.TrimSpace(q.Get("device_token")),
			UserID:      strings.TrimSpace(q.Get("user_id")),
			UserName:    strings.TrimSpace(q.Get("user_name")),
			UserEmail:   strings.TrimSpace(q.Get("user_email")),
		}:
		default:
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><title>Login Successful</title>
<style>body{font-family:system-ui;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#1a1a2e;color:#fff}
.card{text-align:center;padding:2rem;border-radius:12px;background:#16213e;box-shadow:0 4px 20px rgba(0,0,0,0.3)}
h2{color:#7c3aed}p{color:#94a3b8}</style></head>
<body><div class="card"><h2>&#10003; Device Connected</h2>
<p>m3c-tools is now linked to your account.</p>
<p>You can close this tab and return to the terminal.</p></div></body></html>`)
	})

	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		if serveErr := srv.Serve(ln); serveErr != nil && serveErr != http.ErrServerClosed {
			log.Printf("[auth] callback server error: %v", serveErr)
			select {
			case resultCh <- loginResult{Err: serveErr}:
			default:
			}
		}
	}()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	loginURL := fmt.Sprintf("%s/v2/signin?next=%s", baseURL, neturl.QueryEscape(callbackURL))
	fmt.Printf("Opening browser for login...\n")
	fmt.Printf("If the browser does not open, visit:\n  %s\n\n", loginURL)
	openBrowserURL(loginURL)
	fmt.Println("Waiting for login (5 min timeout)...")

	deadline := time.NewTimer(5 * time.Minute)
	defer deadline.Stop()

	for {
		select {
		case result := <-resultCh:
			if result.Err != nil {
				fmt.Fprintf(os.Stderr, "Login error: %v\n", result.Err)
				os.Exit(1)
			}
			ctxID := strings.TrimSpace(result.ContextID)
			if ctxID == "" {
				continue
			}

			// Persist context_id to the active profile.
			pm := config.NewProfileManager()
			active := pm.ActiveProfileName()
			if active != "" {
				if profile, pErr := pm.GetProfile(active); pErr == nil {
					profile.Vars["ER1_CONTEXT_ID"] = ctxID
					if saveErr := pm.CreateProfile(active, profile.Description, profile.Vars); saveErr != nil {
						log.Printf("[auth] failed to persist context_id to profile %s: %v", active, saveErr)
					} else {
						fmt.Printf("Context ID saved to profile %q.\n", active)
					}
				}
			}
			os.Setenv("ER1_CONTEXT_ID", ctxID)

			// Save device token if received from aims-core callback (SPEC-0127).
			if result.DeviceToken != "" {
				dt := &auth.DeviceToken{
					Token:     result.DeviceToken,
					UserID:    result.UserID,
					ContextID: ctxID,
					UserName:  result.UserName,
					UserEmail: result.UserEmail,
					DeviceID:  auth.DeviceID(),
					SavedAt:   time.Now().UTC().Format(time.RFC3339),
				}
				if err := auth.Save(dt); err != nil {
					log.Printf("[auth] save device token failed: %v", err)
				} else {
					os.Setenv("ER1_DEVICE_TOKEN", result.DeviceToken)
					fmt.Printf("Device token saved for user=%s device=%s\n", truncateForLog(result.UserID, 20), auth.DeviceID())
				}
			}

			// Auto-pair desktop device (SPEC-0126).
			go func() {
				pairBaseURL := trayER1BaseURL(cfg.APIURL)
				if pairBaseURL == "" {
					return
				}
				hostname, _ := os.Hostname()
				if pairErr := er1.PairDevice(context.Background(), pairBaseURL, cfg.APIKey, er1.PairRequest{
					DeviceType:    "m3c-desktop",
					DeviceID:      hostname,
					DeviceName:    hostname + " (m3c-tools)",
					ClientVersion: version,
				}); pairErr != nil {
					log.Printf("[device] auto-pair failed (non-fatal): %v", pairErr)
				} else {
					log.Printf("[device] desktop paired: %s", hostname)
				}
			}()

			fmt.Printf("\nLogin successful! Context: %s\n", ctxID)
			return

		case <-deadline.C:
			fmt.Fprintln(os.Stderr, "Login timed out (5 minutes). Please try again.")
			os.Exit(1)
		}
	}
}

// truncateForLog truncates a string for safe log output, preventing
// excessively long values from flooding logs.
func truncateForLog(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func printUsage() {
	fmt.Println(`m3c-tools — Multi-Modal-Memory Tools (CLI mode)

Available commands (cross-platform):
  setup                  Interactive ER1 onboarding wizard
    --er1-url <url>       ER1 upload endpoint (default: onboarding.guide)
    --tags <tags>         Default tags for plaud sync
    --no-browser          Skip browser login, enter User ID manually
  config list|show|switch|create|test|import
                         Configuration profile management
  transcript <video_id>  Fetch YouTube transcript
    --lang <code>         Language code (default: en)
    --format <fmt>        Output format: text, json, srt, webvtt (default: text)
    --list                List available transcripts
  plaud list|sync|auth   Plaud recording sync
    auth login            Extract token from Chrome (CDP)
    auth <token>          Set token directly
    list                  List all recordings
    sync <id>             Download + upload to ER1
    sync all              Sync all unsynced recordings
  login                  Sign in to ER1 via browser (device token auth)
  doctor                 Run connectivity & config diagnostics
  check-er1              Check ER1 server connectivity (use 'doctor' for full check)
  help                   Show this help

Cross-platform commands:
  menubar                Launch system tray app

macOS-only commands (not available on this platform):
  record                 Record audio
  devices                List audio devices
  screenshot             Capture screenshot
  upload                 Upload to ER1 with media`)
}

func openURL(url string) error {
	return plaud.OpenBrowser(url)
}

func cmdExec(name string, args ...string) *exec.Cmd {
	return exec.Command(name, args...)
}


// plaudChromeActive prevents concurrent Chrome launches for Plaud auth.
// BUG-0102: Without this guard, ActionPlaudAuth and ActionPlaudSync can both
// call trayExtractPlaudToken simultaneously, launching two debug Chrome windows.
// 0 = idle, 1 = Chrome running for Plaud auth.
var plaudChromeActive int32

// trayExtractPlaudToken attempts to extract a Plaud token from Chrome via CDP.
// This is the tray-friendly version that never blocks on stdin:
//   1. First tries ExtractTokenCDP() — instant, works if Chrome is already
//      running with plaud.ai open and --remote-debugging-port=9222.
//   2. If that fails, launches Chrome with the debug port, opens plaud.ai,
//      and polls for the token every 3 seconds for 60 seconds while the user
//      logs in. Tooltip is updated with a countdown.
//
// Happy Maker 1: Eliminates the terminal requirement for Plaud authentication.
func trayExtractPlaudToken(app *tray.TrayApp) (string, error) {
	// BUG-0102: Guard against concurrent Chrome launches from ActionPlaudAuth
	// and ActionPlaudSync both calling this function simultaneously.
	if !atomic.CompareAndSwapInt32(&plaudChromeActive, 0, 1) {
		log.Println("[plaud-tray-auth] Chrome auth already in progress, skipping duplicate launch")
		return "", fmt.Errorf("Plaud Chrome auth already in progress — please wait")
	}
	defer atomic.StoreInt32(&plaudChromeActive, 0)

	// Step 1: Try instant CDP extraction (Chrome already running with plaud.ai).
	log.Println("[plaud-tray-auth] trying instant CDP extraction...")
	token, err := plaud.ExtractTokenCDP()
	if err == nil {
		log.Println("[plaud-tray-auth] instant CDP extraction succeeded")
		return token, nil
	}
	log.Printf("[plaud-tray-auth] instant CDP failed: %v — launching Chrome...", err)

	// Step 2: Launch Chrome with debug port + plaud.ai.
	app.UpdateTooltip("M3C Tools — Launching Chrome for Plaud login...")
	cleanup, launchErr := plaud.LaunchChromeForPlaud()
	if launchErr != nil {
		return "", fmt.Errorf("cannot launch Chrome: %w", launchErr)
	}
	defer cleanup()

	// Step 3: Wait for CDP to become ready (Chrome startup takes a few seconds).
	cdpReady := plaud.WaitForCDPReady(30*time.Second, func(msg string) {
		app.UpdateTooltip("M3C Tools — " + msg)
	})
	if !cdpReady {
		return "", fmt.Errorf("Chrome started but CDP port 9222 is not responding")
	}

	// Step 4: Poll for token while user logs in (60s timeout, 3s interval).
	log.Println("[plaud-tray-auth] CDP ready, polling for Plaud token...")
	token, pollErr := plaud.PollForPlaudToken(60*time.Second, 3*time.Second, func(msg string) {
		app.UpdateTooltip("M3C Tools — " + msg)
	})
	if pollErr != nil {
		return "", pollErr
	}

	log.Printf("[plaud-tray-auth] token extracted (%d chars)", len(token))
	return token, nil
}

// trayPlaudSync runs Plaud sync in a tray-safe manner. Unlike cmdPlaudSync,
// it never calls os.Exit and returns structured results for user feedback.
// BUG-0092: This replaces the direct cmdPlaudSync("all") call that would
// silently kill the tray app on any error (token missing, network failure, etc).
// FR-0011: Returns *plaud.SyncStats for detailed tray notification formatting.
func trayPlaudSync(app *tray.TrayApp) (*plaud.SyncStats, error) {
	cfg := plaud.LoadConfig()
	session, loadErr := plaud.LoadToken(cfg.TokenPath)
	if loadErr != nil {
		// Happy Maker 1: Auto-auth via CDP instead of failing with "use terminal".
		log.Printf("[plaud-tray] no saved token, attempting CDP auto-auth: %v", loadErr)
		app.UpdateTooltip("M3C Tools — No Plaud token, attempting Chrome auto-auth...")

		token, authErr := trayExtractPlaudToken(app)
		if authErr != nil {
			return nil, fmt.Errorf("Plaud auto-auth failed: %w — open web.plaud.ai in Chrome, log in, then try again", authErr)
		}

		// Save the extracted token for future use.
		session = &plaud.TokenSession{Token: token, SavedAt: time.Now()}
		if saveErr := plaud.SaveToken(cfg.TokenPath, session); saveErr != nil {
			log.Printf("[plaud-tray] warning: token extracted but save failed: %v", saveErr)
		} else {
			log.Println("[plaud-tray] token extracted and saved via CDP auto-auth")
		}
		app.UpdateTooltip("M3C Tools — Plaud authenticated, syncing...")
	}

	client := plaud.NewClient(cfg, session.Token)
	dbPath := defaultFilesDBPath()

	stats := plaud.NewSyncStats()

	recordings, listErr := client.ListRecordings()
	if listErr != nil {
		return nil, fmt.Errorf("cannot list recordings: %w", listErr)
	}
	stats.LocalTotal = len(recordings)

	// FR-0010 Layer 1: Local DB dedup check (runs FIRST).
	filesDB, dbErr := tracking.OpenFilesDB(dbPath)
	if dbErr != nil {
		log.Printf("[plaud] warning: cannot open tracking DB: %v", dbErr)
	}

	var ids []string
	for _, rec := range recordings {
		skip := false
		if filesDB != nil {
			if tracked, lookupErr := filesDB.GetByPath("plaud://" + rec.ID); lookupErr == nil && tracked != nil {
				skip = true
				stats.LocalExisting++
			}
		}
		if !skip {
			ids = append(ids, rec.ID)
		}
	}
	if filesDB != nil {
		filesDB.Close()
	}
	stats.LocalNew = len(ids)

	log.Printf("[plaud-tray] found %d recordings, %d already in local DB", stats.LocalTotal, stats.LocalExisting)

	// FR-0010 Layer 2: Server-side dedup check (runs SECOND, catches cross-device dupes).
	er1Cfg := er1.LoadConfig()
	if er1Cfg.APIKey != "" && session.Token != "" && len(ids) > 0 {
		syncAPI := plaud.NewSyncAPIClient(er1Cfg.APIURL, er1Cfg.APIKey, er1Cfg.ContextID, !er1Cfg.VerifySSL)
		plaudAccountID := plaud.DeriveAccountID(session.Token)
		checkResult, checkErr := syncAPI.CheckRecordings(plaudAccountID, ids)
		if checkErr == nil && checkResult != nil && len(checkResult.Synced) > 0 {
			stats.AlreadyInER1 = len(checkResult.Synced)
			var filtered []string
			for _, id := range ids {
				if _, alreadySynced := checkResult.Synced[id]; alreadySynced {
					log.Printf("[plaud-tray] [skip] %s already in ER1 (cross-device)", id)
				} else {
					filtered = append(filtered, id)
				}
			}
			ids = filtered
			log.Printf("[plaud-tray] server check: %d already in ER1", stats.AlreadyInER1)
		}
	}

	if len(ids) == 0 {
		return stats, nil // all synced, no error
	}

	// Run the shared pipeline (FR-0009/FR-0011).
	stats = runPlaudSyncPipeline(client, cfg, ids, dbPath, session.Token, stats)

	return stats, nil
}

// checkFirstRun inspects the setup state and returns actionable guidance.
// It checks config profiles, API key, Plaud token, and ER1 URL to detect
// whether the user needs to complete initial setup before features will work.
func checkFirstRun() []tray.SetupIssue {
	var issues []tray.SetupIssue
	home, err := os.UserHomeDir()
	if err != nil {
		issues = append(issues, tray.SetupIssue{
			Key: "no_home", Message: "Cannot detect home directory",
		})
		return issues
	}

	// 1. Check if profiles directory exists and has at least one profile.
	profileDir := filepath.Join(home, ".m3c-tools", "profiles")
	entries, statErr := os.ReadDir(profileDir)
	if statErr != nil || len(entries) == 0 {
		issues = append(issues, tray.SetupIssue{
			Key: "no_profiles", Message: "No configuration profiles found",
		})
	}

	// 2. Check if ER1 API key is configured (either from env or active profile).
	apiKey := os.Getenv("ER1_API_KEY")
	if apiKey == "" {
		// Also peek at the active profile's vars in case it was set there
		// but not yet applied to env (e.g., first launch after profile edit).
		pm := config.NewProfileManager()
		if ap, apErr := pm.ActiveProfile(); apErr == nil {
			apiKey = ap.Vars["ER1_API_KEY"]
		}
	}
	// SPEC-0127: device token replaces API key — only warn if neither exists.
	deviceTokenPath := filepath.Join(home, ".m3c-tools", "device-token.enc")
	hasDeviceToken := false
	if _, dtErr := os.Stat(deviceTokenPath); dtErr == nil {
		hasDeviceToken = true
	}
	if apiKey == "" && !hasDeviceToken {
		issues = append(issues, tray.SetupIssue{
			Key: "no_auth", Message: "Not authenticated — run 'm3c-tools login'",
		})
	}

	// 3. Check if Plaud session token exists.
	tokenPath := filepath.Join(home, ".m3c-tools", "plaud-session.json")
	if _, tokenErr := os.Stat(tokenPath); os.IsNotExist(tokenErr) {
		issues = append(issues, tray.SetupIssue{
			Key: "no_plaud_token", Message: "Plaud account not connected",
		})
	}

	// 4. Check if ER1 API URL looks intentionally configured (not just the
	// localhost default that ships with the dev profile template).
	apiURL := os.Getenv("ER1_API_URL")
	if apiURL == "" {
		pm := config.NewProfileManager()
		if ap, apErr := pm.ActiveProfile(); apErr == nil {
			apiURL = ap.Vars["ER1_API_URL"]
		}
	}
	if apiURL == "" {
		issues = append(issues, tray.SetupIssue{
			Key: "no_api_url", Message: "ER1 server URL not configured",
		})
	}

	return issues
}

// cmdTrayApp launches the cross-platform system tray app using fyne.io/systray.
// This mirrors the macOS cmdMenubar function from main.go with the handlers
// that work cross-platform (profiles, transcript fetch, plaud/pocket sync, log).
func cmdTrayApp(args []string) {
	home, _ := os.UserHomeDir()
	logPath := filepath.Join(home, ".m3c-tools", "m3c-tools.log")
	verbose := true

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--log":
			if i+1 < len(args) {
				logPath = args[i+1]
				i++
			}
		case "--verbose":
			verbose = true
		case "--quiet":
			verbose = false
		default:
			if strings.HasPrefix(args[i], "--") {
				fmt.Fprintf(os.Stderr, "Warning: unknown flag %q (ignored)\n", args[i])
			}
		}
	}

	// Set up log file.
	if logDir := filepath.Dir(logPath); logDir != "" && logDir != "." {
		os.MkdirAll(logDir, 0700)
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: cannot open log file %s: %v\n", logPath, err)
	} else {
		if verbose {
			log.SetOutput(io.MultiWriter(logFile, os.Stderr))
		} else {
			log.SetOutput(logFile)
		}
		log.SetFlags(log.Ldate | log.Ltime)
	}
	fmt.Fprintf(os.Stderr, "m3c-tools tray started. Logs: %s\n", logPath)

	// Auto-configure from ~/m3c-tools.init.cfg if present (zero-touch onboarding).
	initResult := config.CheckAndApplyInitCfg()
	if initResult.Found && initResult.Imported {
		log.Printf("[config] auto-configured from init file: profile=%s", initResult.ProfileName)
		fmt.Fprintf(os.Stderr, "Auto-configured from init file (profile: %s)\n", initResult.ProfileName)
	} else if initResult.Found && initResult.Error != nil {
		log.Printf("[config] init config found but failed: %v", initResult.Error)
	}

	// BUG-0092: Declare app before constructing so the OnAction closure can
	// capture it for tooltip feedback. Safe because clicks only fire after Run().
	var app *tray.TrayApp

	app = tray.New(tray.TrayHandlers{
		OnAction: func(action tray.ActionType, data string) {
			log.Printf("[tray] action: %s data=%q", action, data)
			switch action {
			// Windows MVP: only PlaudSync, SignIn, SignOut, Quit actions.
			case tray.ActionPlaudSync:
				// First-run guard: give specific guidance instead of a cryptic error.
				if !app.IsSetupComplete() {
					for _, issue := range app.SetupIssues {
						if issue.Key == "no_auth" || issue.Key == "no_api_key" {
							app.Notify("Setup Required", "ER1 API key missing — open Settings in tray menu")
							return
						}
						if issue.Key == "no_plaud_token" {
							app.Notify("Setup Required", "Plaud not connected — open Settings in tray menu")
							return
						}
					}
					app.Notify("Setup Required", "Configuration incomplete — open Settings in tray menu")
					return
				}
				// BUG-0092: Use tray-safe sync with feedback instead of
				// cmdPlaudSync which calls os.Exit on errors, killing the tray.
				if !app.ClaimPlaudSync() {
					log.Println("[tray] plaud sync already running, ignoring click")
					app.UpdateTooltip("M3C Tools — Plaud sync already running...")
					return
				}
				// Tooltip for immediate in-progress feedback (no notification spam).
				app.UpdateTooltip("M3C Tools — Syncing Plaud recordings...")
				log.Println("[tray] starting plaud sync (tray-safe)...")
				go func() {
					defer app.ReleasePlaudSync()
					// FR-0011: trayPlaudSync returns *plaud.SyncStats for detailed notification.
					stats, err := trayPlaudSync(app)
					if err != nil {
						log.Printf("[tray] plaud sync error: %v", err)
						errMsg := err.Error()
						// Detect auth/token issues and show setup guidance.
						if strings.Contains(errMsg, "no Plaud token") {
							app.Notify("Plaud Setup Required", "Please open web.plaud.ai in Chrome and log in")
						} else {
							app.Notify("Plaud Sync Failed", errMsg)
						}
						app.UpdateTooltip(fmt.Sprintf("M3C Tools — Plaud sync failed: %v", err))
						go func() {
							time.Sleep(10 * time.Second)
							app.ResetTooltip()
						}()
						return
					}
					// Use the stats notification formatter for compact feedback.
					notification := stats.FormatNotification()
					log.Printf("[tray] plaud sync done: %s", notification)
					// Native OS notification for completion (visible even if tray is hidden).
					app.Notify("Plaud Sync Complete", notification)
					app.UpdateTooltip("M3C Tools — " + notification)
					// Reset tooltip after 10 seconds.
					go func() {
						time.Sleep(10 * time.Second)
						app.ResetTooltip()
					}()
				}()
			case tray.ActionPlaudAuth:
				// Login to Plaud.ai via Chrome CDP
				log.Println("[tray] Login Plaud.ai clicked — starting CDP auth...")
				app.UpdateTooltip("M3C Tools — Connecting to Plaud via Chrome...")
				go func() {
					token, authErr := trayExtractPlaudToken(app)
					if authErr != nil {
						log.Printf("[tray] Plaud auth failed: %v", authErr)
						app.Notify("Plaud Auth Failed", "Open web.plaud.ai in Chrome, log in, then try again")
						app.UpdatePlaudStatus(false, "auth failed")
						app.UpdateTooltip(fmt.Sprintf("M3C Tools — Plaud auth failed"))
						go func() {
							time.Sleep(10 * time.Second)
							app.ResetTooltip()
						}()
						return
					}
					cfg := plaud.LoadConfig()
					session := &plaud.TokenSession{Token: token, SavedAt: time.Now()}
					if saveErr := plaud.SaveToken(cfg.TokenPath, session); saveErr != nil {
						log.Printf("[tray] token save failed: %v", saveErr)
						app.Notify("Plaud Auth", "Token extracted but could not save")
					} else {
						log.Println("[tray] Plaud token saved")
						app.Notify("Plaud Connected", "Token saved — you can now sync")
						app.UpdatePlaudStatus(true, "token OK")
					}
					app.UpdateTooltip("M3C Tools — Plaud connected")
					go func() {
						time.Sleep(10 * time.Second)
						app.ResetTooltip()
					}()
				}()
			case tray.ActionEditConfig:
				// Open the profile settings editor
				log.Println("[tray] Edit Configuration clicked")
				go func() {
					srv := config.NewEditorServer(":9116")
					if err := srv.Start(); err != nil {
						log.Printf("[config] editor error: %v", err)
					}
				}()
			case tray.ActionSignIn:
				// BUG-0088 fix: Use proper ER1 callback flow (same as macOS).
				go trayLoginER1(app)
			case tray.ActionSignOut:
				// FEAT-0014: Sign out — clear runtime state.
				log.Println("[tray] sign out")
				os.Setenv("ER1_CONTEXT_ID", "")
				app.UpdateLoginState(false, "")
				app.UpdateTooltip("M3C Tools — Signed out")
				go func() {
					time.Sleep(5 * time.Second)
					app.ResetTooltip()
				}()
			case tray.ActionQuit:
				log.Println("[tray] quit requested")
				os.Exit(0)
			}
		},
		// Windows MVP: Plaud sync only — no profile/history/preferences handlers.
	})

	app.SetLogPath(logPath)

	// First-run detection: check setup state before launching the tray.
	// This populates SetupIssues which onReady() uses to show the setup
	// banner, tooltip, and deferred notification.
	setupIssues := checkFirstRun()
	if len(setupIssues) > 0 {
		log.Printf("[setup] first-run detection: %d issue(s) found", len(setupIssues))
		for _, issue := range setupIssues {
			log.Printf("[setup]   - %s: %s", issue.Key, issue.Message)
		}
		app.SetSetupIssues(setupIssues)
	} else {
		log.Println("[setup] first-run check passed — setup is complete")
	}

	// Check Plaud token status on startup
	plaudCfg := plaud.LoadConfig()
	if session, err := plaud.LoadToken(plaudCfg.TokenPath); err == nil && session != nil {
		if session.IsExpired(plaud.DefaultMaxTokenAge) {
			app.UpdatePlaudStatus(false, "token expired")
		} else {
			app.UpdatePlaudStatus(true, "token OK")
		}
	}

	// systray.Run() blocks — this must be the last call.
	app.Run()
}

// openFileWithDefault opens a file with the system default application.
// BUG-0091: Ensures log file viewer works on all platforms.
func openFileWithDefault(path string) {
	if path == "" {
		log.Printf("[tray] openFileWithDefault called with empty path")
		return
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", "", path)
	case "linux":
		cmd = exec.Command("xdg-open", path)
	default:
		cmd = exec.Command("open", path)
	}
	if err := cmd.Start(); err != nil {
		log.Printf("[tray] failed to open file %s: %v", path, err)
	}
}

// openBrowserURL opens a URL in the platform default browser.
// BUG-0088: Windows uses "cmd /c start" instead of rundll32 which silently fails.
func openBrowserURL(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		// Empty title arg ("") prevents cmd from misinterpreting URLs with & as title.
		cmd = exec.Command("cmd", "/c", "start", "", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	default:
		cmd = exec.Command("open", url)
	}
	if err := cmd.Start(); err != nil {
		log.Printf("[tray] failed to open browser for %s: %v", url, err)
	}
}

// --- ER1 Login Flow (BUG-0088, BUG-0096, BUG-0098 fix) ---

// trayLoginER1 runs the full ER1 login flow: starts a local callback server,
// opens the browser to /v2/signin, waits for the callback with context_id.
// Same flow as macOS menubarLoginER1 in main.go.
func trayLoginER1(app *tray.TrayApp) {
	cfg := er1.LoadConfig()
	baseURL := trayER1BaseURL(cfg.APIURL)
	if baseURL == "" {
		log.Println("[auth] cannot derive ER1 base URL from ER1_API_URL")
		app.UpdateTooltip("M3C Tools — Login failed (no ER1 URL)")
		return
	}

	// Start local callback server on a random port.
	srv, callbackURL, resultCh, closeFn, err := startTrayLoginCallbackServer()
	if err != nil {
		log.Printf("[auth] login callback server start failed: %v", err)
		app.UpdateTooltip("M3C Tools — Login failed (callback)")
		return
	}
	defer func() {
		// Keep callback server alive for 30s so browser redirect can complete.
		go func() {
			time.Sleep(30 * time.Second)
			closeFn()
			log.Printf("[auth] callback server closed (30s grace period)")
		}()
	}()
	_ = srv

	loginURL := fmt.Sprintf("%s/v2/signin?next=%s", baseURL, neturl.QueryEscape(callbackURL))
	log.Printf("[auth] login start base=%s callback=%s", baseURL, callbackURL)
	openBrowserURL(loginURL)
	app.UpdateTooltip("M3C Tools — Waiting for login...")

	// BUG-0096: 5-minute timeout (Google OAuth + Passkey can take time).
	deadline := time.NewTimer(5 * time.Minute)
	defer deadline.Stop()

	for {
		select {
		case result := <-resultCh:
			if result.Err != nil {
				log.Printf("[auth] callback received error: %v", result.Err)
				app.UpdateTooltip("M3C Tools — Login failed")
				return
			}
			ctxID := strings.TrimSpace(result.ContextID)
			if ctxID == "" {
				log.Printf("[auth] callback received but no context_id")
				continue
			}
			completeTrayLogin(app, ctxID)
			return
		case <-deadline.C:
			log.Printf("[auth] login timed out (5m) waiting for callback; addr=%s", srv.Addr)
			app.UpdateTooltip("M3C Tools — Login timed out")
			go func() {
				time.Sleep(10 * time.Second)
				app.ResetTooltip()
			}()
			return
		}
	}
}

// completeTrayLogin finalizes a successful login.
func completeTrayLogin(app *tray.TrayApp, contextID string) {
	log.Printf("[auth] login success context_id=%s", contextID)

	// Persist context_id to the active profile.
	pm := config.NewProfileManager()
	active := pm.ActiveProfileName()
	if active != "" {
		if profile, err := pm.GetProfile(active); err == nil {
			profile.Vars["ER1_CONTEXT_ID"] = contextID
			if saveErr := pm.CreateProfile(active, profile.Description, profile.Vars); saveErr != nil {
				log.Printf("[auth] failed to persist context_id to profile %s: %v", active, saveErr)
			} else {
				log.Printf("[auth] context_id saved to profile %s", active)
			}
		}
	}

	// Update runtime state and menu.
	os.Setenv("ER1_CONTEXT_ID", contextID)
	app.UpdateLoginState(true, contextID)
	app.UpdateTooltip(fmt.Sprintf("M3C Tools — Signed in (%s...)", contextID[:min(8, len(contextID))]))
	go func() {
		time.Sleep(15 * time.Second)
		app.ResetTooltip()
	}()

	// Auto-pair desktop device (SPEC-0126).
	go func() {
		cfg := er1.LoadConfig()
		pairBaseURL := trayER1BaseURL(cfg.APIURL)
		if pairBaseURL == "" {
			return
		}
		hostname, _ := os.Hostname()
		if pairErr := er1.PairDevice(context.Background(), pairBaseURL, cfg.APIKey, er1.PairRequest{
			DeviceType:    "m3c-desktop",
			DeviceID:      hostname,
			DeviceName:    hostname + " (m3c-tools)",
			ClientVersion: version,
		}); pairErr != nil {
			log.Printf("[device] auto-pair failed (non-fatal): %v", pairErr)
		} else {
			log.Printf("[device] desktop paired: %s", hostname)
		}
	}()
}

type trayLoginResult struct {
	ContextID string
	Err       error
}

// startTrayLoginCallbackServer creates a local HTTP server that waits for
// the OAuth redirect with context_id. Same pattern as macOS startER1LoginCallbackServer.
func startTrayLoginCallbackServer() (*http.Server, string, <-chan trayLoginResult, func(), error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", nil, nil, err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		ln.Close()
		return nil, "", nil, nil, fmt.Errorf("generate callback nonce: %w", err)
	}
	callbackPath := "/m3c-login-" + hex.EncodeToString(nonce)
	addr := ln.Addr().String()
	callbackURL := "http://" + addr + callbackPath
	resultCh := make(chan trayLoginResult, 1)

	mux := http.NewServeMux()
	mux.HandleFunc(callbackPath, func(w http.ResponseWriter, r *http.Request) {
		ctxID := strings.TrimSpace(r.URL.Query().Get("context_id"))
		if ctxID == "" {
			ctxID = strings.TrimSpace(r.URL.Query().Get("user_id"))
		}
		if ctxID == "" {
			ctxID = strings.TrimSpace(r.URL.Query().Get("uid"))
		}
		select {
		case resultCh <- trayLoginResult{ContextID: ctxID}:
		default:
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><title>Login Successful</title>
<style>body{font-family:system-ui;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#1a1a2e;color:#fff}
.card{text-align:center;padding:2rem;border-radius:12px;background:#16213e;box-shadow:0 4px 20px rgba(0,0,0,0.3)}
h2{color:#7c3aed}p{color:#94a3b8}</style></head>
<body><div class="card"><h2>&#10003; Device Connected</h2>
<p>m3c-tools is now linked to your account.</p>
<p>You can close this tab and return to the app.</p></div></body></html>`)
	})

	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		if serveErr := srv.Serve(ln); serveErr != nil && serveErr != http.ErrServerClosed {
			log.Printf("[auth] callback server error: %v", serveErr)
			select {
			case resultCh <- trayLoginResult{Err: serveErr}:
			default:
			}
		}
	}()
	closeFn := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
	return srv, callbackURL, resultCh, closeFn, nil
}

// trayER1BaseURL extracts the base URL from the ER1 API URL.
// e.g., "https://onboarding.guide/upload_2" -> "https://onboarding.guide"
func trayER1BaseURL(apiURL string) string {
	raw := strings.TrimSpace(apiURL)
	if raw == "" {
		return ""
	}
	u, err := neturl.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	p := strings.TrimSuffix(u.Path, "/upload_2")
	p = strings.TrimSuffix(p, "/")
	return fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, p)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
