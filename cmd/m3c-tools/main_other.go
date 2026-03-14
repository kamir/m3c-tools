// main_other.go — CLI-only entry point for non-macOS platforms.
// GUI features (menu bar, observation window, recording) are not available.
//
//go:build !darwin

package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/er1"
	"github.com/kamir/m3c-tools/pkg/impression"
	"github.com/kamir/m3c-tools/pkg/plaud"
	"github.com/kamir/m3c-tools/pkg/tracking"
	"github.com/kamir/m3c-tools/pkg/transcript"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	// Load .env files: CWD first, then home dir (config precedence).
	home, _ := os.UserHomeDir()
	for _, p := range []string{".env", filepath.Join(home, ".m3c-tools.env")} {
		_ = er1.LoadDotenv(p)
	}

	switch os.Args[1] {
	case "transcript":
		cmdTranscript(os.Args[2:])
	case "plaud":
		cmdPlaud(os.Args[2:])
	case "setup":
		cmdSetup(os.Args[2:])
	case "check-er1":
		cmdCheckER1()
	case "menubar":
		fmt.Fprintln(os.Stderr, "Error: menu bar is only available on macOS")
		os.Exit(1)
	case "record", "devices":
		fmt.Fprintln(os.Stderr, "Error: audio recording requires macOS with PortAudio")
		os.Exit(1)
	case "screenshot":
		fmt.Fprintln(os.Stderr, "Error: screenshot capture requires macOS")
		os.Exit(1)
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

	// 5. Write config
	if err := er1.WriteConfig(er1URL, apiKey, contextID, true, tags); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing config: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\n  Configuration saved to %s\n\n", er1.ConfigPath())

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
	debugDir := filepath.Join(os.TempDir(), "m3c-tools-er1-setup")
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
			fmt.Fprintln(os.Stderr, "Usage: m3c-tools plaud sync <recording_id|all>")
			os.Exit(1)
		}
		cmdPlaudSync(args[1])
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

	fmt.Printf("%-36s  %-6s  %-10s  %s\n", "ID", "Secs", "Status", "Title")
	fmt.Println("------------------------------------  ------  ----------  -----")
	for _, r := range recordings {
		fmt.Printf("%-36s  %6d  %-10s  %s\n", r.ID, r.Duration, r.Status, r.Title)
	}
	fmt.Printf("\nTotal: %d recordings\n", len(recordings))
}

// cmdPlaudSync syncs a recording (or all) to ER1.
func cmdPlaudSync(recordingID string) {
	cfg := plaud.LoadConfig()
	session, err := plaud.LoadToken(cfg.TokenPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading token: %v\nRun: m3c-tools plaud auth login\n", err)
		os.Exit(1)
	}

	client := plaud.NewClient(cfg, session.Token)
	er1Cfg := er1.LoadConfig()
	er1Cfg.ContentType = cfg.ContentType

	dbPath := defaultFilesDBPath()

	var ids []string
	if recordingID == "all" {
		recordings, listErr := client.ListRecordings()
		if listErr != nil {
			fmt.Fprintf(os.Stderr, "Error listing recordings: %v\n", listErr)
			os.Exit(1)
		}
		// Check tracking DB to skip already-synced.
		filesDB, dbErr := tracking.OpenFilesDB(dbPath)
		if dbErr != nil {
			log.Printf("[plaud] warning: cannot open tracking DB: %v", dbErr)
		}
		for _, rec := range recordings {
			skip := false
			if filesDB != nil {
				if tracked, lookupErr := filesDB.GetByPath("plaud://" + rec.ID); lookupErr == nil && tracked != nil {
					skip = true
				}
			}
			if !skip {
				ids = append(ids, rec.ID)
			}
		}
		if filesDB != nil {
			filesDB.Close()
		}
		fmt.Printf("Found %d recordings, %d already synced.\n", len(recordings), len(recordings)-len(ids))
		if len(ids) == 0 {
			fmt.Println("All recordings already synced.")
			return
		}
		fmt.Printf("Syncing %d recordings...\n", len(ids))
	} else {
		ids = []string{recordingID}
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

	success, failed := 0, 0
	for i, recID := range ids {
		if len(ids) > 1 {
			fmt.Printf("  [%d/%d] ", i+1, len(ids))
		}

		// 1. Get recording metadata.
		fmt.Printf("Fetching recording %s...\n", recID)
		rec, recErr := client.GetRecording(recID)
		if recErr != nil {
			fmt.Fprintf(os.Stderr, "  Error: %v\n", recErr)
			failed++
			continue
		}
		fmt.Printf("  Title: %s\n  Duration: %ds\n", rec.Title, rec.Duration)

		// 2. Download audio.
		fmt.Print("Downloading audio... ")
		audioData, audioFmt, dlErr := client.DownloadAudio(recID)
		if dlErr != nil {
			fmt.Fprintf(os.Stderr, "FAILED: %v\n", dlErr)
			failed++
			continue
		}
		fmt.Printf("(%d KB)\n", len(audioData)/1024)

		// 3. Get transcript.
		fmt.Print("Fetching transcript... ")
		var transcriptText string
		tx, txErr := client.GetTranscript(recID)
		if txErr != nil {
			fmt.Println("(not available)")
			transcriptText = "[No transcript available — audio only]"
		} else {
			fmt.Println("OK")
			transcriptText = tx.Text
			if tx.Summary != "" {
				transcriptText = transcriptText + "\n\n=== SUMMARY ===\n" + tx.Summary
			}
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
		fmt.Printf("Uploading to ER1 (%s)...\n", er1Cfg.APIURL)
		fmt.Printf("  Context: %s\n  Tags: %s\n", er1Cfg.ContextID, tags)

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
			fmt.Fprintf(os.Stderr, "  Upload FAILED: %v\n", upErr)
			// Save locally as fallback.
			localErr := savePlaudLocally(recID, rec, audioData, audioFmt, doc, transcriptText, tags)
			if localErr != nil {
				fmt.Fprintf(os.Stderr, "  Local save also FAILED: %v\n", localErr)
				failed++
				continue
			}
			fmt.Printf("  Saved locally to ~/plaud-sync/%s/\n", recID[:min(8, len(recID))])
			// Track as locally saved.
			if filesDB != nil {
				audioHash := fmt.Sprintf("%x", sha256.Sum256(audioData))
				_, _ = filesDB.RecordFile("plaud://"+recID, audioHash, int64(len(audioData)), "plaud", "")
				_ = filesDB.RecordTranscript(audioHash, "plaud", strings.TrimSpace(transcriptText), "")
			}
			success++
			continue
		}

		fmt.Printf("  Uploaded. Doc ID: %s\n", resp.DocID)

		// 6. Record in tracking DB.
		if filesDB != nil {
			audioHash := fmt.Sprintf("%x", sha256.Sum256(audioData))
			_, _ = filesDB.RecordFile("plaud://"+recID, audioHash, int64(len(audioData)), "plaud", "")
			_ = filesDB.RecordTranscript(audioHash, "plaud", strings.TrimSpace(transcriptText), "")
			_ = filesDB.RecordUploadSuccess(audioHash, "plaud", resp.DocID)
		}
		success++
	}

	if len(ids) > 1 {
		fmt.Printf("Done. %d synced, %d failed.\n", success, failed)
	} else {
		fmt.Println("Done.")
	}
}

// savePlaudLocally saves recording data to ~/plaud-sync/<recID>/ for later re-upload.
func savePlaudLocally(recID string, rec *plaud.Recording, audioData []byte, audioFmt, compositeDoc, transcriptText, tags string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("get home dir: %w", err)
	}
	dir := filepath.Join(home, "plaud-sync", recID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create dir: %w", err)
	}

	if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("audio.%s", audioFmt)), audioData, 0644); err != nil {
		return fmt.Errorf("write audio: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fieldnote.txt"), []byte(compositeDoc), 0644); err != nil {
		return fmt.Errorf("write doc: %w", err)
	}
	if transcriptText != "" {
		if err := os.WriteFile(filepath.Join(dir, "transcript.txt"), []byte(transcriptText), 0644); err != nil {
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
	return os.WriteFile(filepath.Join(dir, "metadata.json"), metaJSON, 0644)
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

func printUsage() {
	fmt.Println(`m3c-tools — Multi-Modal-Memory Tools (CLI mode)

Available commands (cross-platform):
  setup                  Interactive ER1 onboarding wizard
    --er1-url <url>       ER1 upload endpoint (default: onboarding.guide)
    --tags <tags>         Default tags for plaud sync
    --no-browser          Skip browser login, enter User ID manually
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
  check-er1              Check ER1 server connectivity
  help                   Show this help

macOS-only commands (not available on this platform):
  menubar                Launch menu bar app
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
