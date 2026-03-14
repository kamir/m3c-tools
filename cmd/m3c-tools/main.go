//go:build darwin

// m3c-tools — Multi-Modal-Memory Tools
//
// CLI entry point for transcript fetching, voice recording,
// and ER1 upload. Also serves as the menu bar app when run with --menubar.
//
// Usage:
//
//	m3c-tools transcript <video_id> [--lang en] [--format text|srt|json|webvtt] [--translate de]
//	m3c-tools upload <video_id> [--audio file.wav] [--image file.jpg]
//	m3c-tools record [output.wav] [--duration 5]
//	m3c-tools whisper <audio_file> [--model base] [--language en]
//	m3c-tools devices
//	m3c-tools thumbnail <video_id> [--output file.jpg]
//	m3c-tools retry [--interval 30] [--max-retries 10]
//	m3c-tools check-er1
//	m3c-tools menubar [--title M3C] [--icon path.png] [--log ~/.m3c-tools/m3c-tools.log]
package main

import (
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
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kamir/m3c-tools/pkg/er1"
	"github.com/kamir/m3c-tools/pkg/importer"
	"github.com/kamir/m3c-tools/pkg/impression"
	"github.com/kamir/m3c-tools/pkg/plaud"
	"github.com/kamir/m3c-tools/pkg/menubar"
	"github.com/kamir/m3c-tools/pkg/recorder"
	"github.com/kamir/m3c-tools/pkg/screenshot"
	"github.com/kamir/m3c-tools/pkg/timetracking"
	"github.com/kamir/m3c-tools/pkg/tracking"
	"github.com/kamir/m3c-tools/pkg/transcript"
	"github.com/kamir/m3c-tools/pkg/whisper"
)

func init() {
	// macOS AppKit requires all UI operations on the main OS thread (thread 1).
	// Go 1.26+ no longer guarantees the main goroutine runs on thread 1,
	// so we must lock it explicitly.
	runtime.LockOSThread()
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	// Load .env if present
	for _, p := range []string{".env", filepath.Join(os.Getenv("HOME"), ".m3c-tools.env")} {
		_ = er1.LoadDotenv(p)
	}

	switch os.Args[1] {
	case "transcript":
		cmdTranscript(os.Args[2:])
	case "upload":
		cmdUpload(os.Args[2:])
	case "whisper":
		cmdWhisper(os.Args[2:])
	case "thumbnail":
		cmdThumbnail(os.Args[2:])
	case "check-er1":
		cmdCheckER1()
	case "devices":
		cmdDevices()
	case "record":
		cmdRecord(os.Args[2:])
	case "retry":
		cmdRetry(os.Args[2:])
	case "schedule":
		cmdSchedule(os.Args[2:])
	case "status":
		cmdStatus(os.Args[2:])
	case "cancel":
		cmdCancel(os.Args[2:])
	case "screenshot":
		cmdScreenshot(os.Args[2:])
	case "import-audio":
		cmdImportAudio(os.Args[2:])
	case "plaud":
		cmdPlaud(os.Args[2:])
	case "setup":
		cmdSetup(os.Args[2:])
	case "menubar":
		cmdMenubar(os.Args[2:])
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`m3c-tools — Multi-Modal-Memory Tools

Commands:
  transcript <video_id>  Fetch YouTube transcript
    --lang <code>          Language code (default: en)
    --format <fmt>         Output format: text, srt, json, webvtt (default: text)
    --translate <code>     Translate transcript to target language code
    --list                 List available transcripts only
    --exclude-generated    Exclude auto-generated transcripts from --list
    --exclude-manually-created  Exclude manually created transcripts from --list
    --proxy-url <url>      HTTP/SOCKS5 proxy URL (e.g. http://host:port)
    --proxy-auth <creds>   Proxy credentials as user:password

  upload <video_id>      Fetch transcript + thumbnail, upload to ER1
    --audio <file>         Include audio file
    --impression <text>    Add user impression text

  whisper <audio_file>   Transcribe audio via whisper
    --model <model>        Whisper model (default: base)
    --language <lang>      Language hint

  thumbnail <video_id>   Download video thumbnail
    --output <file>        Output path (default: <video_id>_thumbnail.jpg)

  record [output.wav]    Record from microphone
    --duration <secs>      Recording duration (default: 5)

  devices                List audio input devices
  check-er1              Test ER1 server connectivity

  retry                  Run ER1 retry loop for queued uploads
    --interval <secs>      Poll interval in seconds (default: 30)
    --max-retries <n>      Max retries per entry (default: 10)
    --queue <path>         Queue file path (default: ~/.m3c-tools/queue.json)

  schedule <entry_id>    Schedule an ER1 retry entry in SQLite tracking DB
    --transcript <path>    Transcript file path (required)
    --audio <path>         Audio file path
    --image <path>         Image file path
    --tags <tags>          Comma-separated tags
    --max-attempts <n>     Max retry attempts (default: 10)
    --db <path>            SQLite DB path (default: ~/.m3c-tools/exports.db)

  status                 Show status of ER1 retry entries
    --entry <id>           Show status of a specific entry
    --db <path>            SQLite DB path (default: ~/.m3c-tools/exports.db)

  cancel <entry_id>      Cancel a pending ER1 retry entry
    --db <path>            SQLite DB path (default: ~/.m3c-tools/exports.db)

  screenshot             Capture a screenshot (macOS only)
    --mode <mode>          Capture mode: full, window, region (default: full)
    --output <dir>         Output directory (default: current dir)
    --filename <name>      Output filename (default: timestamped)
    --silent               Suppress capture sound
    --hide-cursor          Hide cursor in capture

  import-audio <dir>     Scan/import audio files
    --run                  Import, transcribe, upload, and tag end-to-end
    --extensions           List supported audio extensions
    --compact              Machine-readable output (TSV: status, path, size, tags)
    --db <path>            Tracking DB path (default: ~/.m3c-tools/tracking.db)

  plaud list             List Plaud recordings with sync status
  plaud sync <id>        Sync a Plaud recording to ER1
  plaud auth login       Extract token from Chrome (web.plaud.ai)
  plaud auth <token>     Save Plaud API token manually

  setup                  Set up Python venv and install whisper
    --force                Recreate venv from scratch
    --check                Check setup status without installing

  menubar                Launch macOS menu bar app
    --title <text>         Menu bar title (default: M3C)
    --icon <path>          Menu bar icon PNG path
    --log <path>           Log file path (default: ~/.m3c-tools/m3c-tools.log)

Like m3c-tools? Star us on GitHub: https://github.com/kamir/m3c-tools`)
}

type er1SessionState struct {
	mu        sync.RWMutex
	contextID string
	loggedIn  bool
}

type persistedER1Session struct {
	ContextID string    `json:"context_id"`
	SavedAt   time.Time `json:"saved_at"`
}

var runtimeER1Session er1SessionState
var ingestionOps = newIngestionCoordinator()
var reverseTracker *timetracking.ReverseTracker

func setRuntimeER1Login(contextID string) {
	runtimeER1Session.mu.Lock()
	defer runtimeER1Session.mu.Unlock()
	runtimeER1Session.contextID = strings.TrimSpace(contextID)
	runtimeER1Session.loggedIn = runtimeER1Session.contextID != ""
}

func clearRuntimeER1Login() {
	runtimeER1Session.mu.Lock()
	defer runtimeER1Session.mu.Unlock()
	runtimeER1Session.contextID = ""
	runtimeER1Session.loggedIn = false
}

func runtimeER1ContextID() string {
	runtimeER1Session.mu.RLock()
	defer runtimeER1Session.mu.RUnlock()
	return runtimeER1Session.contextID
}

func applyRuntimeER1Context(cfg *er1.Config) {
	if ctx := runtimeER1ContextID(); ctx != "" {
		cfg.ContextID = ctx
	}
}

func er1SessionPersistenceEnabled() bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv("M3C_ER1_SESSION_PERSIST")))
	switch v {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func er1SessionFilePath() string {
	if p := strings.TrimSpace(os.Getenv("M3C_ER1_SESSION_FILE")); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return ""
	}
	return filepath.Join(home, ".m3c-tools", "er1_session.json")
}

func savePersistedER1Session(contextID string) error {
	if !er1SessionPersistenceEnabled() {
		return nil
	}
	p := er1SessionFilePath()
	if p == "" {
		return fmt.Errorf("session file path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return fmt.Errorf("create session dir: %w", err)
	}
	data, err := json.MarshalIndent(persistedER1Session{
		ContextID: strings.TrimSpace(contextID),
		SavedAt:   time.Now(),
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode session json: %w", err)
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		return fmt.Errorf("write session file: %w", err)
	}
	return nil
}

func loadPersistedER1Session() (string, error) {
	if !er1SessionPersistenceEnabled() {
		return "", nil
	}
	p := er1SessionFilePath()
	if p == "" {
		return "", fmt.Errorf("session file path is empty")
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read session file: %w", err)
	}
	var s persistedER1Session
	if err := json.Unmarshal(data, &s); err != nil {
		return "", fmt.Errorf("parse session json: %w", err)
	}
	return strings.TrimSpace(s.ContextID), nil
}

func clearPersistedER1Session() error {
	p := er1SessionFilePath()
	if p == "" {
		return nil
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove session file: %w", err)
	}
	return nil
}

// -- transcript command --

func cmdTranscript(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: m3c-tools transcript <video_id> [--lang en] [--format text] [--translate de] [--proxy-url URL] [--proxy-auth user:pass]")
		os.Exit(1)
	}
	videoID := args[0]
	lang := "en"
	format := "text"
	translateLang := ""
	listOnly := false
	excludeGenerated := false
	excludeManuallyCreated := false
	proxyURL := ""
	proxyAuth := ""

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--lang":
			if i+1 < len(args) {
				lang = args[i+1]
				i++
			}
		case "--format":
			if i+1 < len(args) {
				format = args[i+1]
				i++
			}
		case "--translate":
			if i+1 < len(args) {
				translateLang = args[i+1]
				i++
			}
		case "--list":
			listOnly = true
		case "--exclude-generated":
			excludeGenerated = true
		case "--exclude-manually-created":
			excludeManuallyCreated = true
		case "--proxy-url":
			if i+1 < len(args) {
				proxyURL = args[i+1]
				i++
			}
		case "--proxy-auth":
			if i+1 < len(args) {
				proxyAuth = args[i+1]
				i++
			}
		default:
			if strings.HasPrefix(args[i], "--") {
				fmt.Fprintf(os.Stderr, "Warning: unknown flag %q (ignored)\n", args[i])
			}
		}
	}

	var api *transcript.API
	if proxyURL != "" {
		proxyCfg := &transcript.GenericProxyConfig{
			ProxyURL:  proxyURL,
			ProxyAuth: proxyAuth,
		}
		var err error
		api, err = transcript.NewWithProxy(proxyCfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Proxy error: %v\n", err)
			os.Exit(1)
		}
	} else {
		api = transcript.New()
	}

	if listOnly {
		list, err := api.List(videoID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if excludeGenerated {
			list = list.FilterExcludeGenerated()
		}
		if excludeManuallyCreated {
			list = list.FilterExcludeManuallyCreated()
		}
		fmt.Print(list.String())
		return
	}

	var fetched *transcript.FetchedTranscript
	var err error

	if translateLang != "" {
		fetched, err = api.FetchTranslated(videoID, []string{lang}, translateLang)
	} else {
		fetched, err = api.Fetch(videoID, []string{lang}, false)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var output string
	switch format {
	case "text":
		f := transcript.TextFormatter{}
		output = f.FormatTranscript(fetched)
	case "srt":
		f := transcript.SRTFormatter{}
		output = f.FormatTranscript(fetched)
	case "json":
		f := transcript.JSONFormatter{Pretty: true}
		output = f.FormatTranscript(fetched)
	case "webvtt":
		f := transcript.WebVTTFormatter{}
		output = f.FormatTranscript(fetched)
	default:
		fmt.Fprintf(os.Stderr, "Unknown format: %s\n", format)
		os.Exit(1)
	}
	fmt.Print(output)
}

// -- upload command --

func cmdUpload(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: m3c-tools upload <video_id> [--audio file.wav] [--impression text]")
		os.Exit(1)
	}
	videoID := args[0]
	audioPath := ""
	impressionText := ""

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--audio":
			if i+1 < len(args) {
				audioPath = args[i+1]
				i++
			}
		case "--impression":
			if i+1 < len(args) {
				impressionText = args[i+1]
				i++
			}
		default:
			if strings.HasPrefix(args[i], "--") {
				fmt.Fprintf(os.Stderr, "Warning: unknown flag %q (ignored)\n", args[i])
			}
		}
	}

	// Start background retry goroutine to process any previously queued uploads.
	// This runs concurrently with the current upload attempt.
	queuePath := er1.DefaultQueuePath()
	cfg := er1.LoadConfig()
	bgRetry := er1.StartBackgroundRetry(
		queuePath, cfg,
		time.Duration(cfg.RetryInterval)*time.Second,
		cfg.MaxRetries,
	)
	bgRetry.OnLog = func(msg string) {
		fmt.Println(msg)
	}
	defer bgRetry.Stop(5 * time.Second)
	fmt.Println("Background retry goroutine started.")

	fmt.Printf("Fetching transcript for %s...\n", videoID)
	api := transcript.New()
	fetched, err := api.Fetch(videoID, []string{"en"}, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Transcript error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  %d snippets, %s (%s)\n", len(fetched.Snippets), fetched.Language, fetched.LanguageCode)

	// Build composite document
	textFmt := transcript.TextFormatter{}
	doc := &impression.CompositeDoc{
		VideoID:        videoID,
		VideoURL:       "https://www.youtube.com/watch?v=" + videoID,
		Language:       fetched.Language,
		LanguageCode:   fetched.LanguageCode,
		IsGenerated:    fetched.IsGenerated,
		SnippetCount:   len(fetched.Snippets),
		TranscriptText: textFmt.FormatTranscript(fetched),
		ImpressionText: impressionText,
		ObsType:        impression.Progress,
		Timestamp:      time.Now(),
	}
	composite := doc.Build()
	fmt.Printf("  Composite: %d chars\n", len(composite))

	// Fetch thumbnail
	fmt.Println("Fetching thumbnail...")
	fetcher, _ := transcript.NewFetcher(nil)
	thumbData, err := fetcher.FetchThumbnail(videoID)
	if err != nil {
		fmt.Printf("  Warning: %v (using placeholder)\n", err)
	} else {
		fmt.Printf("  Thumbnail: %d bytes\n", len(thumbData))
	}

	// Read audio if provided
	var audioData []byte
	if audioPath != "" {
		audioData, err = os.ReadFile(audioPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading audio: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("  Audio: %s (%d bytes)\n", audioPath, len(audioData))
	}

	// Upload to ER1
	fmt.Printf("Uploading to %s...\n", cfg.APIURL)

	tags := impression.BuildVideoTags(videoID, "", impression.Progress)
	payload := &er1.UploadPayload{
		TranscriptData:     []byte(composite),
		TranscriptFilename: fmt.Sprintf("%s_transcript.txt", videoID),
		AudioData:          audioData,
		AudioFilename:      fmt.Sprintf("%s_audio.wav", videoID),
		ImageData:          thumbData,
		ImageFilename:      fmt.Sprintf("%s_thumbnail.jpg", videoID),
		Tags:               tags,
	}
	resp, err := er1.Upload(cfg, payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Upload error: %v\n", err)
		// ER1 failure detection: queue failed upload for retry
		entry := er1.EnqueueFailure(queuePath, videoID, payload, tags, err)
		fmt.Fprintf(os.Stderr, "Queued for retry: %s → %s\n", entry.ID, queuePath)
		os.Exit(1)
	}

	fmt.Printf("\nUpload SUCCESS\n")
	fmt.Printf("  doc_id: %s\n", resp.DocID)
	fmt.Printf("  GCS:    %s\n", resp.GCSURI)
	fmt.Printf("  time:   %s\n", resp.Time)
}

// -- whisper command --

func cmdWhisper(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: m3c-tools whisper <audio_file> [--model base] [--language en]")
		os.Exit(1)
	}
	audioFile := args[0]
	model := "base"
	language := ""

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--model":
			if i+1 < len(args) {
				model = args[i+1]
				i++
			}
		case "--language":
			if i+1 < len(args) {
				language = args[i+1]
				i++
			}
		}
	}

	result, err := whisper.Transcribe(audioFile, model, language)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Segments: %d\n", len(result.Segments))
	for _, s := range result.Segments {
		fmt.Printf("[%6.1fs → %6.1fs] %s\n", s.Start, s.End, strings.TrimSpace(s.Text))
	}
	fmt.Printf("\nFull text (%d chars):\n%s\n", len(result.Text), result.Text)
}

// -- thumbnail command --

func cmdThumbnail(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: m3c-tools thumbnail <video_id> [--output file.jpg]")
		os.Exit(1)
	}
	videoID := args[0]
	output := videoID + "_thumbnail.jpg"

	for i := 1; i < len(args); i++ {
		if args[i] == "--output" && i+1 < len(args) {
			output = args[i+1]
			i++
		}
	}

	fetcher, _ := transcript.NewFetcher(nil)
	data, err := fetcher.FetchThumbnail(videoID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	os.WriteFile(output, data, 0644)
	fmt.Printf("Saved %s (%d bytes)\n", output, len(data))
}

// -- check-er1 command --

func cmdSetup(args []string) {
	force := false
	checkOnly := false
	for _, arg := range args {
		switch arg {
		case "--force":
			force = true
		case "--check":
			checkOnly = true
		}
	}

	home := os.Getenv("HOME")
	dataDir := filepath.Join(home, ".m3c-tools")
	venvDir := whisper.VenvDir()
	whisperPath := whisper.VenvWhisperPath()

	fmt.Println("m3c-tools setup")
	fmt.Println("===============")
	fmt.Println()

	// Check data directory
	if fi, err := os.Stat(dataDir); err == nil && fi.IsDir() {
		fmt.Printf("  Data dir:    %s (exists)\n", dataDir)
	} else {
		fmt.Printf("  Data dir:    %s (will be created)\n", dataDir)
	}

	// Check Python
	pythonPath, err := exec.LookPath("python3")
	if err != nil {
		pythonPath = "(not found)"
	}
	fmt.Printf("  Python3:     %s\n", pythonPath)

	// Check venv
	venvExists := false
	if fi, err := os.Stat(filepath.Join(venvDir, "bin", "python")); err == nil && !fi.IsDir() {
		venvExists = true
		fmt.Printf("  Venv:        %s (exists)\n", venvDir)
	} else {
		fmt.Printf("  Venv:        %s (not installed)\n", venvDir)
	}

	// Check whisper in venv
	whisperFound := false
	if fi, err := os.Stat(whisperPath); err == nil && !fi.IsDir() {
		whisperFound = true
		fmt.Printf("  Whisper:     %s (installed)\n", whisperPath)
	} else {
		fmt.Printf("  Whisper:     (not installed)\n")
	}

	// Check system whisper as fallback
	if sysWhisper, err := exec.LookPath("whisper"); err == nil && !whisperFound {
		fmt.Printf("  Whisper:     %s (system, fallback)\n", sysWhisper)
	}

	// Check ffmpeg
	if ffmpegPath, err := exec.LookPath("ffmpeg"); err == nil {
		fmt.Printf("  ffmpeg:      %s\n", ffmpegPath)
	} else {
		fmt.Printf("  ffmpeg:      (not found — install with: brew install ffmpeg)\n")
	}

	// Check ER1 config
	er1Cfg := er1.LoadConfig()
	fmt.Printf("  ER1 API:     %s\n", er1Cfg.APIURL)

	// Check .env
	envPath := filepath.Join(home, ".m3c-tools.env")
	if _, err := os.Stat(envPath); err == nil {
		fmt.Printf("  Config:      %s\n", envPath)
	} else if _, err := os.Stat(".env"); err == nil {
		fmt.Printf("  Config:      .env (local)\n")
	} else {
		fmt.Printf("  Config:      (no .env found)\n")
	}

	fmt.Println()

	if checkOnly {
		if venvExists && whisperFound {
			fmt.Println("Status: ready")
		} else {
			fmt.Println("Status: setup needed — run 'm3c-tools setup'")
			os.Exit(1)
		}
		return
	}

	if venvExists && whisperFound && !force {
		fmt.Println("Setup is already complete. Use --force to reinstall.")
		return
	}

	// Create data directory
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating %s: %v\n", dataDir, err)
		os.Exit(1)
	}

	// Run setup-venv.sh
	setupScript := findSetupScript()
	if setupScript == "" {
		fmt.Fprintf(os.Stderr, "Error: setup-venv.sh not found.\n")
		fmt.Fprintf(os.Stderr, "Expected at: scripts/setup-venv.sh (relative to repo root)\n")
		os.Exit(1)
	}

	setupArgs := []string{setupScript}
	if force {
		setupArgs = append(setupArgs, "--force")
	}
	cmd := exec.Command("bash", setupArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "\nSetup failed: %v\n", err)
		os.Exit(1)
	}
}

// findSetupScript locates scripts/setup-venv.sh relative to the binary or CWD.
func findSetupScript() string {
	// Check relative to working directory
	if _, err := os.Stat("scripts/setup-venv.sh"); err == nil {
		return "scripts/setup-venv.sh"
	}
	// Check relative to binary location
	if exePath, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(exePath), "..", "scripts", "setup-venv.sh")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	// Check in app bundle Resources
	if exePath, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(exePath), "..", "Resources", "setup-venv.sh")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}

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

// -- devices command --

func cmdDevices() {
	devices, err := recorder.ListInputDevices()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing devices: %v\n", err)
		os.Exit(1)
	}

	if len(devices) == 0 {
		fmt.Println("No audio input devices found.")
		return
	}

	fmt.Printf("Audio input devices (%d):\n", len(devices))
	for _, d := range devices {
		marker := "  "
		if d.IsDefault {
			marker = "* "
		}
		fmt.Printf("%s%-40s  %d ch  %.0f Hz\n", marker, d.Name, d.MaxInputChannels, d.DefaultSampleRate)
	}
	fmt.Println("\n  (* = default input device)")
}

// -- record command --

func cmdRecord(args []string) {
	output := "recording.wav"
	duration := 5
	if len(args) > 0 && !strings.HasPrefix(args[0], "--") {
		output = args[0]
	}
	for i := 0; i < len(args); i++ {
		if args[i] == "--duration" && i+1 < len(args) {
			d, err := strconv.Atoi(args[i+1])
			if err == nil {
				duration = d
			}
			i++
		}
	}

	fmt.Printf("Recording %ds to %s...\n", duration, output)
	fmt.Printf("  Format: %d Hz, %d-bit, mono (whisper-compatible)\n", recorder.SampleRate, recorder.BitsPerSample)

	samples, err := recorder.Record(duration)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Recording error: %v\n", err)
		os.Exit(1)
	}

	stats := recorder.Stats(samples)
	fmt.Printf("  Captured %d samples (%.1fs)\n", stats.Samples, stats.Duration)
	fmt.Printf("  Peak amplitude: %d (%.1f%%)\n", stats.PeakAmplitude, float64(stats.PeakAmplitude)/32768.0*100)

	if stats.PeakAmplitude < 100 {
		fmt.Println("  WARNING: Very low audio levels — check microphone permissions")
	}

	if err := recorder.WriteWAV(output, samples); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing WAV: %v\n", err)
		os.Exit(1)
	}

	info, statErr := os.Stat(output)
	if statErr == nil {
		fmt.Printf("  Wrote %s (%d bytes)\n", output, info.Size())
	}
	fmt.Println("Done.")
}

// -- retry command --

func cmdRetry(args []string) {
	interval := 30
	maxRetries := 10
	queuePath := er1.DefaultQueuePath()

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--interval":
			if i+1 < len(args) {
				if v, err := strconv.Atoi(args[i+1]); err == nil {
					interval = v
				}
				i++
			}
		case "--max-retries":
			if i+1 < len(args) {
				if v, err := strconv.Atoi(args[i+1]); err == nil {
					maxRetries = v
				}
				i++
			}
		case "--queue":
			if i+1 < len(args) {
				queuePath = args[i+1]
				i++
			}
		}
	}

	fmt.Printf("Starting ER1 retry loop (interval=%ds, max-retries=%d, queue=%s)\n", interval, maxRetries, queuePath)

	cfg := er1.LoadConfig()
	q := er1.NewQueue(queuePath)

	fmt.Printf("  ER1: %s\n", cfg.Summary())
	fmt.Printf("  Queue entries: %d\n", q.Len())
	fmt.Println("  Press Ctrl+C to stop.")

	runner := er1.NewRetryRunner(q, func(entry er1.QueueEntry) error {
		payload := &er1.UploadPayload{
			TranscriptFilename: entry.TranscriptPath,
			AudioFilename:      entry.AudioPath,
			ImageFilename:      entry.ImagePath,
			Tags:               entry.Tags,
		}
		if entry.TranscriptPath != "" {
			if data, readErr := os.ReadFile(entry.TranscriptPath); readErr == nil {
				payload.TranscriptData = data
			} else {
				payload.TranscriptData = []byte(fmt.Sprintf("Retry upload for %s", entry.ID))
			}
		} else {
			payload.TranscriptData = []byte(fmt.Sprintf("Retry upload for %s", entry.ID))
		}
		if entry.AudioPath != "" {
			if data, readErr := os.ReadFile(entry.AudioPath); readErr == nil {
				payload.AudioData = data
			}
		}
		if entry.ImagePath != "" {
			if data, readErr := os.ReadFile(entry.ImagePath); readErr == nil {
				payload.ImageData = data
			}
		}
		_, uploadErr := er1.Upload(cfg, payload)
		return uploadErr
	}, maxRetries)

	runner.Backoff = er1.DefaultBackoff(
		time.Duration(interval)*time.Second,
		5*time.Minute,
	)

	runner.OnRetry = func(entry er1.QueueEntry, retryErr error, removed bool) {
		if retryErr == nil {
			fmt.Printf("[retry] SUCCESS: %s (removed from queue)\n", entry.ID)
		} else if removed {
			fmt.Printf("[retry] DROPPED: %s — max retries exceeded\n", entry.ID)
		} else {
			fmt.Printf("[retry] FAILED: %s — attempt %d: %v\n", entry.ID, entry.RetryCount+1, retryErr)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nShutting down retry loop...")
		cancel()
	}()

	if loopErr := runner.Run(ctx, time.Duration(interval)*time.Second); loopErr != nil && loopErr != context.Canceled {
		fmt.Fprintf(os.Stderr, "Retry loop error: %v\n", loopErr)
		os.Exit(1)
	}
	fmt.Println("Retry loop stopped.")
}

// -- schedule command --

func defaultExportsDBPath() string {
	dir := filepath.Join(os.Getenv("HOME"), ".m3c-tools")
	os.MkdirAll(dir, 0755)
	return filepath.Join(dir, "exports.db")
}

func cmdSchedule(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: m3c-tools schedule <entry_id> --transcript <path> [--audio <path>] [--image <path>] [--tags <tags>] [--max-attempts <n>] [--db <path>]")
		os.Exit(1)
	}
	entryID := args[0]
	transcriptPath := ""
	audioPath := ""
	imagePath := ""
	tags := ""
	maxAttempts := 10
	dbPath := defaultExportsDBPath()

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--transcript":
			if i+1 < len(args) {
				transcriptPath = args[i+1]
				i++
			}
		case "--audio":
			if i+1 < len(args) {
				audioPath = args[i+1]
				i++
			}
		case "--image":
			if i+1 < len(args) {
				imagePath = args[i+1]
				i++
			}
		case "--tags":
			if i+1 < len(args) {
				tags = args[i+1]
				i++
			}
		case "--max-attempts":
			if i+1 < len(args) {
				if v, err := strconv.Atoi(args[i+1]); err == nil {
					maxAttempts = v
				}
				i++
			}
		case "--db":
			if i+1 < len(args) {
				dbPath = args[i+1]
				i++
			}
		}
	}

	if transcriptPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --transcript is required")
		os.Exit(1)
	}

	db, err := tracking.OpenRetryQueueDB(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening DB: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	entry, err := db.Insert(entryID, transcriptPath, audioPath, imagePath, tags, maxAttempts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error scheduling entry: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Scheduled retry entry:\n")
	fmt.Printf("  entry_id:     %s\n", entry.EntryID)
	fmt.Printf("  transcript:   %s\n", entry.TranscriptPath)
	if entry.AudioPath != "" {
		fmt.Printf("  audio:        %s\n", entry.AudioPath)
	}
	if entry.ImagePath != "" {
		fmt.Printf("  image:        %s\n", entry.ImagePath)
	}
	if entry.Tags != "" {
		fmt.Printf("  tags:         %s\n", entry.Tags)
	}
	fmt.Printf("  max_attempts: %d\n", entry.MaxAttempts)
	fmt.Printf("  status:       %s\n", entry.Status)
}

// -- status command --

func cmdStatus(args []string) {
	entryID := ""
	dbPath := defaultExportsDBPath()

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--entry":
			if i+1 < len(args) {
				entryID = args[i+1]
				i++
			}
		case "--db":
			if i+1 < len(args) {
				dbPath = args[i+1]
				i++
			}
		}
	}

	db, err := tracking.OpenRetryQueueDB(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening DB: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	if entryID != "" {
		entry, err := db.GetByEntryID(entryID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if entry == nil {
			fmt.Fprintf(os.Stderr, "Entry not found: %s\n", entryID)
			os.Exit(1)
		}
		printRetryEntry(entry)
		return
	}

	// Show summary counts and list all entries
	pending, _ := db.CountByStatus(tracking.RetryStatusPending)
	retrying, _ := db.CountByStatus(tracking.RetryStatusRetrying)
	completed, _ := db.CountByStatus(tracking.RetryStatusCompleted)
	failed, _ := db.CountByStatus(tracking.RetryStatusFailed)

	fmt.Printf("ER1 Retry Queue Status:\n")
	fmt.Printf("  pending:   %d\n", pending)
	fmt.Printf("  retrying:  %d\n", retrying)
	fmt.Printf("  completed: %d\n", completed)
	fmt.Printf("  failed:    %d\n", failed)
	fmt.Printf("  total:     %d\n", pending+retrying+completed+failed)

	entries, err := db.ListAll(100)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing entries: %v\n", err)
		os.Exit(1)
	}

	if len(entries) > 0 {
		fmt.Printf("\nEntries:\n")
		for _, e := range entries {
			fmt.Printf("  %-20s  status=%-10s  attempts=%d/%d", e.EntryID, e.Status, e.Attempts, e.MaxAttempts)
			if e.LastError != "" {
				fmt.Printf("  error=%q", e.LastError)
			}
			fmt.Println()
		}
	}
}

func printRetryEntry(e *tracking.RetryEntry) {
	fmt.Printf("Entry: %s\n", e.EntryID)
	fmt.Printf("  status:       %s\n", e.Status)
	fmt.Printf("  attempts:     %d/%d\n", e.Attempts, e.MaxAttempts)
	fmt.Printf("  transcript:   %s\n", e.TranscriptPath)
	if e.AudioPath != "" {
		fmt.Printf("  audio:        %s\n", e.AudioPath)
	}
	if e.ImagePath != "" {
		fmt.Printf("  image:        %s\n", e.ImagePath)
	}
	if e.Tags != "" {
		fmt.Printf("  tags:         %s\n", e.Tags)
	}
	if e.LastError != "" {
		fmt.Printf("  last_error:   %s\n", e.LastError)
	}
	fmt.Printf("  created_at:   %s\n", e.CreatedAt.Format(time.RFC3339))
	fmt.Printf("  updated_at:   %s\n", e.UpdatedAt.Format(time.RFC3339))
	fmt.Printf("  next_retry:   %s\n", e.NextRetryAt.Format(time.RFC3339))
}

// -- cancel command --

func cmdCancel(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: m3c-tools cancel <entry_id> [--db <path>]")
		os.Exit(1)
	}
	entryID := args[0]
	dbPath := defaultExportsDBPath()

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--db":
			if i+1 < len(args) {
				dbPath = args[i+1]
				i++
			}
		}
	}

	db, err := tracking.OpenRetryQueueDB(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening DB: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// Check entry exists
	entry, err := db.GetByEntryID(entryID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if entry == nil {
		fmt.Fprintf(os.Stderr, "Entry not found: %s\n", entryID)
		os.Exit(1)
	}
	if entry.Status == tracking.RetryStatusCompleted {
		fmt.Fprintf(os.Stderr, "Entry %s is already completed\n", entryID)
		os.Exit(1)
	}

	err = db.SetStatus(entryID, "cancelled")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error cancelling: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Cancelled entry: %s\n", entryID)
}

// -- screenshot command --

func cmdScreenshot(args []string) {
	mode := screenshot.FullScreen
	outputDir := "."
	filename := ""
	silent := false
	hideCursor := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--mode":
			if i+1 < len(args) {
				switch args[i+1] {
				case "full":
					mode = screenshot.FullScreen
				case "window":
					mode = screenshot.Window
				case "region":
					mode = screenshot.Region
				default:
					fmt.Fprintf(os.Stderr, "Unknown mode: %s (use full, window, region)\n", args[i+1])
					os.Exit(1)
				}
				i++
			}
		case "--output":
			if i+1 < len(args) {
				outputDir = args[i+1]
				i++
			}
		case "--filename":
			if i+1 < len(args) {
				filename = args[i+1]
				i++
			}
		case "--silent":
			silent = true
		case "--hide-cursor":
			hideCursor = true
		}
	}

	opts := screenshot.Options{
		Mode:       mode,
		OutputDir:  outputDir,
		Filename:   filename,
		HideCursor: hideCursor,
		Silent:     silent,
	}

	fmt.Println("Capturing screenshot...")
	path, err := screenshot.Capture(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Screenshot error: %v\n", err)
		os.Exit(1)
	}

	info, _ := os.Stat(path)
	fmt.Printf("Screenshot saved: %s (%d bytes)\n", path, info.Size())
}

// -- import-audio command --

func cmdImportAudio(args []string) {
	showExtensions := false
	compact := false
	runPipeline := false
	dbPath := defaultFilesDBPath()
	dir := ""

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--run":
			runPipeline = true
		case "--extensions":
			showExtensions = true
		case "--compact":
			compact = true
		case "--db":
			if i+1 < len(args) {
				dbPath = args[i+1]
				i++
			}
		default:
			if !strings.HasPrefix(args[i], "--") {
				dir = args[i]
			}
		}
	}

	if showExtensions {
		exts := importer.ExtensionList()
		fmt.Printf("Supported audio extensions (%d):\n", len(exts))
		for _, ext := range exts {
			fmt.Printf("  %s\n", ext)
		}
		return
	}

	// If no directory argument, fall back to IMPORT_AUDIO_SOURCE env var
	if dir == "" {
		envDir := os.Getenv("IMPORT_AUDIO_SOURCE")
		if envDir == "" {
			fmt.Fprintln(os.Stderr, "Usage: m3c-tools import-audio <directory> [--run] [--extensions] [--compact] [--db <path>]")
			fmt.Fprintln(os.Stderr, "  Or set IMPORT_AUDIO_SOURCE environment variable")
			os.Exit(1)
		}
		dir = envDir
		fmt.Printf("Using IMPORT_AUDIO_SOURCE=%s\n", dir)
	}

	// Expand ~ in directory path
	if strings.HasPrefix(dir, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			dir = filepath.Join(home, dir[2:])
		}
	}

	if runPipeline {
		summary, err := runAudioImportPipeline(dir, dbPath, "", nil, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Import pipeline failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Import pipeline complete: imported=%d uploaded=%d failed=%d\n",
			summary.Imported, summary.Uploaded, summary.Failed)
		return
	}

	fmt.Printf("Scanning %s for audio files...\n", dir)
	result, err := importer.ScanDir(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Scan error: %v\n", err)
		os.Exit(1)
	}

	if result.TotalFound == 0 {
		fmt.Println("No audio files found.")
		return
	}

	// Build status checker using tracking DB (best-effort: if DB unavailable, all files show as "new").
	// StatusCheckerFromDB handles nil DB gracefully (returns StatusNew for all files).
	filesDB, dbErr := tracking.OpenFilesDB(dbPath)
	if dbErr != nil {
		filesDB = nil // graceful degradation: all files appear as "new"
	} else {
		defer filesDB.Close()
	}
	checker := importer.StatusCheckerFromDB(filesDB, "audio")

	entries, err := importer.BuildFileEntries(result, checker)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error checking file status: %v\n", err)
		os.Exit(1)
	}

	if compact {
		fmt.Print(importer.FormatScanOutputCompact(entries))
	} else {
		fmt.Print(importer.FormatScanOutput(entries, result.ScannedDir))
	}
}

type audioImportRunSummary struct {
	Scanned  int
	Imported int
	Uploaded int
	Failed   int
}

func runAudioImportPipeline(sourceDir, dbPath, onlySourcePath string, app *menubar.App, onProgress func(menubar.BulkProgressEvent)) (*audioImportRunSummary, error) {
	cfg, err := importer.LoadImportConfig()
	if err != nil {
		return nil, fmt.Errorf("load import config: %w", err)
	}
	if sourceDir != "" {
		cfg.AudioSource = sourceDir
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	filesDB, err := tracking.OpenFilesDB(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open tracking db: %w", err)
	}
	defer filesDB.Close()

	normalizedOnly := strings.TrimSpace(onlySourcePath)

	result, err := importer.ImportAudioFiltered(cfg, filesDB, nil, normalizedOnly)
	if err != nil {
		return nil, fmt.Errorf("import audio: %w", err)
	}

	summary := &audioImportRunSummary{
		Scanned:  result.TotalScanned,
		Imported: len(result.Imported),
		Failed:   len(result.Failed),
	}
	if len(result.Imported) == 0 {
		return summary, nil
	}

	er1Cfg := er1.LoadConfig()
	applyRuntimeER1Context(er1Cfg)
	totalItems := len(result.Imported)
	processedItems := 0

	for _, imp := range result.Imported {
		processedItems++
		if onProgress != nil {
			onProgress(menubar.BulkProgressEvent{
				Event:       "ITEM_START",
				Item:        filepath.Base(imp.Source),
				Index:       processedItems,
				Total:       totalItems,
				CurrentFile: filepath.Base(imp.Source),
				Phase:       menubar.BulkPhaseQueued,
			})
		}
		if onProgress != nil {
			onProgress(menubar.BulkProgressEvent{
				Event:       "ITEM_PHASE",
				Item:        filepath.Base(imp.Source),
				Index:       processedItems,
				Total:       totalItems,
				Phase:       menubar.BulkPhaseImport,
				CurrentFile: filepath.Base(imp.Source),
			})
		}
		if app != nil {
			app.SetStatus(menubar.StatusUploading)
		}

		audioData, readErr := os.ReadFile(imp.Dest)
		if readErr != nil {
			summary.Failed++
			_ = filesDB.UpdateStatus(imp.Hash, "audio", "failed")
			log.Printf("[import] failed reading imported audio: %s error=%v", imp.Dest, readErr)
			if onProgress != nil {
				onProgress(menubar.BulkProgressEvent{
					Event:       "ITEM_DONE",
					Item:        filepath.Base(imp.Source),
					Index:       processedItems,
					Total:       totalItems,
					Outcome:     "failed",
					Error:       readErr.Error(),
					Done:        processedItems,
					Success:     summary.Uploaded,
					Failed:      summary.Failed,
					CurrentFile: filepath.Base(imp.Source),
					Phase:       menubar.BulkPhaseFailed,
				})
			}
			continue
		}

		model := menubarWhisperModel()
		lang := menubarWhisperLanguage()
		timeout := menubarWhisperTimeout()
		if onProgress != nil {
			onProgress(menubar.BulkProgressEvent{
				Event:       "ITEM_PHASE",
				Item:        filepath.Base(imp.Source),
				Index:       processedItems,
				Total:       totalItems,
				Phase:       menubar.BulkPhaseTranscribe,
				CurrentFile: filepath.Base(imp.Source),
			})
		}
		log.Printf("[import] whisper START source=%s model=%s language=%s", imp.Source, model, lang)
		text, txErr := whisper.TranscribeTextWithTimeout(imp.Dest, model, lang, timeout)
		if txErr != nil {
			text = fmt.Sprintf("[Transcription failed: %v]", txErr)
			log.Printf("[import] whisper FAIL source=%s error=%v", imp.Source, txErr)
		} else {
			log.Printf("[import] whisper DONE source=%s chars=%d", imp.Source, len(text))
		}

		// Record transcript details in DB.
		_ = filesDB.RecordTranscript(imp.Hash, "audio", strings.TrimSpace(text), lang)

		now := time.Now()
		doc := (&impression.CompositeDoc{
			ObsType:        impression.Import,
			Timestamp:      now,
			TranscriptText: strings.TrimSpace(text),
			ImpressionText: fmt.Sprintf("Imported audio file: %s\nSource: %s\nTags: %s", filepath.Base(imp.Dest), imp.Source, imp.Tags),
		}).Build()

		payload := &er1.UploadPayload{
			TranscriptData:     []byte(strings.TrimSpace(doc) + "\n"),
			TranscriptFilename: fmt.Sprintf("import_%s.txt", now.Format("20060102_150405")),
			AudioData:          audioData,
			AudioFilename:      filepath.Base(imp.Dest),
			ImageData:          nil, // Upload layer injects app-logo placeholder for audio-import.
			ImageFilename:      "placeholder-logo.png",
			Tags:               imp.Tags,
			ContentType:        cfg.ContentType,
		}

		if onProgress != nil {
			onProgress(menubar.BulkProgressEvent{
				Event:       "ITEM_PHASE",
				Item:        filepath.Base(imp.Source),
				Index:       processedItems,
				Total:       totalItems,
				Phase:       menubar.BulkPhaseUpload,
				CurrentFile: filepath.Base(imp.Source),
			})
		}
		resp, upErr := er1.Upload(er1Cfg, payload)
		if upErr != nil {
			summary.Failed++
			_ = filesDB.RecordUploadError(imp.Hash, "audio", upErr.Error())
			_, _ = er1.HandleUploadFailure(er1.DefaultQueuePath(), er1.DefaultMemoryPath(), imp.MemoryID, payload, imp.Tags, upErr)
			log.Printf("[import] upload FAIL source=%s error=%v", imp.Source, upErr)
			if onProgress != nil {
				onProgress(menubar.BulkProgressEvent{
					Event:       "ITEM_DONE",
					Item:        filepath.Base(imp.Source),
					Index:       processedItems,
					Total:       totalItems,
					Outcome:     "failed",
					Error:       upErr.Error(),
					Done:        processedItems,
					Success:     summary.Uploaded,
					Failed:      summary.Failed,
					CurrentFile: filepath.Base(imp.Source),
					Phase:       menubar.BulkPhaseFailed,
				})
			}
			continue
		}

		summary.Uploaded++
		_ = filesDB.RecordUploadSuccess(imp.Hash, "audio", resp.DocID)
		log.Printf("[import] upload DONE source=%s doc_id=%s", imp.Source, resp.DocID)

		// Reverse time tracking: record observation and create inferred time block (REQ-9/10).
		if reverseTracker != nil && imp.Tags != "" {
			if rtErr := reverseTracker.RecordAndProcess(now, imp.Tags, resp.DocID, "import"); rtErr != nil {
				log.Printf("[reverse-tracking] import observation failed: %v", rtErr)
			}
		}
		if onProgress != nil {
			onProgress(menubar.BulkProgressEvent{
				Event:       "ITEM_DONE",
				Item:        filepath.Base(imp.Source),
				Index:       processedItems,
				Total:       totalItems,
				Outcome:     "ok",
				Done:        processedItems,
				Success:     summary.Uploaded,
				Failed:      summary.Failed,
				CurrentFile: filepath.Base(imp.Source),
				Phase:       menubar.BulkPhaseDone,
			})
		}
	}

	if app != nil {
		app.SetStatus(menubar.StatusIdle)
	}
	return summary, nil
}

// reprocessAudioFile re-transcribes and re-uploads an already-tracked file.
// If the file has an existing doc_id, it passes it to ER1 for overwrite;
// otherwise a fresh document is created. The DB record is updated in place.
func reprocessAudioFile(srcPath, dbPath string, app *menubar.App, onProgress func(menubar.BulkProgressEvent)) error {
	cfg, err := importer.LoadImportConfig()
	if err != nil {
		return fmt.Errorf("load import config: %w", err)
	}

	filesDB, err := tracking.OpenFilesDB(dbPath)
	if err != nil {
		return fmt.Errorf("open tracking db: %w", err)
	}
	defer filesDB.Close()

	absPath, _ := filepath.Abs(strings.TrimSpace(srcPath))
	info, err := os.Stat(absPath)
	if err != nil {
		return fmt.Errorf("file not found: %s", srcPath)
	}
	if onProgress != nil {
		onProgress(menubar.BulkProgressEvent{
			Event:       "ITEM_PHASE",
			Item:        info.Name(),
			Phase:       menubar.BulkPhaseReprocess,
			CurrentFile: info.Name(),
		})
	}

	// Look up existing DB record by path.
	existing, _ := filesDB.GetByPath(absPath)
	existingDocID := ""
	existingHash := ""
	if existing != nil {
		existingDocID = existing.UploadDocID
		existingHash = existing.FileHash
		log.Printf("[reprocess] found existing record: hash=%s doc_id=%q status=%s",
			existingHash[:min(12, len(existingHash))], existingDocID, existing.Status)
	}

	// Compute hash of source file.
	hash, err := tracking.HashFile(absPath)
	if err != nil {
		return fmt.Errorf("hash file: %w", err)
	}

	// Resolve destination directory.
	destDir, err := cfg.DestDir()
	if err != nil {
		return fmt.Errorf("resolve dest: %w", err)
	}
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("create dest dir: %w", err)
	}

	// Create a new MEMORY folder and copy the file.
	now := time.Now()
	memoryID := fmt.Sprintf("MEMORY-%s", now.Format("20060102-150405"))
	memoryPath := filepath.Join(destDir, memoryID)
	for i := 1; ; i++ {
		if _, statErr := os.Stat(memoryPath); os.IsNotExist(statErr) {
			break
		}
		memoryID = fmt.Sprintf("MEMORY-%s-%d", now.Format("20060102-150405"), i)
		memoryPath = filepath.Join(destDir, memoryID)
		if i > 100 {
			return fmt.Errorf("could not create unique MEMORY folder")
		}
	}
	if err := os.MkdirAll(memoryPath, 0755); err != nil {
		return fmt.Errorf("create memory folder: %w", err)
	}

	destFile := filepath.Join(memoryPath, info.Name())
	srcF, err := os.Open(absPath)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	dstF, err := os.Create(destFile)
	if err != nil {
		_ = srcF.Close()
		return fmt.Errorf("create dest: %w", err)
	}
	_, cpErr := io.Copy(dstF, srcF)
	_ = srcF.Close()
	_ = dstF.Close()
	if cpErr != nil {
		return fmt.Errorf("copy file: %w", cpErr)
	}

	// Ensure a DB record exists for this file (upsert).
	if existing == nil {
		// No existing record — create one.
		if _, recErr := filesDB.RecordFile(absPath, hash, info.Size(), "audio", memoryID); recErr != nil {
			return fmt.Errorf("record file: %w", recErr)
		}
		existingHash = hash
	}

	// Update status to indicate re-processing.
	_ = filesDB.UpdateStatus(existingHash, "audio", "imported")

	if app != nil {
		app.SetStatus(menubar.StatusUploading)
	}

	// Read the copied file for whisper + upload.
	audioData, err := os.ReadFile(destFile)
	if err != nil {
		return fmt.Errorf("read audio: %w", err)
	}

	// Transcribe via whisper.
	model := menubarWhisperModel()
	lang := menubarWhisperLanguage()
	timeout := menubarWhisperTimeout()
	if onProgress != nil {
		onProgress(menubar.BulkProgressEvent{
			Event:       "ITEM_PHASE",
			Item:        info.Name(),
			Phase:       menubar.BulkPhaseTranscribe,
			CurrentFile: info.Name(),
		})
	}
	log.Printf("[reprocess] whisper START source=%s model=%s language=%s", info.Name(), model, lang)
	text, txErr := whisper.TranscribeTextWithTimeout(destFile, model, lang, timeout)
	if txErr != nil {
		log.Printf("[reprocess] whisper FAIL source=%s error=%v", info.Name(), txErr)
		_ = filesDB.UpdateStatus(existingHash, "audio", "whisper-error")
		if app != nil {
			app.SetStatus(menubar.StatusIdle)
		}
		return fmt.Errorf("whisper: %w", txErr)
	}
	log.Printf("[reprocess] whisper DONE source=%s chars=%d", info.Name(), len(text))

	_ = filesDB.RecordTranscript(existingHash, "audio", strings.TrimSpace(text), lang)

	// Build upload payload.
	parsedInfo := impression.ParseFilename(info.Name())
	tags := impression.BuildImportTags(parsedInfo.Tags)

	doc := (&impression.CompositeDoc{
		ObsType:        impression.Import,
		Timestamp:      now,
		TranscriptText: strings.TrimSpace(text),
		ImpressionText: fmt.Sprintf("Re-processed audio file: %s\nSource: %s\nTags: %s", info.Name(), absPath, tags),
	}).Build()

	er1Cfg := er1.LoadConfig()
	applyRuntimeER1Context(er1Cfg)

	payload := &er1.UploadPayload{
		TranscriptData:     []byte(strings.TrimSpace(doc) + "\n"),
		TranscriptFilename: fmt.Sprintf("reprocess_%s.txt", now.Format("20060102_150405")),
		AudioData:          audioData,
		AudioFilename:      info.Name(),
		Tags:               tags,
		ContentType:        cfg.ContentType,
		DocID:              existingDocID, // Reuse existing doc_id if available.
	}

	if existingDocID != "" {
		log.Printf("[reprocess] upload START reusing doc_id=%s", existingDocID)
	} else {
		log.Printf("[reprocess] upload START (new document)")
	}
	if onProgress != nil {
		onProgress(menubar.BulkProgressEvent{
			Event:       "ITEM_PHASE",
			Item:        info.Name(),
			Phase:       menubar.BulkPhaseUpload,
			CurrentFile: info.Name(),
		})
	}

	resp, upErr := er1.Upload(er1Cfg, payload)
	if upErr != nil {
		_ = filesDB.RecordUploadError(existingHash, "audio", upErr.Error())
		if app != nil {
			app.SetStatus(menubar.StatusIdle)
		}
		return fmt.Errorf("upload: %w", upErr)
	}

	_ = filesDB.RecordUploadSuccess(existingHash, "audio", resp.DocID)
	log.Printf("[reprocess] upload DONE source=%s doc_id=%s", info.Name(), resp.DocID)

	// Reverse time tracking: record observation and create inferred time block (REQ-9/10).
	if reverseTracker != nil && tags != "" {
		if rtErr := reverseTracker.RecordAndProcess(now, tags, resp.DocID, "import"); rtErr != nil {
			log.Printf("[reverse-tracking] reprocess observation failed: %v", rtErr)
		}
	}

	if app != nil {
		app.SetStatus(menubar.StatusIdle)
	}
	return nil
}

func defaultFilesDBPath() string {
	dir := filepath.Join(os.Getenv("HOME"), ".m3c-tools")
	os.MkdirAll(dir, 0755)
	return filepath.Join(dir, "tracking.db")
}

// -- menubar command --

func cmdMenubar(args []string) {
	cfg := menubar.DefaultConfig()
	verbose := true // default ON during hardening (BUG-0003)

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--title":
			if i+1 < len(args) {
				cfg.Title = args[i+1]
				i++
			}
		case "--icon":
			if i+1 < len(args) {
				cfg.IconPath = args[i+1]
				i++
			}
		case "--log":
			if i+1 < len(args) {
				cfg.LogPath = args[i+1]
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

	// Open log file for writing so "Open Log File" has something to show.
	// Ensure log directory exists
	if logDir := filepath.Dir(cfg.LogPath); logDir != "" && logDir != "." {
		os.MkdirAll(logDir, 0700)
	}
	logFile, err := os.OpenFile(cfg.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: cannot open log file %s: %v\n", cfg.LogPath, err)
	} else {
		if verbose {
			log.SetOutput(io.MultiWriter(logFile, os.Stderr))
		} else {
			log.SetOutput(logFile)
		}
		log.SetFlags(log.Ldate | log.Ltime)
	}

	// Fix 3 (BUG-0003): Print log file path on startup so user knows where to look.
	fmt.Fprintf(os.Stderr, "m3c-tools menubar started. Logs: %s\n", cfg.LogPath)

	// Check whisper availability at startup.
	if whisperPath, err := whisper.FindBinary(); err != nil {
		log.Printf("[startup] WARNING: whisper not found — voice transcription unavailable")
		log.Printf("[startup] Run 'm3c-tools setup' to install whisper in a dedicated venv")
		fmt.Fprintf(os.Stderr, "Warning: whisper not found. Run 'm3c-tools setup' to install.\n")
	} else {
		log.Printf("[startup] whisper found: %s", whisperPath)
	}

	// Create transcript fetcher for the Fetch Transcript menu item.
	fetcher := menubar.NewTranscriptFetcher()

	app := menubar.NewAppWithConfig(cfg, menubar.Handlers{
		OnUploadER1: menubarUploadER1,
		ListTrackingRecords: func(limit int) ([]menubar.TrackingRecord, error) {
			db, err := tracking.OpenFilesDB(defaultFilesDBPath())
			if err != nil {
				return nil, err
			}
			defer db.Close()
			files, err := db.ListFiles(limit)
			if err != nil {
				return nil, err
			}
			records := make([]menubar.TrackingRecord, len(files))
			for i, f := range files {
				records[i] = menubar.TrackingRecord{
					FileName:       filepath.Base(f.FilePath),
					Status:         f.Status,
					TranscriptLen:  f.TranscriptLen,
					TranscriptLang: f.TranscriptLang,
					UploadDocID:    f.UploadDocID,
					UploadError:    f.UploadError,
					ProcessedAt:    f.ProcessedAt.Format("2006-01-02 15:04"),
				}
			}
			return records, nil
		},
	})
	app.SetAuthSession(menubar.AuthSession{})
	startAudioImportListRefresher(app)
	if ctxID, err := loadPersistedER1Session(); err != nil {
		log.Printf("[auth] persisted session load failed: %v", err)
	} else if ctxID != "" {
		setRuntimeER1Login(ctxID)
		app.SetAuthSession(menubar.AuthSession{LoggedIn: true, UserID: ctxID})
		log.Printf("[auth] restored persisted session context_id=%s", truncateForLog(ctxID, 64))
	}
	menubar.StartFrontmostAppTracker()
	if exe, err := os.Executable(); err == nil {
		log.Printf("[diag] pid=%d exe=%q screen_access=%v screenshot_mode=%s", os.Getpid(), exe, menubar.HasScreenCaptureAccess(), screenshotCaptureMode())
	}
	maybePreloadWhisper()

	// --- Time Tracking Engine ---
	ttStore, ttErr := timetracking.OpenStore(timetracking.DefaultDBPath())
	var ttEngine *timetracking.Engine
	var ttSyncer *timetracking.Syncer
	if ttErr != nil {
		log.Printf("[timetracking] store open failed: %v — time tracking disabled", ttErr)
	} else {
		ttEngine = timetracking.NewEngine(ttStore, func(title, msg string) {
			app.Notify(title, msg)
		})
		app.SetTimeEngine(ttEngine)

		// Recover orphaned contexts from any prior crash.
		if err := ttEngine.RecoverOrphanedContexts(); err != nil {
			log.Printf("[timetracking] crash recovery: %v", err)
		}

		// Start ER1 sync if API key is configured.
		// M3C_PLM_BASE_URL overrides the base derived from ER1_API_URL,
		// allowing uploads to go to a local server while PLM queries hit production.
		er1Cfg := er1.LoadConfig()
		plmBase := os.Getenv("M3C_PLM_BASE_URL")
		if plmBase == "" {
			plmBase = er1BaseURL(er1Cfg.APIURL)
		}
		if plmBase != "" && er1Cfg.APIKey != "" {
			log.Printf("[timetracking] PLM connection: base=%s context=%s ssl=%v",
				plmBase, truncateForLog(er1Cfg.ContextID, 32), er1Cfg.VerifySSL)
			// Strip ___mft suffix from context ID — PLM uses the raw Google UID.
			plmContextID := er1Cfg.ContextID
			if idx := strings.Index(plmContextID, "___"); idx > 0 {
				plmContextID = plmContextID[:idx]
			}
			plmClient := timetracking.NewPLMClient(timetracking.PLMConfig{
				BaseURL:   plmBase,
				APIKey:    er1Cfg.APIKey,
				ContextID: plmContextID,
				VerifySSL: er1Cfg.VerifySSL,
			})
			ttSyncer = timetracking.NewSyncer(ttStore, plmClient, 30*time.Second)
			ttSyncer.Start()
			log.Printf("[timetracking] syncer started (interval=30s)")

			// Start project list refresher.
			startTimeTrackingProjectRefresher(plmClient, ttStore)
		} else {
			log.Printf("[timetracking] PLM sync disabled (base=%q key_set=%v)", plmBase, er1Cfg.APIKey != "")
		}

		log.Printf("[timetracking] engine ready db=%s", timetracking.DefaultDBPath())

		// Create reverse tracker for observation-inferred time blocks (REQ-9).
		reverseTracker = timetracking.NewReverseTracker(ttStore)
		log.Printf("[timetracking] reverse tracker ready (enabled=%v)", reverseTracker != nil)

		// Wire Gantt chart Time Tracker window.
		var ganttViewMode int // 0=week, 1=month
		var ganttOffset int

		showGantt := func(viewMode, offset int) {
			ganttViewMode = viewMode
			ganttOffset = offset

			now := time.Now()
			var from, to time.Time
			if viewMode == 0 {
				from, to = timetracking.WeekBounds(now, offset)
			} else {
				from, to = timetracking.MonthBounds(now, offset)
			}

			// Backfill reverse tracking for the viewed period (REQ-10).
			if reverseTracker != nil {
				if n, bfErr := reverseTracker.BackfillPeriod(from, to); bfErr != nil {
					log.Printf("[reverse-tracking] gantt backfill failed: %v", bfErr)
				} else if n > 0 {
					log.Printf("[reverse-tracking] gantt backfill: processed %d observations", n)
				}
			}

			events, err := ttStore.ListAllEvents(from, to)
			if err != nil {
				log.Printf("[timetracking] gantt: fetch events failed: %v", err)
				return
			}

			sessions := timetracking.ComputeSessions(events)

			// Build unique project list.
			type projInfo struct {
				name  string
				id    string
				total time.Duration
			}
			projMap := make(map[string]*projInfo)
			var projOrder []string

			for _, s := range sessions {
				if _, ok := projMap[s.ProjectID]; !ok {
					projMap[s.ProjectID] = &projInfo{name: s.ProjectName, id: s.ProjectID}
					projOrder = append(projOrder, s.ProjectID)
				}
				projMap[s.ProjectID].total += time.Duration(s.DurationSec) * time.Second
			}

			var data menubar.GanttData
			data.PeriodStart = float64(from.Unix())
			data.PeriodEnd = float64(to.Unix())
			data.ViewMode = viewMode

			if viewMode == 0 {
				_, cw := from.ISOWeek()
				data.PeriodLabel = fmt.Sprintf("CW %d: %s – %s",
					cw, from.Format("Jan 2"), to.AddDate(0, 0, -1).Format("Jan 2, 2006"))
			} else {
				data.PeriodLabel = from.Format("January 2006")
			}

			if viewMode == 0 {
				for d := 0; d < 7; d++ {
					day := from.AddDate(0, 0, d)
					data.DayLabels = append(data.DayLabels, day.Format("Mon 2"))
				}
			} else {
				daysInMonth := to.AddDate(0, 0, -1).Day()
				for d := 1; d <= daysInMonth; d++ {
					data.DayLabels = append(data.DayLabels, fmt.Sprintf("%d", d))
				}
			}

			projIdx := make(map[string]int)
			for i, pid := range projOrder {
				p := projMap[pid]
				r, g, b := timetracking.ProjectColor(pid)
				data.Projects = append(data.Projects, menubar.GanttProject{
					Name:   p.name,
					Total:  ganttFormatDuration(p.total),
					ColorR: r,
					ColorG: g,
					ColorB: b,
				})
				projIdx[pid] = i
			}

			for _, s := range sessions {
				idx, ok := projIdx[s.ProjectID]
				if !ok {
					continue
				}
				data.Sessions = append(data.Sessions, menubar.GanttSession{
					ProjectIndex: idx,
					Start:        float64(s.Start.Unix()),
					End:          float64(s.End.Unix()),
					IsActive:     s.IsActive,
					IsInferred:   s.Trigger == "observation_inferred",
				})
			}

			log.Printf("[timetracking] gantt: mode=%d offset=%d projects=%d sessions=%d period=%s",
				viewMode, offset, len(data.Projects), len(data.Sessions), data.PeriodLabel)
			menubar.ShowTimeTrackerWindow(data)
		}

		app.SetShowTimeTrackerFunc(func() {
			showGantt(ganttViewMode, ganttOffset)
		})

		menubar.SetGanttNavigateCallback(func(viewMode, offset int) {
			showGantt(viewMode, offset)
		})
	}

	// safeGo launches a goroutine with panic recovery (BUG-0003 Fix 2).
	// Any panic is logged and shown in the menu bar instead of crashing the process.
	safeGo := func(name string, fn func()) {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[PANIC] %s: %v\n%s", name, r, debug.Stack())
					app.Notify("Internal Error", fmt.Sprintf("%s crashed: %v", name, r))
				}
			}()
			fn()
		}()
	}

	// Wire OnAction to dispatch menu actions to real implementations.
	app.Handlers.OnAction = func(action menubar.ActionType, data string) {
		log.Printf("[menubar] action=%s data=%q", action, data)
		if actionBlockedDuringBulk(action) {
			if busy, state := ingestionOps.IsBusy(); busy {
				remaining := state.Total - state.Done
				if remaining < 0 {
					remaining = 0
				}
				msg := fmt.Sprintf("Bulk run active (%d/%d, %d remaining). Please wait.", state.Done, state.Total, remaining)
				app.Notify("Ingestion Busy", msg)
				app.SetLastImportMessage("⏳ " + msg)
				return
			}
		}
		switch action {
		case menubar.ActionFetchTranscript:
			safeGo("FetchTranscript", func() { menubarFetchTranscriptAndTrack(app, fetcher, data) })
		case menubar.ActionCaptureScreenshot:
			safeGo("CaptureScreenshot", func() { menubarCaptureScreenshot(app) })
		case menubar.ActionCopyTranscript:
			safeGo("CopyTranscript", func() { fetcher.FetchAndDisplay(app, data) })
		case menubar.ActionRecordImpression:
			safeGo("RecordImpression", func() { menubarRecordImpression(app, data) })
		case menubar.ActionQuickImpulse:
			safeGo("QuickImpulse", func() { menubarQuickImpulse(app) })
		case menubar.ActionBatchImport:
			safeGo("BatchImport", func() { menubarHandleBatchImportAction(app, data) })
		case menubar.ActionLoginER1:
			safeGo("LoginER1", func() { menubarLoginER1(app) })
		case menubar.ActionLogoutER1:
			safeGo("LogoutER1", func() { menubarLogoutER1(app) })
		case menubar.ActionShowTrackingDB:
			safeGo("ShowTrackingDB", func() { menubarShowTrackingDB() })
		case menubar.ActionPlaudSync:
			safeGo("PlaudSync", func() { menubarHandlePlaudSync(app) })
		case menubar.ActionStarGitHub:
			safeGo("StarGitHub", func() { openURL(menubar.GitHubRepoURL) })
		}
	}

	// Register bulk-action callback for tracking window buttons.
	menubar.SetTrackingBulkCallback(func(action string, filenames []string, statuses []string) {
		if busy, state := ingestionOps.IsBusy(); busy {
			remaining := state.Total - state.Done
			if remaining < 0 {
				remaining = 0
			}
			app.Notify("Ingestion Busy",
				fmt.Sprintf("Bulk run active (%d/%d, %d remaining). Please wait.", state.Done, state.Total, remaining))
			return
		}
		go runTrackingBulkAction(app, action, filenames, statuses)
		// Refresh the tracking window data after bulk ops.
		go menubarShowTrackingDB()
	})

	// Start background retry scheduler to auto-retry failed ER1 uploads every 5 minutes.
	bgRetryCfg := er1.LoadConfig()
	bgRetry := er1.StartBackgroundRetry(
		er1.DefaultQueuePath(), bgRetryCfg,
		5*time.Minute,
		bgRetryCfg.MaxRetries,
	)
	bgRetry.OnLog = func(msg string) {
		log.Printf("%s", msg)
	}
	log.Printf("[bg-retry] background retry scheduler started (interval=5m, max-retries=%d)", bgRetryCfg.MaxRetries)

	// Shutdown hook: stop retry scheduler, deactivate projects, stop syncer.
	app.OnShutdown(func() {
		bgRetry.Stop(5 * time.Second)
		log.Printf("[bg-retry] stopped")
		if ttEngine != nil {
			ttEngine.ShutdownAll()
		}
		if ttSyncer != nil {
			ttSyncer.Stop(5 * time.Second)
		}
		if ttStore != nil {
			ttStore.Close()
		}
		log.Printf("[timetracking] shutdown complete")
	})

	// Handle SIGINT/SIGTERM to run shutdown callbacks before exit.
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Printf("[menubar] signal received, running shutdown hooks")
		app.RunShutdown()
		os.Exit(0)
	}()

	log.Printf("Launching menu bar app (title=%q, icon=%q, log=%q)", cfg.Title, cfg.IconPath, cfg.LogPath)
	app.Run()
}

// startTimeTrackingProjectRefresher fetches the PLM project list periodically
// and updates the menubar cache and time tracking store (for reverse tracking tag matching).
func startTimeTrackingProjectRefresher(plmClient *timetracking.PLMClient, ttStore *timetracking.Store) {
	refresh := func() {
		projects, err := plmClient.FetchProjects()
		if err != nil {
			log.Printf("[timetracking] project refresh failed: %v", err)
			return
		}
		var ttProjects []menubar.TimeTrackingProject
		var cacheProjects []timetracking.CachedProject
		for _, p := range projects {
			ttProjects = append(ttProjects, menubar.TimeTrackingProject{
				ID:     p.ID,
				Name:   p.Name,
				Client: p.Client,
			})
			updatedAt, _ := time.Parse(time.RFC3339, p.UpdatedAt)
			cacheProjects = append(cacheProjects, timetracking.CachedProject{
				ProjectID: p.ID,
				Name:      p.Name,
				Client:    p.Client,
				Status:    p.Status,
				Tags:      strings.Join(p.Tags, ","),
				UpdatedAt: updatedAt,
			})
		}
		menubar.SetTimeTrackingProjects(ttProjects)
		if err := ttStore.UpsertProjects(cacheProjects); err != nil {
			log.Printf("[timetracking] project cache update failed: %v", err)
		}
		for i, p := range ttProjects {
			client := ""
			if p.Client != "" {
				client = " (" + p.Client + ")"
			}
			log.Printf("[timetracking]   [%d] %s%s id=%s", i+1, p.Name, client, p.ID)
		}
		log.Printf("[timetracking] refreshed %d projects (cached with tags)", len(ttProjects))
	}
	go func() {
		refresh()

		// Backfill reverse tracking for current month after first project cache (REQ-10).
		if reverseTracker != nil {
			now := time.Now()
			monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
			monthEnd := monthStart.AddDate(0, 1, 0)
			n, err := reverseTracker.BackfillPeriod(monthStart, monthEnd)
			if err != nil {
				log.Printf("[reverse-tracking] startup backfill failed: %v", err)
			} else if n > 0 {
				log.Printf("[reverse-tracking] startup backfill: processed %d observations for %s", n, now.Format("January 2006"))
			}
		}

		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			refresh()
		}
	}()
}

func startAudioImportListRefresher(app *menubar.App) {
	refresh := func() {
		state := buildAudioImportState()
		app.SetAudioImportState(state)
	}
	refresh()
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			refresh()
		}
	}()
}

func buildAudioImportState() menubar.AudioImportState {
	state := menubar.AudioImportState{
		UpdatedAt: time.Now(),
	}
	cfg, err := importer.LoadImportConfig()
	if err != nil {
		state.Error = "import config error"
		log.Printf("[import] menu refresh config error: %v", err)
		return state
	}
	if strings.TrimSpace(cfg.AudioSource) == "" {
		state.Error = "IMPORT_AUDIO_SOURCE not set"
		return state
	}

	filesDB, dbErr := tracking.OpenFilesDB(defaultFilesDBPath())
	if dbErr != nil {
		log.Printf("[import] menu refresh tracking db unavailable: %v", dbErr)
	}
	if filesDB != nil {
		defer filesDB.Close()
	}

	scan, scanErr := importer.ScanDir(cfg.AudioSource)
	if scanErr != nil {
		state.Error = "scan failed"
		log.Printf("[import] menu refresh scan error: %v", scanErr)
		return state
	}

	checker := importer.StatusCheckerFromDB(filesDB, "audio")
	entries, entriesErr := importer.BuildFileEntries(scan, checker)
	if entriesErr != nil {
		state.Error = "status build failed"
		log.Printf("[import] menu refresh status error: %v", entriesErr)
		return state
	}

	for _, e := range entries {
		state.Items = append(state.Items, menubar.AudioImportItem{
			Path:   e.File.Path,
			Name:   e.File.Name,
			Status: string(e.Status),
			Size:   e.File.Size,
			Tags:   strings.Join(e.Tags, ","),
		})
	}
	return state
}

func menubarHandleBatchImportAction(app *menubar.App, data string) {
	if busy, state := ingestionOps.IsBusy(); busy {
		remaining := state.Total - state.Done
		if remaining < 0 {
			remaining = 0
		}
		msg := fmt.Sprintf("Bulk run active (%d/%d, %d remaining). Please wait.", state.Done, state.Total, remaining)
		app.Notify("Ingestion Busy", msg)
		app.SetLastImportMessage("⏳ " + msg)
		return
	}

	switch strings.TrimSpace(data) {
	case "__refresh__":
		log.Printf("[import] refreshing audio import list...")
		app.SetAudioImportState(buildAudioImportState())
		log.Printf("[import] list refreshed")
		app.Notify("Audio Import", "List refreshed.")
		return
	case "__run_all__", "":
		log.Printf("[import] starting batch import (all new files)...")
		totalNew := 0
		for _, it := range app.GetAudioImportState().Items {
			if strings.EqualFold(strings.TrimSpace(it.Status), "new") {
				totalNew++
			}
		}
		startedAt := time.Now()
		runID := startedAt.Format("20060102-150405.000")
		startState := menubar.BulkRunState{
			Active:    true,
			RunID:     runID,
			Action:    "menu_import_all",
			Total:     totalNew,
			StartedAt: startedAt,
			Phase:     menubar.BulkPhaseQueued,
		}
		if !ingestionOps.TryStart("menu_import_all", startState) {
			if busy, state := ingestionOps.IsBusy(); busy {
				remaining := state.Total - state.Done
				if remaining < 0 {
					remaining = 0
				}
				msg := fmt.Sprintf("Bulk run active (%d/%d, %d remaining). Please wait.", state.Done, state.Total, remaining)
				app.Notify("Ingestion Busy", msg)
				app.SetLastImportMessage("⏳ " + msg)
			}
			return
		}
		app.SetBulkRunState(startState)
		menubar.SetTrackingBulkProgress(startState)
		app.SetLastImportMessage("⏳ Importing…")
		app.SetStatus(menubar.StatusUploading)

		onProgress := func(evt menubar.BulkProgressEvent) {
			state := app.GetBulkRunState()
			if state.RunID != runID {
				state = startState
			}
			if evt.Total > 0 {
				state.Total = evt.Total
			}
			if evt.CurrentFile != "" {
				state.CurrentFile = evt.CurrentFile
			}
			if evt.Phase != "" {
				state.Phase = evt.Phase
			}
			if evt.Event == "ITEM_DONE" {
				state.Done = evt.Done
				state.Success = evt.Success
				state.Failed = evt.Failed
				if evt.Error != "" {
					state.LastError = evt.Error
				}
			}
			state.Active = true
			ingestionOps.Update(state)
			app.SetBulkRunState(state)
			menubar.SetTrackingBulkProgress(state)
		}

		summary, err := runAudioImportPipeline("", defaultFilesDBPath(), "", app, onProgress)
		if err != nil {
			log.Printf("[import] batch import FAILED: %v", err)
			final := app.GetBulkRunState()
			final.Active = false
			final.Phase = menubar.BulkPhaseFailed
			final.LastError = err.Error()
			ingestionOps.Finish(final)
			app.SetBulkRunState(final)
			menubar.SetTrackingBulkProgress(final)
			app.SetLastImportMessage("❌ " + err.Error())
			app.SetStatus(menubar.StatusError)
			app.Notify("Audio Import Failed", err.Error())
			app.SetAudioImportState(buildAudioImportState())
			return
		}
		final := app.GetBulkRunState()
		final.Active = false
		final.Done = summary.Imported
		final.Success = summary.Uploaded
		final.Failed = summary.Failed
		if final.Total == 0 {
			final.Total = summary.Imported
		}
		if final.Failed > 0 {
			final.Phase = menubar.BulkPhaseFailed
		} else {
			final.Phase = menubar.BulkPhaseDone
		}
		ingestionOps.Finish(final)
		app.SetBulkRunState(final)
		menubar.SetTrackingBulkProgress(final)
		msg := fmt.Sprintf("✅ Imported=%d Uploaded=%d Failed=%d", summary.Imported, summary.Uploaded, summary.Failed)
		log.Printf("[import] batch import DONE: %s", msg)
		app.SetLastImportMessage(msg)
		app.SetStatus(menubar.StatusIdle)
		app.Notify("Audio Import", msg)
		app.SetAudioImportState(buildAudioImportState())
		return
	default:
		log.Printf("[import] single-file import START: %s", data)
		app.SetLastImportMessage("⏳ Importing " + filepath.Base(data) + "…")
		app.SetStatus(menubar.StatusUploading)
		summary, err := runAudioImportPipeline("", defaultFilesDBPath(), data, app, nil)
		if err != nil {
			log.Printf("[import] single-file import FAILED: %s error=%v", data, err)
			app.SetLastImportMessage("❌ " + filepath.Base(data) + ": " + err.Error())
			app.SetStatus(menubar.StatusError)
			app.Notify("Audio Import Failed", err.Error())
			app.SetAudioImportState(buildAudioImportState())
			return
		}
		msg := fmt.Sprintf("✅ %s: Imported=%d Uploaded=%d Failed=%d", filepath.Base(data), summary.Imported, summary.Uploaded, summary.Failed)
		log.Printf("[import] single-file import DONE: %s", msg)
		app.SetLastImportMessage(msg)
		app.SetStatus(menubar.StatusIdle)
		app.Notify("Audio Import", msg)
		app.SetAudioImportState(buildAudioImportState())
	}
}

func menubarShowTrackingDB() {
	// Tab 1: load all tracked records from DB.
	db, err := tracking.OpenFilesDB(defaultFilesDBPath())
	if err != nil {
		log.Printf("[tracking] open db for window: %v", err)
		return
	}
	defer db.Close()

	records, err := db.ListFiles(500)
	if err != nil {
		log.Printf("[tracking] list files for window: %v", err)
		return
	}

	var tracked []menubar.TrackingRecord
	// Build a set of tracked basenames for cross-reference with source files.
	trackedNames := make(map[string]string) // basename → status
	for _, r := range records {
		basename := filepath.Base(r.FilePath)
		tracked = append(tracked, menubar.TrackingRecord{
			FileName:       basename,
			Status:         r.Status,
			TranscriptLen:  r.TranscriptLen,
			TranscriptLang: r.TranscriptLang,
			UploadDocID:    r.UploadDocID,
			UploadError:    r.UploadError,
			ProcessedAt:    r.ProcessedAt.Format("2006-01-02 15:04"),
		})
		trackedNames[basename] = r.Status
	}

	// Tab 2: scan source folder and cross-reference with DB.
	cfg, cfgErr := importer.LoadImportConfig()
	if cfgErr != nil || strings.TrimSpace(cfg.AudioSource) == "" {
		log.Printf("[tracking] source folder not configured: %v", cfgErr)
		menubar.ShowTrackingWindow(tracked, nil, "")
		return
	}

	folderPath := cfg.AudioSource
	scan, scanErr := importer.ScanDir(folderPath)
	if scanErr != nil {
		log.Printf("[tracking] scan source folder: %v", scanErr)
		menubar.ShowTrackingWindow(tracked, nil, folderPath)
		return
	}

	var source []menubar.SourceFileRecord
	for _, f := range scan.Files {
		status := "new"
		if st, ok := trackedNames[f.Name]; ok {
			status = st
		}
		source = append(source, menubar.SourceFileRecord{
			FileName:  f.Name,
			Status:    status,
			Size:      fmtFileSize(f.Size),
			SizeBytes: f.Size,
			CreatedAt: fileCreationTime(f.Path),
		})
	}

	menubar.ShowTrackingWindow(tracked, source, folderPath)
}

func runTrackingBulkAction(app *menubar.App, action string, filenames []string, statuses []string) {
	action = strings.TrimSpace(action)
	if len(filenames) == 0 {
		return
	}
	startedAt := time.Now()
	runID := startedAt.Format("20060102-150405.000")
	opType := "bulk_" + action
	startState := menubar.BulkRunState{
		Active:    true,
		RunID:     runID,
		Action:    action,
		Total:     len(filenames),
		Phase:     menubar.BulkPhaseQueued,
		StartedAt: startedAt,
	}
	if !ingestionOps.TryStart(opType, startState) {
		if busy, state := ingestionOps.IsBusy(); busy {
			remaining := state.Total - state.Done
			if remaining < 0 {
				remaining = 0
			}
			app.Notify("Ingestion Busy",
				fmt.Sprintf("Bulk run active (%d/%d, %d remaining). Please wait.", state.Done, state.Total, remaining))
		}
		return
	}

	app.SetBulkRunState(startState)
	menubar.SetTrackingBulkProgress(startState)
	app.SetStatus(menubar.StatusUploading)
	app.SetLastImportMessage(fmt.Sprintf("⏳ Bulk %s started (%d files)", action, len(filenames)))
	for _, name := range filenames {
		menubar.SetTrackingSourceStatus(name, "queued")
	}

	emit := func(evt menubar.BulkProgressEvent) {
		if evt.RunID == "" {
			evt.RunID = runID
		}
		if evt.Action == "" {
			evt.Action = action
		}
		if evt.Total == 0 {
			evt.Total = len(filenames)
		}

		state := app.GetBulkRunState()
		if state.RunID != runID {
			state = startState
		}
		switch evt.Event {
		case "RUN_START":
			log.Print(formatBulkLog(evt))
			state.Phase = menubar.BulkPhaseQueued
		case "ITEM_START":
			log.Print(formatBulkLog(evt))
			state.CurrentFile = evt.Item
			state.Phase = menubar.BulkPhaseQueued
			menubar.SetTrackingSourceStatus(baseName(evt.Item), "queued")
		case "ITEM_PHASE":
			log.Print(formatBulkLog(evt))
			state.CurrentFile = evt.Item
			state.Phase = evt.Phase
			menubar.SetTrackingSourceStatus(baseName(evt.Item), trackingStatusForPhase(evt.Phase))
		case "ITEM_DONE":
			log.Print(formatBulkLog(evt))
			state.Done = evt.Done
			state.Success = evt.Success
			state.Failed = evt.Failed
			state.CurrentFile = evt.Item
			state.Phase = itemDonePhase(evt.Outcome, boolErr(evt.Error))
			if evt.Error != "" {
				state.LastError = evt.Error
			}
			menubar.SetTrackingSourceStatus(baseName(evt.Item), trackingStatusForOutcome(evt.Outcome, evt.Error))
		case "RUN_DONE":
			log.Print(formatBulkLog(evt))
			state.Done = evt.Done
			state.Success = evt.Success
			state.Failed = evt.Failed
			state.CurrentFile = ""
			state.Phase = menubar.BulkPhaseDone
		}
		state.Active = true
		ingestionOps.Update(state)
		app.SetBulkRunState(state)
		menubar.SetTrackingBulkProgress(state)
	}

	handler := func(index, total int, filename, status string, emitFn func(menubar.BulkProgressEvent)) (string, error) {
		srcPath := filepath.Join(importAudioSourceDir(), filename)
		switch action {
		case "transcribe_upload":
			summary, err := runAudioImportPipeline("", defaultFilesDBPath(), srcPath, app, func(evt menubar.BulkProgressEvent) {
				evt.RunID = runID
				evt.Action = action
				evt.Index = index
				evt.Total = total
				if evt.Item == "" {
					evt.Item = filename
				}
				emitFn(evt)
			})
			if err != nil {
				return "failed", err
			}
			if summary.Imported == 0 && summary.Uploaded == 0 && summary.Failed == 0 && strings.EqualFold(strings.TrimSpace(status), "uploaded") {
				return "skipped", nil
			}
			if summary.Failed > 0 {
				return "failed", fmt.Errorf("item failed: imported=%d uploaded=%d failed=%d", summary.Imported, summary.Uploaded, summary.Failed)
			}
			if summary.Uploaded == 0 && summary.Imported == 0 {
				return "skipped", nil
			}
			return "ok", nil
		case "retranscribe_reupload":
			err := reprocessAudioFile(srcPath, defaultFilesDBPath(), app, func(evt menubar.BulkProgressEvent) {
				evt.RunID = runID
				evt.Action = action
				evt.Index = index
				evt.Total = total
				if evt.Item == "" {
					evt.Item = filename
				}
				emitFn(evt)
			})
			if err != nil {
				return "failed", err
			}
			return "ok", nil
		default:
			return "failed", fmt.Errorf("unsupported action: %s", action)
		}
	}

	result := runBulkSession(runID, action, filenames, statuses, handler, emit)
	finalState := app.GetBulkRunState()
	finalState.Active = false
	finalState.Done = result.Done
	finalState.Success = result.Success
	finalState.Failed = result.Failed
	if finalState.Failed > 0 {
		finalState.Phase = menubar.BulkPhaseFailed
	} else {
		finalState.Phase = menubar.BulkPhaseDone
	}
	ingestionOps.Finish(finalState)
	app.SetBulkRunState(finalState)
	menubar.SetTrackingBulkProgress(finalState)
	app.SetStatus(menubar.StatusIdle)
	msg := fmt.Sprintf("Bulk %s done: %d/%d ok, %d failed", action, result.Success, result.Total, result.Failed)
	app.SetLastImportMessage("✅ " + msg)
	app.Notify("Bulk Operation", msg)
	go menubarShowTrackingDB()
}

func boolErr(text string) error {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	return fmt.Errorf("%s", text)
}

func trackingStatusForPhase(phase menubar.BulkRunPhase) string {
	switch phase {
	case menubar.BulkPhaseQueued:
		return "queued"
	case menubar.BulkPhaseImport:
		return "importing"
	case menubar.BulkPhaseTranscribe:
		return "transcribing"
	case menubar.BulkPhaseUpload:
		return "uploading"
	case menubar.BulkPhaseReprocess:
		return "reprocessing"
	case menubar.BulkPhaseDone:
		return "done"
	case menubar.BulkPhaseFailed:
		return "failed"
	default:
		return "processing"
	}
}

func trackingStatusForOutcome(outcome, errText string) string {
	switch strings.ToLower(strings.TrimSpace(outcome)) {
	case "ok":
		return "done"
	case "skipped":
		return "skipped"
	default:
		if strings.TrimSpace(errText) != "" {
			return "failed"
		}
		return "failed"
	}
}

func phaseLogToken(phase menubar.BulkRunPhase) string {
	switch phase {
	case menubar.BulkPhaseTranscribe:
		return "whisper"
	default:
		return string(phase)
	}
}

func fmtFileSize(bytes int64) string {
	switch {
	case bytes >= 1024*1024*1024:
		return fmt.Sprintf("%.1f GB", float64(bytes)/(1024*1024*1024))
	case bytes >= 1024*1024:
		return fmt.Sprintf("%.1f MB", float64(bytes)/(1024*1024))
	case bytes >= 1024:
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

func importAudioSourceDir() string {
	cfg, err := importer.LoadImportConfig()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(cfg.AudioSource)
}

func fileCreationTime(path string) string {
	fi, err := os.Stat(path)
	if err != nil {
		return ""
	}
	if sys, ok := fi.Sys().(*syscall.Stat_t); ok && sys.Birthtimespec.Sec > 0 {
		return time.Unix(sys.Birthtimespec.Sec, sys.Birthtimespec.Nsec).Format("2006-01-02 15:04")
	}
	return fi.ModTime().Format("2006-01-02 15:04")
}

func menubarLoginER1(app *menubar.App) {
	cfg := er1.LoadConfig()
	baseURL := er1BaseURL(cfg.APIURL)
	if baseURL == "" {
		app.Notify("ER1 Login", "Could not derive ER1 base URL from ER1_API_URL.")
		return
	}

	callbackServer, callbackURL, resultCh, closeFn, err := startER1LoginCallbackServer()
	if err != nil {
		log.Printf("[auth] login callback server start failed: %v", err)
		app.Notify("ER1 Login", "Could not start login callback listener.")
		return
	}
	defer closeFn()

	loginURL := fmt.Sprintf("%s/login/multi?next=%s", baseURL, neturl.QueryEscape(callbackURL))
	log.Printf("[auth] login start base=%s callback=%s", baseURL, callbackURL)
	if err := openURL(loginURL); err != nil {
		log.Printf("[auth] failed to open login URL: %v", err)
		app.Notify("ER1 Login", "Failed to open login page in browser.")
		return
	}
	app.Notify("ER1 Login", "Browser opened. Complete login to link account.")
	deadline := time.NewTimer(2 * time.Minute)
	defer deadline.Stop()
	poll := time.NewTicker(1500 * time.Millisecond)
	defer poll.Stop()

	// configFallback uses ER1_CONTEXT_ID from .env when the user is on the
	// ER1 site (Chrome tabs match the host) but no context_id can be extracted
	// from URLs. This handles ER1 servers that don't redirect to the callback
	// or don't expose context_id in page URLs. See BUG-0003.
	configFallback := func() string {
		if !menubar.HasServiceHostTabs(baseURL) {
			return ""
		}
		fallbackID := strings.TrimSpace(cfg.ContextID)
		if fallbackID == "" {
			return ""
		}
		log.Printf("[auth] ER1 host tabs detected but no context_id in URLs; using ER1_CONTEXT_ID=%s from config", fallbackID)
		return fallbackID
	}

	for {
		select {
		case result := <-resultCh:
			if result.Err != nil {
				log.Printf("[auth] callback received error: %v", result.Err)
				app.Notify("ER1 Login", "Login callback failed.")
				return
			}
			ctxID := strings.TrimSpace(result.ContextID)
			if ctxID == "" {
				// Fallback 1: inspect Chrome tabs for memory URLs on ER1 host.
				ctxID = menubar.SuggestedServiceContextID(baseURL)
			}
			if ctxID == "" {
				// Fallback 2: use ER1_CONTEXT_ID from config if ER1 tabs are open.
				ctxID = configFallback()
			}
			if completeER1Login(app, ctxID) {
				return
			}
			log.Printf("[auth] callback received but no context_id yet; continuing tab polling")
		case <-poll.C:
			ctxID := menubar.SuggestedServiceContextID(baseURL)
			if ctxID == "" {
				ctxID = configFallback()
			}
			if completeER1Login(app, ctxID) {
				return
			}
		case <-deadline.C:
			// Final attempt: try config fallback before giving up.
			if ctxID := configFallback(); ctxID != "" {
				if completeER1Login(app, ctxID) {
					return
				}
			}
			log.Printf("[auth] login timed out waiting for callback/context; addr=%s", callbackServer.Addr)
			app.SetStatus(menubar.StatusError)
			app.Notify("ER1 Login", "Timed out waiting for login confirmation. Check logs for details.")
			return
		}
	}
}

func completeER1Login(app *menubar.App, contextID string) bool {
	ctxID := strings.TrimSpace(contextID)
	if ctxID == "" {
		return false
	}
	setRuntimeER1Login(ctxID)
	app.SetAuthSession(menubar.AuthSession{LoggedIn: true, UserID: ctxID})
	if err := savePersistedER1Session(ctxID); err != nil {
		log.Printf("[auth] persist session failed: %v", err)
	}
	log.Printf("[auth] login success context_id=%s", truncateForLog(ctxID, 64))
	app.Notify("ER1 Login", fmt.Sprintf("Linked account: %s", ctxID))
	return true
}

func menubarLogoutER1(app *menubar.App) {
	clearRuntimeER1Login()
	app.SetAuthSession(menubar.AuthSession{})
	if err := clearPersistedER1Session(); err != nil {
		log.Printf("[auth] persisted session clear failed: %v", err)
	}
	app.Notify("ER1 Logout", "Session cleared. Uploads use ER1_CONTEXT_ID until you login again.")
	log.Printf("[auth] logout complete; runtime session cleared")
}

type loginCallbackResult struct {
	ContextID string
	Err       error
}

func startER1LoginCallbackServer() (*http.Server, string, <-chan loginCallbackResult, func(), error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", nil, nil, err
	}
	// Generate a random nonce so only the legitimate ER1 redirect can hit the callback.
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		ln.Close()
		return nil, "", nil, nil, fmt.Errorf("generate callback nonce: %w", err)
	}
	callbackPath := "/m3c-login-" + hex.EncodeToString(nonce)
	addr := ln.Addr().String()
	callbackURL := "http://" + addr + callbackPath
	resultCh := make(chan loginCallbackResult, 1)
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
		case resultCh <- loginCallbackResult{ContextID: ctxID}:
		default:
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprint(w, "<html><body><h3>Login captured.</h3><p>You can return to M3C Tools.</p></body></html>")
	})

	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}
	go func() {
		if serveErr := srv.Serve(ln); serveErr != nil && serveErr != http.ErrServerClosed {
			log.Printf("[auth] callback server error: %v", serveErr)
			select {
			case resultCh <- loginCallbackResult{Err: serveErr}:
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

// truncateForLog truncates a string for safe log output, preventing
// excessively long values from flooding logs.
func truncateForLog(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func ganttFormatDuration(d time.Duration) string {
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh %02dm", h, m)
	}
	return fmt.Sprintf("%dm", m)
}

func er1BaseURL(apiURL string) string {
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
	u.Path = p
	u.RawQuery = ""
	u.Fragment = ""
	return strings.TrimSuffix(u.String(), "/")
}

// menubarFetchTranscriptAndTrack fetches YouTube transcript context, opens a
// record-capable Observation Window, and starts voice tracking regardless of
// transcript availability. On transcript fetch rate limit/failure, tags include
// "transcript-pull-needed" so the item can be revisited later.
func menubarFetchTranscriptAndTrack(app *menubar.App, fetcher *menubar.TranscriptFetcher, videoID string) {
	app.SetStatus(menubar.StatusFetching)
	app.Notify("Fetching...", fmt.Sprintf("Fetching transcript for %s", videoID))

	result, err := fetcher.Fetch(videoID)
	if err != nil {
		app.SetStatus(menubar.StatusError)
		app.Notify("Error", fmt.Sprintf("Failed to fetch transcript: %s", err))
		return
	}

	if result.Text != "" {
		_ = menubar.CopyToClipboard(result.Text)
	}
	app.AddHistory(menubar.NewHistoryEntry(result.VideoID, result.Flag))

	thumbnailPath := fetcher.FetchAndSaveThumbnail(result.VideoID)
	var imgData []byte
	if thumbnailPath != "" {
		if data, readErr := os.ReadFile(thumbnailPath); readErr == nil {
			imgData = data
		}
	}

	meta := &menubar.ReviewMetadata{
		Source:       "YouTube",
		Language:     result.Language,
		SnippetCount: result.SnippetCount,
		CharCount:    result.CharCount,
		Date:         time.Now().Format("2006-01-02 15:04:05"),
	}
	if result.FromCache {
		meta.Source = "YouTube (cached)"
	}

	title := fmt.Sprintf("Observation — YouTube [%s]", result.VideoID)
	ok := menubar.ShowObservationWindowWithMeta(title, thumbnailPath, menubar.ChannelTypeProgress, meta)
	if !ok {
		app.SetStatus(menubar.StatusError)
		app.Notify("Error", "Failed to open observation window.")
		return
	}

	tags := fmt.Sprintf("youtube, %s", result.VideoID)
	if result.RateLimited {
		tags += ", transcript-pull-needed"
	}
	menubar.SetObservationTags(tags)
	menubar.SetObservationTitle(result.VideoID)

	if result.Text != "" {
		statusText := fmt.Sprintf("Transcript loaded — %d chars", len(result.Text))
		menubar.SetReviewTranscript(result.Text, statusText)
	} else if result.RateLimited {
		menubar.SetReviewTranscript("[Transcript unavailable — YouTube rate limit (429). Voice note recording is still available.]", "Transcript pull needed")
	}

	// NOTE: Do NOT load transcript into the Notes field. The Notes field is
	// editable and gets merged into ImpressionText on Store, which would
	// duplicate the transcript. The transcript is visible in the Review tab.
	// See BUG-0004.

	menubar.SetRecordSourceLabel("  video " + result.VideoID + "  ")

	obsCtx := ObservationContext{
		TranscriptText: result.Text,
		VideoID:        result.VideoID,
		VideoURL:       "https://www.youtube.com/watch?v=" + result.VideoID,
		Language:        result.Language,
		LanguageCode:    result.LanguageCode,
		SnippetCount:    result.SnippetCount,
	}

	// Channel A (YouTube): defer recording until user clicks "Start Recording".
	// The user needs time to review the transcript before narrating. See BUG-0005.
	//
	// Register Store/Cancel callbacks immediately so the user can store the
	// transcript observation without recording audio (transcript-only mode).
	// If the user clicks Start Recording, observationRecordAndUpload will
	// overwrite these with recording-aware versions.
	menubar.SetObservationStoreCallback(func(tags, notes, contentType, imagePath string) {
		app.SetStatus(menubar.StatusUploading)
		now := time.Now()
		ts := now.Format("20060102_150405")

		memoText := mergeCaptureMemoAndNotes(menubar.GetReviewMemoText(), notes)
		doc := &impression.CompositeDoc{
			VideoID:        obsCtx.VideoID,
			VideoURL:       obsCtx.VideoURL,
			Language:        obsCtx.Language,
			LanguageCode:    obsCtx.LanguageCode,
			IsGenerated:     obsCtx.IsGenerated,
			SnippetCount:    obsCtx.SnippetCount,
			TranscriptText:  obsCtx.TranscriptText,
			ImpressionText: memoText,
			ObsType:        impression.Progress,
			Timestamp:      now,
		}
		composite := strings.TrimSpace(doc.Build()) + "\n"

		payload := &er1.UploadPayload{
			TranscriptData:     []byte(composite),
			TranscriptFilename: fmt.Sprintf("progress_%s.txt", ts),
			ImageData:          imgData,
			ImageFilename:      filepath.Base(thumbnailPath),
			Tags:               tags,
			ContentType:        contentType,
		}
		log.Printf("[progress] transcript-only upload: transcript=%d image=%d",
			len(payload.TranscriptData), len(payload.ImageData))
		menubarUploadPayload(app, "progress", payload, tags)
	})

	menubar.SetObservationCancelCallback(func(draftPath string) {
		log.Printf("[progress] draft saved: %s", draftPath)
		app.SetStatus(menubar.StatusIdle)
	})

	menubar.SetStartRecordingCallback(func() {
		app.SetStatus(menubar.StatusRecording)
		observationRecordAndUpload(app, "progress", thumbnailPath, imgData, impression.Progress, obsCtx)
	})

	if result.RateLimited {
		app.Notify("Observation Ready", fmt.Sprintf("⚠️ %s — transcript-pull-needed, voice tracker active", result.VideoID))
		return
	}
	if result.FromCache {
		app.Notify("Observation Ready", fmt.Sprintf("%s %s (cached) — voice tracker active", result.Flag, result.VideoID))
		return
	}
	app.Notify("Observation Ready", fmt.Sprintf("%s %s — transcript loaded, voice tracker active", result.Flag, result.VideoID))
}

// menubarUploadER1 performs the full ER1 upload workflow for a video ID:
// fetch transcript, build composite doc, fetch thumbnail, upload to ER1.
// On failure, the upload is queued for retry.
func menubarUploadER1(videoID string) (*menubar.ER1UploadResult, error) {
	// Fetch transcript
	api := transcript.New()
	fetched, err := api.Fetch(videoID, []string{"en"}, false)
	if err != nil {
		return nil, fmt.Errorf("transcript fetch: %w", err)
	}

	// Build composite document
	textFmt := transcript.TextFormatter{}
	doc := &impression.CompositeDoc{
		VideoID:        videoID,
		VideoURL:       "https://www.youtube.com/watch?v=" + videoID,
		Language:       fetched.Language,
		LanguageCode:   fetched.LanguageCode,
		IsGenerated:    fetched.IsGenerated,
		SnippetCount:   len(fetched.Snippets),
		TranscriptText: textFmt.FormatTranscript(fetched),
		ObsType:        impression.Progress,
		Timestamp:      time.Now(),
	}
	composite := doc.Build()

	// Fetch thumbnail
	fetcher, _ := transcript.NewFetcher(nil)
	thumbData, _ := fetcher.FetchThumbnail(videoID)

	// Build payload
	tags := impression.BuildVideoTags(videoID, "", impression.Progress)
	payload := &er1.UploadPayload{
		TranscriptData:     []byte(composite),
		TranscriptFilename: fmt.Sprintf("%s_transcript.txt", videoID),
		ImageData:          thumbData,
		ImageFilename:      fmt.Sprintf("%s_thumbnail.jpg", videoID),
		Tags:               tags,
	}

	// Upload
	cfg := er1.LoadConfig()
	applyRuntimeER1Context(cfg)
	resp, err := er1.Upload(cfg, payload)
	if err != nil {
		// Queue for retry on failure
		queuePath := er1.DefaultQueuePath()
		entry := er1.EnqueueFailure(queuePath, videoID, payload, tags, err)
		return &menubar.ER1UploadResult{
			VideoID: videoID,
			Message: fmt.Sprintf("Upload failed, queued for retry: %s", entry.ID),
			Queued:  true,
		}, nil
	}

	return &menubar.ER1UploadResult{
		VideoID: videoID,
		DocID:   resp.DocID,
		Message: fmt.Sprintf("Uploaded %s → doc_id: %s", videoID, resp.DocID),
	}, nil
}

// menubarCaptureScreenshot performs the Idea observation flow via the
// Observation Window: capture screenshot → show in Record tab → record
// voice note with VU meter → whisper transcribe → Review tab → Store/Cancel.
func menubarCaptureScreenshot(app *menubar.App) {
	app.SetStatus(menubar.StatusRecording)

	imgPath, sourceLabel, err := captureScreenshotForMenu(app, "screenshot")
	if err != nil {
		app.SetStatus(menubar.StatusIdle)
		log.Printf("[screenshot] capture failed: %v", err)
		return
	}
	log.Printf("[screenshot] saved: %s", imgPath)

	imgData, err := os.ReadFile(imgPath)
	if err != nil {
		app.SetStatus(menubar.StatusError)
		log.Printf("[screenshot] read failed: %v", err)
		return
	}

	menubar.ShowObservationWindowForScreenshot(imgPath)
	menubar.StartRecordingTimer()
	menubar.SetRecordSourceLabel(sourceLabel)
	observationRecordAndUpload(app, "screenshot", imgPath, imgData, impression.Idea)
}

// menubarQuickImpulse performs the Impulse observation flow via the
// Observation Window: region screenshot → show in Record tab → record
// voice note with VU meter → whisper transcribe → Review tab → Store/Cancel.
func menubarQuickImpulse(app *menubar.App) {
	app.SetStatus(menubar.StatusRecording)

	imgPath, sourceLabel, err := captureScreenshotForMenu(app, "impulse")
	if err != nil {
		app.SetStatus(menubar.StatusIdle)
		log.Printf("[impulse] screenshot cancelled or failed: %v", err)
		return
	}
	log.Printf("[impulse] screenshot: %s", imgPath)

	imgData, _ := os.ReadFile(imgPath)

	menubar.ShowObservationWindowForImpulse(imgPath)
	menubar.StartRecordingTimer()
	menubar.SetRecordSourceLabel(sourceLabel)
	observationRecordAndUpload(app, "impulse", imgPath, imgData, impression.Impulse)
}

// menubarRecordImpression starts an audio-record impression flow for a YouTube
// item, including thumbnail context when available.
func menubarRecordImpression(app *menubar.App, videoID string) {
	videoID = strings.TrimSpace(videoID)
	if videoID == "" {
		app.Notify("Record Impression", "Missing video ID.")
		return
	}

	app.SetStatus(menubar.StatusRecording)

	// Best-effort thumbnail fetch; recording still works if unavailable.
	var (
		imgPath string
		imgData []byte
	)
	fetcher, _ := transcript.NewFetcher(nil)
	if data, err := fetcher.FetchThumbnail(videoID); err == nil && len(data) > 0 {
		imgData = data
		imgPath = filepath.Join(os.TempDir(), fmt.Sprintf("m3c-thumb-%s.jpg", videoID))
		if writeErr := os.WriteFile(imgPath, data, 0o644); writeErr != nil {
			log.Printf("[record] thumbnail write failed video=%s error=%v", videoID, writeErr)
			imgPath = ""
		}
	} else if err != nil {
		log.Printf("[record] thumbnail fetch failed video=%s error=%v (non-fatal)", videoID, err)
	}

	title := fmt.Sprintf("Observation — YouTube [%s]", videoID)
	_ = menubar.ShowObservationWindow(title, imgPath, menubar.ChannelTypeProgress)
	menubar.SetObservationTags(fmt.Sprintf("progress, youtube, %s", videoID))
	menubar.SetObservationTitle(videoID)
	menubar.StartRecordingTimer()
	menubar.SetRecordSourceLabel("  video " + videoID + "  ")

	observationRecordAndUpload(app, "progress", imgPath, imgData, impression.Progress)
}

// ObservationContext carries optional pre-existing data into the recording
// pipeline so that e.g. a YouTube transcript is not lost when whisper runs.
type ObservationContext struct {
	// Pre-existing transcript text (e.g. YouTube transcript).
	// Preserved in the Review tab and included in the uploaded composite doc.
	TranscriptText string
	// Video metadata for Progress observations.
	VideoID      string
	VideoURL     string
	Language     string
	LanguageCode string
	IsGenerated  bool
	SnippetCount int
}

// observationRecordAndUpload starts background recording with VU meter and
// registers the Stop/Store/Cancel callbacks for the Observation Window pipeline.
// The Observation Window must already be shown before calling this function.
func observationRecordAndUpload(app *menubar.App, label string, imgPath string, imgData []byte, obsType impression.ObservationType, ctxData ...ObservationContext) {
	var obsCtx ObservationContext
	if len(ctxData) > 0 {
		obsCtx = ctxData[0]
	}
	const maxRecordSeconds = 120

	// Shared state written by stop callback, read by store callback.
	var audioData []byte
	var uploadAudioData []byte
	var recordingStopped bool
	var transcribedText string

	// Context for cancelling the recording from any callback.
	ctx, cancel := context.WithCancel(context.Background())
	recDone := make(chan struct{})

	// Start recording in background with VU meter updates.
	go func() {
		defer close(recDone)
		samples, recErr := recorder.RecordWithLevels(ctx.Done(), maxRecordSeconds, func(level recorder.AudioLevel) {
			// Map RMS dB to 0.0–1.0 visual range: -60 dB → 0%, 0 dB → 100%.
			// Raw RMS is too low for a useful linear meter (speech ≈ 0.01–0.05).
			dbLevel := recorder.AmplitudeToDb(level.RMS)
			visualLevel := float32((dbLevel + 60.0) / 60.0)
			if visualLevel < 0 {
				visualLevel = 0
			}
			if visualLevel > 1 {
				visualLevel = 1
			}
			menubar.UpdateVUMeterLevel(visualLevel)
		})
		if recErr != nil {
			log.Printf("[%s] recording failed: %v", label, recErr)
			return
		}
		audioData = recorder.EncodeWAV(samples)
	}()

	// Stop callback: stop recording → whisper transcribe → update Review tab.
	menubar.SetStopRecordingCallback(func(elapsed int) {
		if busy, state := ingestionOps.IsBusy(); busy {
			remaining := state.Total - state.Done
			if remaining < 0 {
				remaining = 0
			}
			menubar.SetReviewTranscript(
				fmt.Sprintf("Bulk audio processing is active (%d/%d, %d remaining). Please wait and retry.",
					state.Done, state.Total, remaining),
				"Ingestion blocked",
			)
			return
		}
		cancel()
		<-recDone
		recordingStopped = true

		if len(audioData) == 0 {
			menubar.SetReviewTranscript("No audio recorded.", "Recording failed")
			return
		}
		// Freeze audio bytes for Store upload.
		uploadAudioData = append([]byte(nil), audioData...)

		// Log recording details
		wavSize := len(uploadAudioData)
		pcmBytes := wavSize - 44
		if pcmBytes < 0 {
			pcmBytes = 0
		}
		sampleCount := pcmBytes / (recorder.BitsPerSample / 8)
		duration := float64(sampleCount) / float64(recorder.SampleRate)
		samples := recorder.DecodePCM16(uploadAudioData[44:])
		stats := recorder.Stats(samples)
		log.Printf("[%s] recorded %.1fs (%d bytes, peak=%d)", label, duration, wavSize, stats.PeakAmplitude)

		// Write WAV to temp file for whisper
		wavPath := filepath.Join(os.TempDir(), fmt.Sprintf("m3c-%s-%d.wav", label, time.Now().UnixNano()))
		if err := os.WriteFile(wavPath, uploadAudioData, 0644); err != nil {
			log.Printf("[%s] write WAV failed: %v", label, err)
			menubar.SetReviewTranscript("Could not save audio for transcription.", "Error")
			return
		}
		defer os.Remove(wavPath)

		// Transcribe via whisper — show animated progress bar
		menubar.SetReviewTranscript("Transcribing...", "Whisper processing")
		menubar.ShowWhisperProgress()
		model := menubarWhisperModel()
		language := menubarWhisperLanguage()
		timeout := menubarWhisperTimeout()

		log.Printf("[%s] whisper START: file=%s model=%s language=%q timeout=%s", label, wavPath, model, language, timeout)
		whisperStart := time.Now()
		text, whisperErr := whisper.TranscribeTextWithTimeout(wavPath, model, language, timeout)
		whisperElapsed := time.Since(whisperStart)
		menubar.HideWhisperProgress()

		if whisperErr != nil {
			log.Printf("[%s] whisper FAILED after %s: %v", label, whisperElapsed, whisperErr)
			menubar.SetReviewTranscript("Transcription failed: "+whisperErr.Error(), "Failed")
			return
		}

		transcribedText = text
		log.Printf("[%s] whisper DONE in %s: %d chars", label, whisperElapsed, len(text))
		log.Printf("[%s] transcription: %q", label, text)

		// Build structured memo text with metadata + voice comment + original transcript.
		sizeKB := float64(wavSize) / 1024.0
		peakPct := float64(stats.PeakAmplitude) / 32768.0 * 100
		var memo string
		if obsCtx.TranscriptText != "" {
			// Preserve the original transcript (e.g. YouTube) and add the
			// voice comment as a separate section — do NOT overwrite.
			memo = fmt.Sprintf(
				"--- Metadata ---\nChannel: %s\nDate: %s\nRecording: %.1fs, %.1f KB, peak %.0f%%\nWhisper: %s model, %d chars in %s\n\n--- Voice Comment ---\n%s\n\n--- Original Transcript ---\n%s\n\n--- Notes ---\n",
				label,
				time.Now().Format("2006-01-02 15:04:05"),
				duration, sizeKB, peakPct,
				model, len(text), whisperElapsed.Round(time.Millisecond),
				text,
				obsCtx.TranscriptText,
			)
		} else {
			memo = fmt.Sprintf(
				"--- Metadata ---\nChannel: %s\nDate: %s\nRecording: %.1fs, %.1f KB, peak %.0f%%\nWhisper: %s model, %d chars in %s\n\n--- Transcript ---\n%s\n\n--- Notes ---\n",
				label,
				time.Now().Format("2006-01-02 15:04:05"),
				duration, sizeKB, peakPct,
				model, len(text), whisperElapsed.Round(time.Millisecond),
				text,
			)
		}
		statusText := fmt.Sprintf("Memo — %d chars (editable)", len(memo))
		menubar.SetReviewTranscript(memo, statusText)
	})

	// Store callback: build composite doc + upload to ER1.
	// Reads the (possibly user-edited) memo text from the Review tab.
	menubar.SetObservationStoreCallback(func(tags, notes, contentType, imagePath string) {
		app.SetStatus(menubar.StatusUploading)
		if !recordingStopped {
			log.Printf("[%s] store requested before recording was stopped", label)
			app.Notify("Recording Still Running", "Click Stop Recording first.")
			app.SetStatus(menubar.StatusRecording)
			return
		}
		// Allow storing without audio — ER1 Upload sends a placeholder WAV automatically.

		now := time.Now()
		ts := now.Format("20060102_150405")

		// Read the final memo text (user may have edited it).
		memoText := menubar.GetReviewMemoText()
		if memoText == "" {
			memoText = transcribedText
		}
		memoText = mergeCaptureMemoAndNotes(memoText, notes)

		doc := &impression.CompositeDoc{
			VideoID:        obsCtx.VideoID,
			VideoURL:       obsCtx.VideoURL,
			Language:        obsCtx.Language,
			LanguageCode:    obsCtx.LanguageCode,
			IsGenerated:     obsCtx.IsGenerated,
			SnippetCount:    obsCtx.SnippetCount,
			TranscriptText:  obsCtx.TranscriptText,
			ImpressionText: memoText,
			ObsType:        obsType,
			Timestamp:      now,
		}
		composite := strings.TrimSpace(doc.Build()) + "\n"

		prefix := "idea"
		switch obsType {
		case impression.Progress:
			prefix = "progress"
		case impression.Impulse:
			prefix = "impulse"
		}

		payload := &er1.UploadPayload{
			TranscriptData:     []byte(composite),
			TranscriptFilename: fmt.Sprintf("%s_%s.txt", prefix, ts),
			AudioData:          uploadAudioData,
			AudioFilename:      fmt.Sprintf("%s_%s.wav", prefix, ts),
			ImageData:          imgData,
			ImageFilename:      filepath.Base(imgPath),
			Tags:               tags,
			ContentType:        contentType,
		}
		log.Printf("[%s] upload payload sizes: transcript=%d audio=%d image=%d",
			label, len(payload.TranscriptData), len(payload.AudioData), len(payload.ImageData))
		menubarUploadPayload(app, label, payload, tags)
	})

	// Cancel callback: stop recording if still running, set idle.
	menubar.SetObservationCancelCallback(func(draftPath string) {
		cancel() // safe to call multiple times
		log.Printf("[%s] draft saved: %s", label, draftPath)
		app.SetStatus(menubar.StatusIdle)
	})
}

func mergeCaptureMemoAndNotes(memo, notes string) string {
	m := strings.TrimSpace(memo)
	n := strings.TrimSpace(notes)
	if n == "" {
		return m
	}
	if m == "" {
		return "Additional Comment:\n" + n
	}
	if strings.Contains(m, n) {
		return m
	}
	return m + "\n\n--- Additional Comment ---\n" + n
}

// menubarUploadPayload uploads a payload to ER1, queuing on failure.
// On success, opens the uploaded item in the default browser.
func menubarUploadPayload(app *menubar.App, label string, payload *er1.UploadPayload, tags string) {
	if busy, state := ingestionOps.IsBusy(); busy {
		remaining := state.Total - state.Done
		if remaining < 0 {
			remaining = 0
		}
		msg := fmt.Sprintf("Bulk run active (%d/%d, %d remaining). Upload blocked.", state.Done, state.Total, remaining)
		log.Printf("[%s] upload blocked: %s", label, msg)
		app.Notify("Ingestion Busy", msg)
		app.SetStatus(menubar.StatusIdle)
		return
	}

	cfg := er1.LoadConfig()
	applyRuntimeER1Context(cfg)
	resp, err := er1.Upload(cfg, payload)
	if err != nil {
		log.Printf("[%s] ER1 upload failed (queuing): %v", label, err)
		queuePath := er1.DefaultQueuePath()
		er1.EnqueueFailure(queuePath, label, payload, tags, err)
		app.SetStatus(menubar.StatusIdle)
		return
	}

	// Build item URL: <service_base>/memory/<context_id>/<doc_id>
	baseURL := strings.TrimSuffix(cfg.APIURL, "/upload_2")
	baseURL = strings.TrimSuffix(baseURL, "/")
	itemURL := fmt.Sprintf("%s/memory/%s/%s", baseURL, cfg.ContextID, resp.DocID)

	log.Printf("[%s] uploaded to ER1: doc_id=%s url=%s", label, resp.DocID, itemURL)
	app.Notify("Upload Done", fmt.Sprintf("doc_id: %s", resp.DocID))
	app.SetStatus(menubar.StatusIdle)

	// Reverse time tracking: record observation and create inferred time block (REQ-9/10).
	if reverseTracker != nil && tags != "" {
		if err := reverseTracker.RecordAndProcess(time.Now(), tags, resp.DocID, label); err != nil {
			log.Printf("[reverse-tracking] process observation failed: %v", err)
		}
	}

	// Open the item in the default browser.
	_ = openURL(itemURL)
}

// openURL opens a URL in the default browser (macOS only).
func openURL(url string) error {
	// Prefer Chrome to keep auth/session in the same browser used for ER1.
	if err := exec.Command("open", "-a", "Google Chrome", url).Start(); err == nil {
		return nil
	}
	// Fallback to system default browser if Chrome is unavailable.
	return exec.Command("open", url).Start()
}

func captureScreenshotForMenu(app *menubar.App, flow string) (string, string, error) {
	mode := screenshotCaptureMode()
	switch mode {
	case "clipboard-first":
		// Check if there's already an image on the clipboard — use it directly.
		if imgType, _ := screenshot.DetectClipboardImage(); imgType != screenshot.ClipboardNoImage {
			outPath := filepath.Join(
				os.TempDir(),
				fmt.Sprintf("m3c-clipboard-%s.png", time.Now().Format("20060102-150405")),
			)
			imgPath, err := screenshot.ExtractClipboardImage(outPath)
			if err == nil {
				log.Printf("[%s] using existing clipboard image: %s", flow, imgPath)
				return imgPath, "  from clipboard  ", nil
			}
			log.Printf("[%s] clipboard image extraction failed: %v; falling back to capture", flow, err)
		}

		timeout := clipboardCaptureTimeout()
		app.Notify("Take Screenshot", fmt.Sprintf("Press Cmd+Ctrl+Shift+4 (waiting %ds)", int(timeout/time.Second)))
		menubar.ResetCaptureHintCancelled()
		menubar.ShowCaptureHintWindow(
			"Waiting for screenshot…",
			fmt.Sprintf("Press Cmd+Ctrl+Shift+4 (timeout %ds)", int(timeout/time.Second)),
		)
		defer menubar.HideCaptureHintWindow()
		log.Printf("[%s] screenshot mode=clipboard-first timeout=%s", flow, timeout)

		imgPath, err := waitForClipboardImageChange(timeout)
		if err != nil {
			return "", "", err
		}
		return imgPath, "  from clipboard  ", nil

	case "interactive":
		log.Printf("[%s] screenshot mode=interactive", flow)

		if !menubar.HasScreenCaptureAccess() {
			app.Notify("Screen Recording Permission Needed", "Enable m3c-tools in Screen Recording and restart the app. Falling back to clipboard mode.")
			_ = openURL("x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture")
			return captureScreenshotForMenuClipboardFallback(app)
		}

		menubar.PrepareForInteractiveCapture()
		delay := interactiveCaptureFocusDelay()
		log.Printf("[%s] focus handoff delay=%s", flow, delay)
		time.Sleep(delay)

		imgPath, err := screenshot.Capture(screenshot.Options{
			Mode:   screenshot.Region,
			Silent: true,
		})
		if err != nil {
			log.Printf("[%s] interactive capture failed: %v; trying clipboard fallback", flow, err)
			imgPath, err = screenshot.CaptureClipboardFirst(os.TempDir())
			if err != nil {
				return "", "", err
			}
			return imgPath, "  from clipboard  ", nil
		}
		return imgPath, "  capture at " + time.Now().Format("15:04:05") + "  ", nil

	default:
		log.Printf("[%s] unknown screenshot mode %q; using clipboard-first", flow, mode)
		return captureScreenshotForMenuClipboardFallback(app)
	}
}

func captureScreenshotForMenuClipboardFallback(app *menubar.App) (string, string, error) {
	timeout := clipboardCaptureTimeout()
	menubar.ResetCaptureHintCancelled()
	menubar.ShowCaptureHintWindow(
		"Waiting for screenshot…",
		fmt.Sprintf("Press Cmd+Ctrl+Shift+4 (timeout %ds)", int(timeout/time.Second)),
	)
	defer menubar.HideCaptureHintWindow()
	if app != nil {
		app.Notify("Take Screenshot", fmt.Sprintf("Press Cmd+Ctrl+Shift+4 (waiting %ds)", int(timeout/time.Second)))
	}
	imgPath, err := waitForClipboardImageChange(timeout)
	if err != nil {
		return "", "", err
	}
	return imgPath, "  from clipboard  ", nil
}

func waitForClipboardImageChange(timeout time.Duration) (string, error) {
	startCount := menubar.ClipboardChangeCount()
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		if menubar.CaptureHintWasCancelled() {
			return "", fmt.Errorf("screenshot capture cancelled by user")
		}
		currentCount := menubar.ClipboardChangeCount()
		if currentCount != startCount {
			startCount = currentCount
			imgType, err := screenshot.DetectClipboardImage()
			if err != nil {
				log.Printf("[screenshot] clipboard check failed after change_count=%d: %v", currentCount, err)
				time.Sleep(120 * time.Millisecond)
				continue
			}
			if imgType == screenshot.ClipboardNoImage {
				time.Sleep(120 * time.Millisecond)
				continue
			}

			outPath := filepath.Join(
				os.TempDir(),
				fmt.Sprintf("m3c-clipboard-%s.png", time.Now().Format("20060102-150405")),
			)
			return screenshot.ExtractClipboardImage(outPath)
		}
		time.Sleep(120 * time.Millisecond)
	}

	return "", fmt.Errorf("timed out waiting for clipboard screenshot after %s", timeout)
}

func screenshotCaptureMode() string {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv("M3C_SCREENSHOT_MODE")))
	switch raw {
	case "", "clipboard-first", "clipboard", "hotkey":
		return "clipboard-first"
	case "interactive", "screencapture-legacy", "legacy":
		return "interactive"
	default:
		return raw
	}
}

func clipboardCaptureTimeout() time.Duration {
	const (
		defaultTimeout = 20 * time.Second
		maxTimeout     = 5 * time.Minute
	)

	raw := strings.TrimSpace(os.Getenv("M3C_SCREENSHOT_CLIPBOARD_TIMEOUT_SEC"))
	if raw == "" {
		return defaultTimeout
	}

	secs, err := strconv.Atoi(raw)
	if err != nil {
		log.Printf("[screenshot] invalid M3C_SCREENSHOT_CLIPBOARD_TIMEOUT_SEC=%q; using default %ds", raw, int(defaultTimeout/time.Second))
		return defaultTimeout
	}
	if secs < 1 {
		log.Printf("[screenshot] M3C_SCREENSHOT_CLIPBOARD_TIMEOUT_SEC=%d is too low; using 1s", secs)
		return time.Second
	}

	timeout := time.Duration(secs) * time.Second
	if timeout > maxTimeout {
		log.Printf("[screenshot] M3C_SCREENSHOT_CLIPBOARD_TIMEOUT_SEC=%d is too high; clamping to %ds", secs, int(maxTimeout/time.Second))
		return maxTimeout
	}
	return timeout
}

func interactiveCaptureFocusDelay() time.Duration {
	const (
		defaultDelay = 700 * time.Millisecond
		maxDelay     = 5 * time.Second
	)

	raw := strings.TrimSpace(os.Getenv("M3C_SCREENSHOT_FOCUS_DELAY_MS"))
	if raw == "" {
		return defaultDelay
	}

	ms, err := strconv.Atoi(raw)
	if err != nil {
		log.Printf("[screenshot] invalid M3C_SCREENSHOT_FOCUS_DELAY_MS=%q; using default %dms", raw, defaultDelay/time.Millisecond)
		return defaultDelay
	}
	if ms < 0 {
		log.Printf("[screenshot] M3C_SCREENSHOT_FOCUS_DELAY_MS=%d is negative; using 0ms", ms)
		return 0
	}

	delay := time.Duration(ms) * time.Millisecond
	if delay > maxDelay {
		log.Printf("[screenshot] M3C_SCREENSHOT_FOCUS_DELAY_MS=%d is too high; clamping to %dms", ms, maxDelay/time.Millisecond)
		return maxDelay
	}
	return delay
}

func maybePreloadWhisper() {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv("M3C_WHISPER_PRELOAD")))
	if raw == "0" || raw == "false" || raw == "off" || raw == "no" {
		log.Printf("[whisper] preload disabled by M3C_WHISPER_PRELOAD=%q", raw)
		return
	}

	model := menubarWhisperModel()
	language := menubarWhisperLanguage()

	go func() {
		start := time.Now()
		tmpPath := filepath.Join(os.TempDir(), fmt.Sprintf("m3c-whisper-preload-%d.wav", time.Now().UnixNano()))
		samples := make([]int16, recorder.SampleRate) // 1s silence
		if err := os.WriteFile(tmpPath, recorder.EncodeWAV(samples), 0644); err != nil {
			log.Printf("[whisper] preload skipped: write temp wav failed: %v", err)
			return
		}
		defer os.Remove(tmpPath)

		log.Printf("[whisper] preload start model=%s language=%s", model, language)
		_, err := whisper.TranscribeTextWithTimeout(tmpPath, model, language, menubarWhisperTimeout())
		if err != nil {
			log.Printf("[whisper] preload failed after %s: %v", time.Since(start).Round(time.Millisecond), err)
			return
		}
		log.Printf("[whisper] preload done in %s", time.Since(start).Round(time.Millisecond))
	}()
}

func menubarWhisperModel() string {
	model := strings.TrimSpace(os.Getenv("M3C_WHISPER_MODEL"))
	if model != "" {
		return model
	}
	model = strings.TrimSpace(os.Getenv("YT_WHISPER_MODEL"))
	if model != "" {
		return model
	}
	return "base"
}

func menubarWhisperLanguage() string {
	language := strings.TrimSpace(os.Getenv("YT_WHISPER_LANGUAGE"))
	if language != "" {
		return language
	}
	return "de"
}

func menubarWhisperTimeout() time.Duration {
	const defaultTimeout = 7200 * time.Second // 2 hours — large audio files need time

	raw := strings.TrimSpace(os.Getenv("M3C_WHISPER_TIMEOUT"))
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv("YT_WHISPER_TIMEOUT"))
	}
	if raw == "" {
		return defaultTimeout
	}

	secs, err := strconv.Atoi(raw)
	if err != nil {
		log.Printf("[whisper] invalid timeout %q; using default %s", raw, defaultTimeout)
		return defaultTimeout
	}
	if secs <= 0 {
		return 0
	}
	return time.Duration(secs) * time.Second
}

// ---------- Plaud integration ----------

func cmdPlaud(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: m3c-tools plaud <list|sync|auth> [args]")
		os.Exit(1)
	}
	switch args[0] {
	case "list":
		cmdPlaudList()
	case "sync":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: m3c-tools plaud sync <recording_id>")
			os.Exit(1)
		}
		cmdPlaudSync(args[1])
	case "auth":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Usage: m3c-tools plaud auth <token>")
			fmt.Fprintln(os.Stderr, "       m3c-tools plaud auth login   (extract from Chrome)")
			os.Exit(1)
		}
		if args[1] == "login" {
			cmdPlaudAuthLogin()
		} else {
			cmdPlaudAuth(args[1])
		}
	case "debug":
		cmdPlaudDebugAPI()
	default:
		fmt.Fprintf(os.Stderr, "Unknown plaud subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func cmdPlaudAuthLogin() {
	cfg := plaud.LoadConfig()

	// Try to extract token from an already-open Chrome tab.
	fmt.Println("Checking Chrome for open Plaud tab...")
	token, err := plaud.ExtractTokenFromChrome()
	if err != nil {
		fmt.Printf("Could not extract token: %v\n", err)
		fmt.Println("\nOpening web.plaud.ai — please log in, then run this command again.")
		_ = plaud.OpenPlaudLogin()
		os.Exit(1)
	}

	session := &plaud.TokenSession{Token: token}
	if err := plaud.SaveToken(cfg.TokenPath, session); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving token: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Token extracted from Chrome and saved to %s\n", cfg.TokenPath)

	// Verify the token works.
	client := plaud.NewClient(cfg, token)
	recordings, err := client.ListRecordings()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: token saved but API test failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Authenticated. Found %d recordings.\n", len(recordings))
}

func cmdPlaudAuth(token string) {
	cfg := plaud.LoadConfig()
	session := &plaud.TokenSession{Token: token}
	if err := plaud.SaveToken(cfg.TokenPath, session); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving token: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Token saved to %s\n", cfg.TokenPath)
}

func cmdPlaudDebugAPI() {
	cfg := plaud.LoadConfig()
	session, err := plaud.LoadToken(cfg.TokenPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "No token: %v\n", err)
		os.Exit(1)
	}
	client := plaud.NewClient(cfg, session.Token)

	// Get the full list and find sample IDs.
	body, listErr := client.DebugGet("/file/simple/web?skip=0&limit=100&is_trash=2&is_desc=true")
	if listErr != nil {
		fmt.Fprintf(os.Stderr, "List failed: %v\n", listErr)
		os.Exit(1)
	}
	var listResp struct {
		DataFileList []struct {
			ID      string `json:"id"`
			Name    string `json:"filename"`
			IsTrans bool   `json:"is_trans"`
			IsSumm  bool   `json:"is_summary"`
			Dur     int64  `json:"duration"`
		} `json:"data_file_list"`
	}
	json.Unmarshal(body, &listResp)
	fmt.Printf("Total recordings in list: %d\n", len(listResp.DataFileList))

	// Find one untranscribed and one transcribed recording.
	var sampleID, transID string
	for _, f := range listResp.DataFileList {
		fmt.Printf("  %s  %-30s  dur=%ds  trans=%v  summ=%v\n",
			f.ID[:8], f.Name, f.Dur/1000, f.IsTrans, f.IsSumm)
		if sampleID == "" {
			sampleID = f.ID
		}
		if transID == "" && f.IsTrans {
			transID = f.ID
		}
	}

	// Try detail endpoint for the sample recording.
	endpoints := []string{}
	if sampleID != "" {
		fmt.Printf("\n=== Sample recording: %s ===\n", sampleID)
		endpoints = append(endpoints,
			"/file/detail/"+sampleID,
			"/file/download/"+sampleID,
			"/file/ori/download/"+sampleID,
			"/file/audio/"+sampleID,
		)
	}
	if transID != "" && transID != sampleID {
		fmt.Printf("\n=== Transcribed recording: %s ===\n", transID)
		endpoints = append(endpoints, "/file/detail/"+transID)
	}
	for _, ep := range endpoints {
		fmt.Printf("\n--- GET %s ---\n", ep)
		body, apiErr := client.DebugGet(ep)
		if apiErr != nil {
			fmt.Printf("ERROR: %v\n", apiErr)
			continue
		}
		s := string(body)
		if len(s) > 2000 {
			s = s[:2000] + "..."
		}
		// Pretty-print JSON if possible.
		var pretty json.RawMessage
		if json.Unmarshal(body, &pretty) == nil {
			if pp, ppErr := json.MarshalIndent(pretty, "", "  "); ppErr == nil {
				s = string(pp)
				if len(s) > 3000 {
					s = s[:3000] + "..."
				}
			}
		}
		fmt.Println(s)
	}
}

func cmdPlaudList() {
	cfg := plaud.LoadConfig()
	session, err := plaud.LoadToken(cfg.TokenPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading token: %v\nRun: m3c-tools plaud auth <token>\n", err)
		os.Exit(1)
	}
	client := plaud.NewClient(cfg, session.Token)
	recordings, err := client.ListRecordings()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing recordings: %v\n", err)
		os.Exit(1)
	}

	// Check tracking DB for sync status.
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

	fmt.Printf("Plaud recordings (%d):\n\n", len(recordings))
	for i, rec := range recordings {
		status := "new"
		if filesDB != nil {
			plaudPath := "plaud://" + rec.ID
			if tracked, lookupErr := filesDB.GetByPath(plaudPath); lookupErr == nil && tracked != nil {
				status = tracked.Status
			}
		}
		fmt.Printf("  %3d  %-40s  %6s  %s  [%s]\n",
			i+1,
			truncate(rec.Title, 40),
			plaud.FormatDuration(rec.Duration),
			rec.CreatedAt.Format("2006-01-02"),
			status,
		)
	}
}

func cmdPlaudSync(recordingID string) {
	cfg := plaud.LoadConfig()
	session, err := plaud.LoadToken(cfg.TokenPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading token: %v\nRun: m3c-tools plaud auth <token>\n", err)
		os.Exit(1)
	}
	client := plaud.NewClient(cfg, session.Token)

	var ids []string
	if recordingID == "all" {
		// Sync all recordings that haven't been synced yet.
		recordings, listErr := client.ListRecordings()
		if listErr != nil {
			fmt.Fprintf(os.Stderr, "Error listing recordings: %v\n", listErr)
			os.Exit(1)
		}
		// Check tracking DB to skip already-synced.
		dbPath := defaultFilesDBPath()
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
		fmt.Printf("Syncing %d new recordings (of %d total)...\n", len(ids), len(recordings))
		if len(ids) == 0 {
			fmt.Println("All recordings already synced.")
			return
		}
	} else {
		ids = []string{recordingID}
	}

	summary, err := runPlaudSyncPipeline(client, cfg, ids, defaultFilesDBPath(), nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Sync failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Sync complete: %d synced, %d failed\n", summary.Success, summary.Failed)
}

type plaudSyncSummary struct {
	Total   int
	Success int
	Failed  int
}

func runPlaudSyncPipeline(client *plaud.Client, cfg *plaud.Config, recordingIDs []string, dbPath string, onProgress func(menubar.BulkProgressEvent)) (*plaudSyncSummary, error) {
	filesDB, err := tracking.OpenFilesDB(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open tracking db: %w", err)
	}
	defer filesDB.Close()

	er1Cfg := er1.LoadConfig()
	applyRuntimeER1Context(er1Cfg)
	er1Cfg.ContentType = cfg.ContentType

	summary := &plaudSyncSummary{Total: len(recordingIDs)}

	for i, recID := range recordingIDs {
		itemName := recID

		// ITEM_START
		if onProgress != nil {
			onProgress(menubar.BulkProgressEvent{
				Event:       "ITEM_START",
				Item:        itemName,
				Index:       i + 1,
				Total:       summary.Total,
				CurrentFile: itemName,
				Phase:       menubar.BulkPhaseQueued,
			})
		}

		// 1. Get recording metadata.
		rec, recErr := client.GetRecording(recID)
		if recErr != nil {
			log.Printf("[plaud] get recording %s FAIL: %v", recID, recErr)
			summary.Failed++
			emitPlaudItemDone(onProgress, itemName, i+1, summary, recErr.Error())
			continue
		}
		itemName = rec.Title

		// 2. Download audio.
		if onProgress != nil {
			onProgress(menubar.BulkProgressEvent{
				Event: "ITEM_PHASE", Item: itemName, Index: i + 1,
				Total: summary.Total, Phase: menubar.BulkPhaseImport, CurrentFile: itemName,
			})
		}
		log.Printf("[plaud] downloading audio for %s (%s)...", recID, rec.Title)
		audioData, audioFmt, dlErr := client.DownloadAudio(recID)
		if dlErr != nil {
			log.Printf("[plaud] download %s FAIL: %v", recID, dlErr)
			summary.Failed++
			emitPlaudItemDone(onProgress, itemName, i+1, summary, dlErr.Error())
			continue
		}
		log.Printf("[plaud] downloaded %d bytes (%s)", len(audioData), audioFmt)

		// 3. Get transcript (Plaud-side).
		if onProgress != nil {
			onProgress(menubar.BulkProgressEvent{
				Event: "ITEM_PHASE", Item: itemName, Index: i + 1,
				Total: summary.Total, Phase: menubar.BulkPhaseTranscribe, CurrentFile: itemName,
			})
		}
		var transcriptText string
		tx, txErr := client.GetTranscript(recID)
		if txErr != nil {
			log.Printf("[plaud] no Plaud transcript for %s: %v — saving audio only", recID, txErr)
			transcriptText = "[No transcript available — audio only]"
		} else {
			transcriptText = tx.Text
			if tx.Summary != "" {
				transcriptText = transcriptText + "\n\n=== SUMMARY ===\n" + tx.Summary
			}
			log.Printf("[plaud] got Plaud transcript for %s (%d chars, summary %d chars)", recID, len(tx.Text), len(tx.Summary))
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

		// 5. Upload to ER1.
		if onProgress != nil {
			onProgress(menubar.BulkProgressEvent{
				Event: "ITEM_PHASE", Item: itemName, Index: i + 1,
				Total: summary.Total, Phase: menubar.BulkPhaseUpload, CurrentFile: itemName,
			})
		}
		payload := &er1.UploadPayload{
			TranscriptData:     []byte(strings.TrimSpace(doc) + "\n"),
			TranscriptFilename: fmt.Sprintf("fieldnote_%s.txt", now.Format("20060102_150405")),
			AudioData:          audioData,
			AudioFilename:      fmt.Sprintf("plaud_%s.%s", recID, audioFmt),
			ImageData:          nil, // placeholder injected by upload layer
			ImageFilename:      "placeholder-logo.png",
			Tags:               tags,
			ContentType:        cfg.ContentType,
		}

		resp, upErr := er1.Upload(er1Cfg, payload)
		if upErr != nil {
			log.Printf("[plaud] upload %s FAIL: %v — saving locally", recID, upErr)
			// Fallback: save to ~/plaud-sync/<recID>/ for later re-upload.
			localErr := savePlaudLocally(recID, rec, audioData, audioFmt, doc, transcriptText, tags)
			if localErr != nil {
				log.Printf("[plaud] local save also FAIL: %v", localErr)
				summary.Failed++
				emitPlaudItemDone(onProgress, itemName, i+1, summary, upErr.Error())
				continue
			}
			log.Printf("[plaud] saved locally to ~/plaud-sync/%s/", recID[:8])
			// Record in tracking DB as locally saved.
			audioHash := fmt.Sprintf("%x", sha256.Sum256(audioData))
			plaudPath := "plaud://" + recID
			_, _ = filesDB.RecordFile(plaudPath, audioHash, int64(len(audioData)), "plaud", "")
			_ = filesDB.RecordTranscript(audioHash, "plaud", strings.TrimSpace(transcriptText), "")
			summary.Success++
			if onProgress != nil {
				onProgress(menubar.BulkProgressEvent{
					Event: "ITEM_DONE", Item: itemName, Index: i + 1,
					Total: summary.Total, Outcome: "ok",
					Done: i + 1, Success: summary.Success, Failed: summary.Failed,
					CurrentFile: itemName, Phase: menubar.BulkPhaseDone,
				})
			}
			continue
		}
		log.Printf("[plaud] upload %s DONE doc_id=%s", recID, resp.DocID)

		// 6. Record in tracking DB.
		audioHash := fmt.Sprintf("%x", sha256.Sum256(audioData))
		plaudPath := "plaud://" + recID
		_, _ = filesDB.RecordFile(plaudPath, audioHash, int64(len(audioData)), "plaud", "")
		_ = filesDB.RecordTranscript(audioHash, "plaud", strings.TrimSpace(transcriptText), "")
		_ = filesDB.RecordUploadSuccess(audioHash, "plaud", resp.DocID)

		summary.Success++
		if onProgress != nil {
			onProgress(menubar.BulkProgressEvent{
				Event: "ITEM_DONE", Item: itemName, Index: i + 1,
				Total: summary.Total, Outcome: "ok",
				Done: i + 1, Success: summary.Success, Failed: summary.Failed,
				CurrentFile: itemName, Phase: menubar.BulkPhaseDone,
			})
		}
	}

	return summary, nil
}

// savePlaudLocally saves all captured data for a Plaud recording to ~/plaud-sync/<recID>/
// so it can be re-uploaded to ER1 later.
func savePlaudLocally(recID string, rec *plaud.Recording, audioData []byte, audioFmt string, compositeDoc string, transcriptText string, tags string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("get home dir: %w", err)
	}
	dir := filepath.Join(home, "plaud-sync", recID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create dir: %w", err)
	}

	// Save audio.
	audioPath := filepath.Join(dir, fmt.Sprintf("audio.%s", audioFmt))
	if err := os.WriteFile(audioPath, audioData, 0644); err != nil {
		return fmt.Errorf("write audio: %w", err)
	}

	// Save composite document.
	docPath := filepath.Join(dir, "fieldnote.txt")
	if err := os.WriteFile(docPath, []byte(compositeDoc), 0644); err != nil {
		return fmt.Errorf("write doc: %w", err)
	}

	// Save raw transcript.
	if transcriptText != "" {
		txPath := filepath.Join(dir, "transcript.txt")
		if err := os.WriteFile(txPath, []byte(transcriptText), 0644); err != nil {
			return fmt.Errorf("write transcript: %w", err)
		}
	}

	// Save metadata.
	meta := map[string]interface{}{
		"recording_id": recID,
		"title":        rec.Title,
		"duration":     rec.Duration,
		"created_at":   rec.CreatedAt.Format(time.RFC3339),
		"synced_at":    time.Now().Format(time.RFC3339),
		"tags":         tags,
		"audio_file":   filepath.Base(audioPath),
		"audio_format": audioFmt,
		"audio_size":   len(audioData),
	}
	metaJSON, _ := json.MarshalIndent(meta, "", "  ")
	metaPath := filepath.Join(dir, "metadata.json")
	if err := os.WriteFile(metaPath, metaJSON, 0644); err != nil {
		return fmt.Errorf("write metadata: %w", err)
	}

	return nil
}

func emitPlaudItemDone(onProgress func(menubar.BulkProgressEvent), item string, index int, summary *plaudSyncSummary, errMsg string) {
	if onProgress != nil {
		onProgress(menubar.BulkProgressEvent{
			Event: "ITEM_DONE", Item: item, Index: index,
			Total: summary.Total, Outcome: "failed", Error: errMsg,
			Done: index, Success: summary.Success, Failed: summary.Failed,
			CurrentFile: item, Phase: menubar.BulkPhaseFailed,
		})
	}
}

// menubarHandlePlaudSync handles the Plaud Sync menu action.
func menubarHandlePlaudSync(app *menubar.App) {
	cfg := plaud.LoadConfig()
	session, err := plaud.LoadToken(cfg.TokenPath)
	if err != nil {
		log.Printf("[plaud] no saved token, trying Chrome extraction...")
		token, chromeErr := plaud.ExtractTokenFromChrome()
		if chromeErr != nil {
			log.Printf("[plaud] Chrome extraction failed: %v", chromeErr)
			log.Printf("[plaud] opening web.plaud.ai for login...")
			_ = plaud.OpenPlaudLogin()
			app.Notify("Plaud Sync", "Please log in to web.plaud.ai in Chrome, then try again.")
			return
		}
		// Save the extracted token.
		session = &plaud.TokenSession{Token: token}
		if saveErr := plaud.SaveToken(cfg.TokenPath, session); saveErr != nil {
			log.Printf("[plaud] warning: could not save token: %v", saveErr)
		} else {
			log.Printf("[plaud] token extracted from Chrome and saved")
		}
	}
	client := plaud.NewClient(cfg, session.Token)

	log.Printf("[plaud] fetching recordings...")
	recordings, err := client.ListRecordings()
	if err != nil {
		log.Printf("[plaud] list recordings FAILED: %v", err)
		app.Notify("Plaud Sync Error", err.Error())
		return
	}
	log.Printf("[plaud] found %d recordings", len(recordings))

	// Check each recording against tracking DB.
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

	var records []menubar.PlaudSyncRecord
	for _, rec := range recordings {
		status := "new"
		if filesDB != nil {
			plaudPath := "plaud://" + rec.ID
			if tracked, lookupErr := filesDB.GetByPath(plaudPath); lookupErr == nil && tracked != nil {
				status = tracked.Status
			}
		}
		records = append(records, menubar.PlaudSyncRecord{
			Title:       rec.Title,
			Duration:    plaud.FormatDuration(rec.Duration),
			Date:        rec.CreatedAt.Format("2006-01-02 15:04"),
			Status:      status,
			RecordingID: rec.ID,
		})
	}

	accountInfo := fmt.Sprintf("Plaud — %d recordings", len(recordings))
	menubar.ShowPlaudSyncWindow(records, accountInfo)

	// Register sync callback.
	menubar.SetPlaudSyncCallback(func(action string, recordingIDs []string) {
		if action != "sync" || len(recordingIDs) == 0 {
			return
		}
		log.Printf("[plaud] sync starting for %d recordings", len(recordingIDs))

		// Mark syncing in UI.
		for _, id := range recordingIDs {
			menubar.SetPlaudSyncStatus(id, "syncing")
		}
		menubar.SetPlaudSyncProgress(menubar.BulkRunState{
			Active: true, Total: len(recordingIDs),
		})

		onProgress := func(evt menubar.BulkProgressEvent) {
			state := menubar.BulkRunState{
				Active:      true,
				Total:       evt.Total,
				Done:        evt.Done,
				Success:     evt.Success,
				Failed:      evt.Failed,
				CurrentFile: evt.CurrentFile,
				Phase:       evt.Phase,
			}
			menubar.SetPlaudSyncProgress(state)

			if evt.Event == "ITEM_DONE" {
				status := "synced"
				if evt.Outcome == "failed" {
					status = "failed"
				}
				// Find the recording ID for this item.
				for _, id := range recordingIDs {
					if evt.Item != "" {
						menubar.SetPlaudSyncStatus(id, status)
					}
				}
			}
		}

		summary, syncErr := runPlaudSyncPipeline(client, cfg, recordingIDs, dbPath, onProgress)
		if syncErr != nil {
			log.Printf("[plaud] sync FAILED: %v", syncErr)
			app.Notify("Plaud Sync Failed", syncErr.Error())
		} else {
			log.Printf("[plaud] sync DONE: %d synced, %d failed", summary.Success, summary.Failed)
			app.Notify("Plaud Sync", fmt.Sprintf("Done: %d synced, %d failed", summary.Success, summary.Failed))
		}

		menubar.SetPlaudSyncProgress(menubar.BulkRunState{
			Active: false,
			Total:  summary.Total, Done: summary.Total,
			Success: summary.Success, Failed: summary.Failed,
		})
	})
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
