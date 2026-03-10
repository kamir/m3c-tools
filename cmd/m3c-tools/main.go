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
//	m3c-tools menubar [--title M3C] [--icon path.png] [--log /tmp/m3c-tools.log]
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kamir/m3c-tools/pkg/er1"
	"github.com/kamir/m3c-tools/pkg/importer"
	"github.com/kamir/m3c-tools/pkg/impression"
	"github.com/kamir/m3c-tools/pkg/menubar"
	"github.com/kamir/m3c-tools/pkg/recorder"
	"github.com/kamir/m3c-tools/pkg/screenshot"
	"github.com/kamir/m3c-tools/pkg/tracking"
	"github.com/kamir/m3c-tools/pkg/transcript"
	"github.com/kamir/m3c-tools/pkg/whisper"
)

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

  menubar                Launch macOS menu bar app
    --title <text>         Menu bar title (default: M3C)
    --icon <path>          Menu bar icon PNG path
    --log <path>           Log file path (default: /tmp/m3c-tools.log)`)
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
		summary, err := runAudioImportPipeline(dir, dbPath, "", nil)
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

func runAudioImportPipeline(sourceDir, dbPath, onlySourcePath string, app *menubar.App) (*audioImportRunSummary, error) {
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

	result, err := importer.ImportAudio(cfg, filesDB, nil)
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

	normalizedOnly := strings.TrimSpace(onlySourcePath)
	er1Cfg := er1.LoadConfig()
	applyRuntimeER1Context(er1Cfg)

	for _, imp := range result.Imported {
		if normalizedOnly != "" && !samePath(imp.Source, normalizedOnly) {
			continue
		}
		if app != nil {
			app.SetStatus(menubar.StatusUploading)
		}

		audioData, readErr := os.ReadFile(imp.Dest)
		if readErr != nil {
			summary.Failed++
			_ = filesDB.UpdateStatus(imp.Hash, "audio", "failed")
			log.Printf("[import] failed reading imported audio: %s error=%v", imp.Dest, readErr)
			continue
		}

		model := menubarWhisperModel()
		lang := menubarWhisperLanguage()
		timeout := menubarWhisperTimeout()
		log.Printf("[import] whisper START source=%s model=%s language=%s", imp.Source, model, lang)
		text, txErr := whisper.TranscribeTextWithTimeout(imp.Dest, model, lang, timeout)
		if txErr != nil {
			text = fmt.Sprintf("[Transcription failed: %v]", txErr)
			log.Printf("[import] whisper FAIL source=%s error=%v", imp.Source, txErr)
		} else {
			log.Printf("[import] whisper DONE source=%s chars=%d", imp.Source, len(text))
		}

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

		resp, upErr := er1.Upload(er1Cfg, payload)
		if upErr != nil {
			summary.Failed++
			_ = filesDB.UpdateStatus(imp.Hash, "audio", "failed")
			_, _ = er1.HandleUploadFailure(er1.DefaultQueuePath(), er1.DefaultMemoryPath(), imp.MemoryID, payload, imp.Tags, upErr)
			log.Printf("[import] upload FAIL source=%s error=%v", imp.Source, upErr)
			continue
		}

		summary.Uploaded++
		_ = filesDB.UpdateMemoryID(imp.Hash, "audio", resp.DocID)
		log.Printf("[import] upload DONE source=%s doc_id=%s", imp.Source, resp.DocID)
	}

	if app != nil {
		app.SetStatus(menubar.StatusIdle)
	}
	return summary, nil
}

func samePath(a, b string) bool {
	aa, _ := filepath.Abs(strings.TrimSpace(a))
	bb, _ := filepath.Abs(strings.TrimSpace(b))
	return aa != "" && bb != "" && aa == bb
}

func defaultFilesDBPath() string {
	dir := filepath.Join(os.Getenv("HOME"), ".m3c-tools")
	os.MkdirAll(dir, 0755)
	return filepath.Join(dir, "tracking.db")
}

// -- menubar command --

func cmdMenubar(args []string) {
	cfg := menubar.DefaultConfig()

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
		}
	}

	// Open log file for writing so "Open Log File" has something to show.
	logFile, err := os.OpenFile(cfg.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: cannot open log file %s: %v\n", cfg.LogPath, err)
	} else {
		log.SetOutput(logFile)
		log.SetFlags(log.Ldate | log.Ltime)
	}

	// Create transcript fetcher for the Fetch Transcript menu item.
	fetcher := menubar.NewTranscriptFetcher()

	app := menubar.NewAppWithConfig(cfg, menubar.Handlers{
		OnUploadER1: menubarUploadER1,
	})
	app.SetAuthSession(menubar.AuthSession{})
	startAudioImportListRefresher(app)
	if ctxID, err := loadPersistedER1Session(); err != nil {
		log.Printf("[auth] persisted session load failed: %v", err)
	} else if ctxID != "" {
		setRuntimeER1Login(ctxID)
		app.SetAuthSession(menubar.AuthSession{LoggedIn: true, UserID: ctxID})
		log.Printf("[auth] restored persisted session context_id=%s", ctxID)
	}
	menubar.StartFrontmostAppTracker()
	if exe, err := os.Executable(); err == nil {
		log.Printf("[diag] pid=%d exe=%q screen_access=%v screenshot_mode=%s", os.Getpid(), exe, menubar.HasScreenCaptureAccess(), screenshotCaptureMode())
	}
	maybePreloadWhisper()

	// Wire OnAction to dispatch menu actions to real implementations.
	app.Handlers.OnAction = func(action menubar.ActionType, data string) {
		log.Printf("[menubar] action=%s data=%q", action, data)
		switch action {
		case menubar.ActionFetchTranscript:
			go menubarFetchTranscriptAndTrack(app, fetcher, data)
		case menubar.ActionCaptureScreenshot:
			go menubarCaptureScreenshot(app)
		case menubar.ActionCopyTranscript:
			// data is the video ID; re-fetch and copy
			go fetcher.FetchAndDisplay(app, data)
		case menubar.ActionRecordImpression:
			go menubarRecordImpression(app, data)
		case menubar.ActionQuickImpulse:
			go menubarQuickImpulse(app)
		case menubar.ActionBatchImport:
			go menubarHandleBatchImportAction(app, data)
		case menubar.ActionLoginER1:
			go menubarLoginER1(app)
		case menubar.ActionLogoutER1:
			go menubarLogoutER1(app)
		}
	}

	log.Printf("Launching menu bar app (title=%q, icon=%q, log=%q)", cfg.Title, cfg.IconPath, cfg.LogPath)
	app.Run()
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
	entries, entriesErr := importer.BuildFileEntries(scan, importer.StatusCheckerFromDB(filesDB, "audio"))
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
	switch strings.TrimSpace(data) {
	case "__refresh__":
		app.SetAudioImportState(buildAudioImportState())
		app.Notify("Audio Import", "List refreshed.")
		return
	case "__run_all__", "":
		app.SetStatus(menubar.StatusUploading)
		summary, err := runAudioImportPipeline("", defaultFilesDBPath(), "", app)
		if err != nil {
			app.SetStatus(menubar.StatusError)
			app.Notify("Audio Import Failed", err.Error())
			app.SetAudioImportState(buildAudioImportState())
			return
		}
		app.SetStatus(menubar.StatusIdle)
		app.Notify("Audio Import", fmt.Sprintf("Imported=%d Uploaded=%d Failed=%d", summary.Imported, summary.Uploaded, summary.Failed))
		app.SetAudioImportState(buildAudioImportState())
		return
	default:
		app.SetStatus(menubar.StatusUploading)
		summary, err := runAudioImportPipeline("", defaultFilesDBPath(), data, app)
		if err != nil {
			app.SetStatus(menubar.StatusError)
			app.Notify("Audio Import Failed", err.Error())
			app.SetAudioImportState(buildAudioImportState())
			return
		}
		app.SetStatus(menubar.StatusIdle)
		app.Notify("Audio Import", fmt.Sprintf("Imported=%d Uploaded=%d Failed=%d", summary.Imported, summary.Uploaded, summary.Failed))
		app.SetAudioImportState(buildAudioImportState())
	}
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
				// Fallback: inspect Chrome tabs for memory URLs on ER1 host.
				ctxID = menubar.SuggestedServiceContextID(baseURL)
			}
			if completeER1Login(app, ctxID) {
				return
			}
			log.Printf("[auth] callback received but no context_id yet; continuing tab polling")
		case <-poll.C:
			ctxID := menubar.SuggestedServiceContextID(baseURL)
			if completeER1Login(app, ctxID) {
				return
			}
		case <-deadline.C:
			log.Printf("[auth] login timed out waiting for callback/context; addr=%s", callbackServer.Addr)
			app.Notify("ER1 Login", "Timed out waiting for login confirmation.")
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
	log.Printf("[auth] login success context_id=%s", ctxID)
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
	addr := ln.Addr().String()
	callbackURL := "http://" + addr + "/m3c-login-success"
	resultCh := make(chan loginCallbackResult, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/m3c-login-success", func(w http.ResponseWriter, r *http.Request) {
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

	tags := fmt.Sprintf("progress, youtube, %s", result.VideoID)
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

	app.SetStatus(menubar.StatusRecording)
	menubar.StartRecordingTimer()
	menubar.SetRecordSourceLabel("  video " + result.VideoID + "  ")
	observationRecordAndUpload(app, "progress", thumbnailPath, imgData, impression.Progress)

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

// observationRecordAndUpload starts background recording with VU meter and
// registers the Stop/Store/Cancel callbacks for the Observation Window pipeline.
// The Observation Window must already be shown before calling this function.
func observationRecordAndUpload(app *menubar.App, label string, imgPath string, imgData []byte, obsType impression.ObservationType) {
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

		// Build structured memo text with metadata + transcript + notes section.
		sizeKB := float64(wavSize) / 1024.0
		peakPct := float64(stats.PeakAmplitude) / 32768.0 * 100
		memo := fmt.Sprintf(
			"--- Metadata ---\nChannel: %s\nDate: %s\nRecording: %.1fs, %.1f KB, peak %.0f%%\nWhisper: %s model, %d chars in %s\n\n--- Transcript ---\n%s\n\n--- Notes ---\n",
			label,
			time.Now().Format("2006-01-02 15:04:05"),
			duration, sizeKB, peakPct,
			model, len(text), whisperElapsed.Round(time.Millisecond),
			text,
		)
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
		if len(uploadAudioData) == 0 {
			log.Printf("[%s] store requested but upload audio is empty", label)
			app.Notify("No Audio Available", "Please record again before storing.")
			app.SetStatus(menubar.StatusError)
			return
		}

		now := time.Now()
		ts := now.Format("20060102_150405")

		// Read the final memo text (user may have edited it).
		memoText := menubar.GetReviewMemoText()
		if memoText == "" {
			memoText = transcribedText
		}
		memoText = mergeCaptureMemoAndNotes(memoText, notes)

		doc := &impression.CompositeDoc{
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
	const defaultTimeout = 120 * time.Second

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
