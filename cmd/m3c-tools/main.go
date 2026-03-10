// m3c-tools — Multi-Modal-Memory Tools
//
// CLI entry point for transcript fetching, voice recording,
// and ER1 upload. Also serves as the menu bar app when run with --menubar.
//
// Usage:
//   m3c-tools transcript <video_id> [--lang en] [--format text|srt|json|webvtt] [--translate de]
//   m3c-tools upload <video_id> [--audio file.wav] [--image file.jpg]
//   m3c-tools record [output.wav] [--duration 5]
//   m3c-tools whisper <audio_file> [--model base] [--language en]
//   m3c-tools devices
//   m3c-tools thumbnail <video_id> [--output file.jpg]
//   m3c-tools retry [--interval 30] [--max-retries 10]
//   m3c-tools check-er1
//   m3c-tools menubar [--title M3C] [--icon path.png] [--log /tmp/m3c-tools.log]
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kamir/m3c-tools/pkg/er1"
	"github.com/kamir/m3c-tools/pkg/impression"
	"github.com/kamir/m3c-tools/pkg/importer"
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

  import-audio <dir>     Scan directory for audio files
    --extensions           List supported audio extensions
    --compact              Machine-readable output (TSV: status, path, size, tags)
    --db <path>            Tracking DB path (default: ~/.m3c-tools/tracking.db)

  menubar                Launch macOS menu bar app
    --title <text>         Menu bar title (default: M3C)
    --icon <path>          Menu bar icon PNG path
    --log <path>           Log file path (default: /tmp/m3c-tools.log)`)
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
			if i+1 < len(args) { lang = args[i+1]; i++ }
		case "--format":
			if i+1 < len(args) { format = args[i+1]; i++ }
		case "--translate":
			if i+1 < len(args) { translateLang = args[i+1]; i++ }
		case "--list":
			listOnly = true
		case "--exclude-generated":
			excludeGenerated = true
		case "--exclude-manually-created":
			excludeManuallyCreated = true
		case "--proxy-url":
			if i+1 < len(args) { proxyURL = args[i+1]; i++ }
		case "--proxy-auth":
			if i+1 < len(args) { proxyAuth = args[i+1]; i++ }
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
			if i+1 < len(args) { audioPath = args[i+1]; i++ }
		case "--impression":
			if i+1 < len(args) { impressionText = args[i+1]; i++ }
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
			if i+1 < len(args) { model = args[i+1]; i++ }
		case "--language":
			if i+1 < len(args) { language = args[i+1]; i++ }
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
			output = args[i+1]; i++
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
	dbPath := defaultFilesDBPath()
	dir := ""

	for i := 0; i < len(args); i++ {
		switch args[i] {
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
			fmt.Fprintln(os.Stderr, "Usage: m3c-tools import-audio <directory> [--extensions] [--compact] [--db <path>]")
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

	// Wire OnAction to dispatch menu actions to real implementations.
	app.Handlers.OnAction = func(action menubar.ActionType, data string) {
		log.Printf("[menubar] action=%s data=%q", action, data)
		switch action {
		case menubar.ActionFetchTranscript:
			go fetcher.FetchAndDisplay(app, data)
		case menubar.ActionCaptureScreenshot:
			go menubarCaptureScreenshot(app)
		case menubar.ActionCopyTranscript:
			// data is the video ID; re-fetch and copy
			go fetcher.FetchAndDisplay(app, data)
		case menubar.ActionQuickImpulse:
			go menubarQuickImpulse(app)
		}
	}

	log.Printf("Launching menu bar app (title=%q, icon=%q, log=%q)", cfg.Title, cfg.IconPath, cfg.LogPath)
	app.Run()
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

// menubarCaptureScreenshot performs the full Idea observation flow:
// 1. Clipboard-first screenshot capture
// 2. Record voice note (5s via microphone)
// 3. Transcribe voice note via whisper
// 4. Build composite doc (screenshot + transcription)
// 5. Upload to ER1
func menubarCaptureScreenshot(app *menubar.App) {
	// Step 1: Capture screenshot
	app.SetStatus(menubar.StatusRecording)
	imgPath, err := screenshot.CaptureClipboardFirst(os.TempDir())
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

	// Step 2: Record voice note
	audioData, transcribedText := menubarRecordAndTranscribe(app, "screenshot")

	// Step 3: Build composite doc
	now := time.Now()
	ts := now.Format("20060102_150405")
	doc := &impression.CompositeDoc{
		ImpressionText: transcribedText,
		ObsType:        impression.Idea,
		Timestamp:      now,
	}
	composite := doc.Build()

	// Step 4: Upload to ER1
	app.SetStatus(menubar.StatusUploading)
	tags := impression.BuildTags(impression.Idea)
	payload := &er1.UploadPayload{
		TranscriptData:     []byte(composite),
		TranscriptFilename: fmt.Sprintf("idea_%s.txt", ts),
		AudioData:          audioData,
		AudioFilename:      fmt.Sprintf("idea_%s.wav", ts),
		ImageData:          imgData,
		ImageFilename:      filepath.Base(imgPath),
		Tags:               tags,
	}
	menubarUploadPayload(app, "screenshot", payload, tags)
}

// menubarQuickImpulse performs the full Impulse observation flow:
// 1. Interactive region screenshot
// 2. Record voice note (5s via microphone)
// 3. Transcribe voice note via whisper
// 4. Build composite doc (screenshot + transcription)
// 5. Upload to ER1
func menubarQuickImpulse(app *menubar.App) {
	// Step 1: Region screenshot
	app.SetStatus(menubar.StatusRecording)
	imgPath, err := screenshot.Capture(screenshot.Options{
		Mode:   screenshot.Region,
		Silent: true,
	})
	if err != nil {
		app.SetStatus(menubar.StatusIdle)
		log.Printf("[impulse] screenshot cancelled or failed: %v", err)
		return
	}
	log.Printf("[impulse] screenshot: %s", imgPath)

	imgData, _ := os.ReadFile(imgPath)

	// Step 2: Record voice note
	audioData, transcribedText := menubarRecordAndTranscribe(app, "impulse")

	// Step 3: Build composite doc
	now := time.Now()
	ts := now.Format("20060102_150405")
	doc := &impression.CompositeDoc{
		ImpressionText: transcribedText,
		ObsType:        impression.Impulse,
		Timestamp:      now,
	}
	composite := doc.Build()

	// Step 4: Upload to ER1
	app.SetStatus(menubar.StatusUploading)
	tags := impression.BuildTags(impression.Impulse)
	payload := &er1.UploadPayload{
		TranscriptData:     []byte(composite),
		TranscriptFilename: fmt.Sprintf("impulse_%s.txt", ts),
		AudioData:          audioData,
		AudioFilename:      fmt.Sprintf("impulse_%s.wav", ts),
		ImageData:          imgData,
		ImageFilename:      filepath.Base(imgPath),
		Tags:               tags,
	}
	menubarUploadPayload(app, "impulse", payload, tags)
}

// menubarRecordAndTranscribe shows a recording confirmation dialog, records
// a voice note from the microphone (user-controlled stop), and transcribes
// it via whisper. Returns audio WAV bytes and transcribed text.
// On any failure or if the user skips, returns nil/empty (non-fatal).
func menubarRecordAndTranscribe(app *menubar.App, label string) ([]byte, string) {
	const maxRecordSeconds = 120 // safety cap

	// Show recording confirmation dialog
	if !app.ConfirmRecording() {
		log.Printf("[%s] user skipped voice recording", label)
		return nil, ""
	}

	// Start recording in a goroutine with a stop channel
	app.SetStatus(menubar.StatusRecording)
	log.Printf("[%s] recording voice note (user-controlled stop, max %ds)...", label, maxRecordSeconds)

	stopCh := make(chan struct{})
	var audioData []byte
	var recErr error
	done := make(chan struct{})

	go func() {
		audioData, recErr = recorder.RecordTimedWithStop(stopCh, maxRecordSeconds)
		close(done)
	}()

	// Show blocking "Stop Recording" dialog — returns when user clicks Stop
	app.ShowStopRecording()

	// Signal the recorder to stop
	close(stopCh)
	<-done // wait for recorder goroutine to finish

	if recErr != nil {
		log.Printf("[%s] recording failed: %v (continuing without audio)", label, recErr)
		app.Notify("Recording Failed", fmt.Sprintf("Error: %v", recErr))
		return nil, ""
	}

	// Compute recording details from WAV data (44-byte header + PCM)
	wavSize := len(audioData)
	pcmBytes := wavSize - 44 // WAV header is 44 bytes
	if pcmBytes < 0 {
		pcmBytes = 0
	}
	sampleCount := pcmBytes / (recorder.BitsPerSample / 8)
	duration := float64(sampleCount) / float64(recorder.SampleRate)

	// Decode samples for peak amplitude
	samples := recorder.DecodePCM16(audioData[44:])
	stats := recorder.Stats(samples)

	log.Printf("[%s] recorded %.1fs (%d bytes, peak=%d)", label, duration, wavSize, stats.PeakAmplitude)

	// Show recording details dialog
	sizeKB := float64(wavSize) / 1024.0
	peakPct := float64(stats.PeakAmplitude) / 32768.0 * 100
	details := fmt.Sprintf(
		"Duration: %.1f seconds\nFile size: %.1f KB\nSample rate: %d Hz\nBit depth: %d-bit\nChannels: %d (mono)\nSamples: %d\nPeak amplitude: %d (%.1f%%)",
		duration, sizeKB, recorder.SampleRate, recorder.BitsPerSample, recorder.Channels,
		sampleCount, stats.PeakAmplitude, peakPct,
	)
	if stats.PeakAmplitude < 100 {
		details += "\n\n⚠️ Very low audio levels — check microphone permissions"
	}
	app.ShowRecordingDetails(details)

	// Write WAV to temp file for whisper
	wavPath := filepath.Join(os.TempDir(), fmt.Sprintf("m3c-%s-%d.wav", label, time.Now().UnixNano()))
	if err := os.WriteFile(wavPath, audioData, 0644); err != nil {
		log.Printf("[%s] write WAV failed: %v", label, err)
		return audioData, ""
	}
	defer os.Remove(wavPath)

	// Transcribe via whisper
	app.SetStatus(menubar.StatusFetching)
	model := os.Getenv("YT_WHISPER_MODEL")
	if model == "" {
		model = "base"
	}
	language := os.Getenv("YT_WHISPER_LANGUAGE")

	log.Printf("[%s] whisper START: file=%s model=%s language=%q", label, wavPath, model, language)
	whisperStart := time.Now()

	text, err := whisper.TranscribeText(wavPath, model, language)
	whisperElapsed := time.Since(whisperStart)

	if err != nil {
		log.Printf("[%s] whisper FAILED after %s: %v (continuing without transcription)", label, whisperElapsed, err)
		app.Notify("Whisper Failed", fmt.Sprintf("Error: %v", err))
		return audioData, ""
	}
	log.Printf("[%s] whisper DONE in %s: %d chars transcribed", label, whisperElapsed, len(text))
	log.Printf("[%s] transcription: %q", label, text)
	app.Notify("✅ Transcription Complete", fmt.Sprintf("%d characters in %s", len(text), whisperElapsed.Round(time.Millisecond)))

	return audioData, text
}

// menubarUploadPayload uploads a payload to ER1, queuing on failure.
func menubarUploadPayload(app *menubar.App, label string, payload *er1.UploadPayload, tags string) {
	cfg := er1.LoadConfig()
	resp, err := er1.Upload(cfg, payload)
	if err != nil {
		log.Printf("[%s] ER1 upload failed (queuing): %v", label, err)
		queuePath := er1.DefaultQueuePath()
		er1.EnqueueFailure(queuePath, label, payload, tags, err)
		app.SetStatus(menubar.StatusIdle)
		return
	}
	log.Printf("[%s] uploaded to ER1: doc_id=%s", label, resp.DocID)
	app.SetStatus(menubar.StatusIdle)
}
