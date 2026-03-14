// main_other.go — CLI-only entry point for non-macOS platforms.
// GUI features (menu bar, observation window, recording) are not available.
//
//go:build !darwin

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/kamir/m3c-tools/pkg/er1"
	"github.com/kamir/m3c-tools/pkg/plaud"
	"github.com/kamir/m3c-tools/pkg/transcript"
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
	case "plaud":
		cmdPlaud(os.Args[2:])
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
			fmt.Fprintln(os.Stderr, "Usage: m3c-tools plaud sync <recording_id>")
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
		fmt.Println("Make sure Chrome is running with --remote-debugging-port=9222")
		fmt.Println("and you are logged in to plaud.ai")
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

// cmdPlaudSync downloads a recording's audio and transcript.
func cmdPlaudSync(recordingID string) {
	cfg := plaud.LoadConfig()
	session, err := plaud.LoadToken(cfg.TokenPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading token: %v\nRun: m3c-tools plaud auth login\n", err)
		os.Exit(1)
	}

	client := plaud.NewClient(cfg, session.Token)

	fmt.Printf("Fetching recording %s...\n", recordingID)
	rec, err := client.GetRecording(recordingID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching recording: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  Title: %s\n  Duration: %ds\n  Status: %s\n", rec.Title, rec.Duration, rec.Status)

	fmt.Println("Downloading audio...")
	audio, format, err := client.DownloadAudio(recordingID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error downloading audio: %v\n", err)
	} else {
		outPath := fmt.Sprintf("%s.%s", recordingID, format)
		if err := os.WriteFile(outPath, audio, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing audio: %v\n", err)
		} else {
			fmt.Printf("  Audio saved: %s (%d bytes)\n", outPath, len(audio))
		}
	}

	fmt.Println("Fetching transcript...")
	tr, err := client.GetTranscript(recordingID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching transcript: %v\n", err)
	} else {
		outPath := recordingID + ".txt"
		content := tr.Text
		if tr.Summary != "" {
			content = "=== SUMMARY ===\n" + tr.Summary + "\n\n=== TRANSCRIPT ===\n" + content
		}
		if err := os.WriteFile(outPath, []byte(content), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing transcript: %v\n", err)
		} else {
			fmt.Printf("  Transcript saved: %s\n", outPath)
		}
	}

	fmt.Println("Done.")
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
  transcript <video_id>  Fetch YouTube transcript
    --lang <code>         Language code (default: en)
    --format <fmt>        Output format: text, json, srt, webvtt (default: text)
    --list                List available transcripts
  plaud list|sync|auth   Plaud recording sync
    auth login            Extract token from Chrome (CDP)
    auth <token>          Set token directly
    list                  List all recordings
    sync <id>             Download audio + transcript
  check-er1              Check ER1 server connectivity
  help                   Show this help

macOS-only commands (not available on this platform):
  menubar                Launch menu bar app
  record                 Record audio
  devices                List audio devices
  screenshot             Capture screenshot
  upload                 Upload to ER1 with media`)
}
