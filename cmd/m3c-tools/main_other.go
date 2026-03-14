// main_other.go — CLI-only entry point for non-macOS platforms.
// GUI features (menu bar, observation window, recording) are not available.
//
//go:build !darwin

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/kamir/m3c-tools/pkg/er1"
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
		fmt.Fprintln(os.Stderr, "TODO: transcript command (cross-platform port in progress)")
		os.Exit(1)
	case "plaud":
		fmt.Fprintln(os.Stderr, "TODO: plaud command (cross-platform port in progress)")
		os.Exit(1)
	case "check-er1":
		fmt.Fprintln(os.Stderr, "TODO: check-er1 command (cross-platform port in progress)")
		os.Exit(1)
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

func printUsage() {
	fmt.Println(`m3c-tools — Multi-Modal-Memory Tools (CLI mode)

Available commands (cross-platform):
  transcript <video_id>  Fetch YouTube transcript
  plaud list|sync|auth   Plaud recording sync
  check-er1              Check ER1 server connectivity
  help                   Show this help

macOS-only commands (not available on this platform):
  menubar                Launch menu bar app
  record                 Record audio
  devices                List audio devices
  screenshot             Capture screenshot
  upload                 Upload to ER1 with media`)
}
