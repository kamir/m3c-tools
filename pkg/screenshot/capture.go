// Package screenshot captures screen images on macOS via the screencapture CLI.
// It also provides clipboard image detection via osascript (AppleScript).
// This package uses only Go stdlib.
package screenshot

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Commander abstracts command execution for testing.
type Commander interface {
	// Run executes a command and returns its combined output and error.
	Run(name string, args ...string) ([]byte, error)
}

// execCommander is the default Commander using os/exec.
type execCommander struct{}

func (e *execCommander) Run(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	return cmd.CombinedOutput()
}

// defaultCmd is the package-level commander used by the free functions.
var defaultCmd Commander = &execCommander{}

// Mode specifies the type of screen capture.
type Mode int

const (
	// FullScreen captures the entire screen.
	FullScreen Mode = iota
	// Window captures a single window (user clicks to select).
	Window
	// Region captures a user-selected rectangular region.
	Region
)

// Options configures a screenshot capture.
type Options struct {
	// Mode selects full-screen, window, or region capture.
	Mode Mode
	// OutputDir overrides the temp directory for the output file.
	// If empty, os.TempDir() is used.
	OutputDir string
	// Filename overrides the generated filename. If empty, a
	// timestamped name is generated.
	Filename string
	// HideCursor hides the cursor in the capture.
	HideCursor bool
	// Silent suppresses the capture sound.
	Silent bool
}

// Capture invokes the macOS screencapture CLI and returns the path to
// the captured PNG file. The caller is responsible for cleaning up the
// file when done.
func Capture(opts Options) (string, error) {
	return CaptureWith(defaultCmd, opts)
}

// CaptureWith invokes screencapture using the provided Commander.
// This variant enables dependency injection for testing.
func CaptureWith(cmd Commander, opts Options) (string, error) {
	// Verify screencapture is available.
	if _, err := exec.LookPath("screencapture"); err != nil {
		return "", fmt.Errorf("screencapture not found: %w (macOS only)", err)
	}

	dir := opts.OutputDir
	if dir == "" {
		dir = os.TempDir()
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create output dir: %w", err)
	}

	filename := opts.Filename
	if filename == "" {
		filename = fmt.Sprintf("m3c-screenshot-%s.png", time.Now().Format("20060102-150405"))
	}
	outPath := filepath.Join(dir, filename)

	args := buildArgs(opts, outPath)

	_, runErr := cmd.Run("screencapture", args...)

	// Check if the output file was actually created — screencapture may
	// return a non-zero exit code on some macOS versions even on success.
	// The file existing is the definitive success signal.
	if _, err := os.Stat(outPath); err != nil {
		if runErr != nil {
			return "", fmt.Errorf("screencapture failed: %w", runErr)
		}
		return "", fmt.Errorf("screenshot not created (capture may have been cancelled): %w", err)
	}

	return outPath, nil
}

// CaptureClipboardFirst performs clipboard-first screenshot capture:
// 1. If the clipboard contains an image, save it directly to outputDir.
// 2. Otherwise, launch interactive region capture.
func CaptureClipboardFirst(outputDir string) (string, error) {
	return CaptureClipboardFirstWith(defaultCmd, outputDir)
}

// CaptureClipboardFirstWith performs clipboard-first capture using the given Commander.
func CaptureClipboardFirstWith(cmd Commander, outputDir string) (string, error) {
	imgType, _ := DetectClipboardImageWith(cmd)
	if imgType != ClipboardNoImage {
		ts := time.Now().Format("20060102-150405")
		filename := fmt.Sprintf("m3c-clipboard-%s.png", ts)
		outPath := filepath.Join(outputDir, filename)
		return ExtractClipboardImageWith(cmd, outPath)
	}

	// Fall back to interactive region capture.
	return CaptureWith(cmd, Options{
		Mode:      Region,
		OutputDir: outputDir,
		Silent:    true,
	})
}

// buildArgs constructs the screencapture CLI arguments.
func buildArgs(opts Options, outPath string) []string {
	var args []string

	switch opts.Mode {
	case Window:
		args = append(args, "-w")
	case Region:
		args = append(args, "-s")
	// FullScreen is the default (no flag needed).
	}

	if opts.HideCursor {
		args = append(args, "-C")
	}
	if opts.Silent {
		args = append(args, "-x")
	}

	// Force PNG format.
	args = append(args, "-t", "png")

	// Output file path must be the last argument.
	args = append(args, outPath)

	return args
}
