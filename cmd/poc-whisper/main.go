// POC 3: Whisper Transcription via CLI Subprocess
//
// Validates:
//   - Whisper CLI detection and invocation
//   - Audio file transcription via subprocess
//   - JSON output parsing (segments with timing)
//   - Error handling for missing dependencies
//
// Prerequisites:
//   - pip install openai-whisper  (or brew install openai-whisper)
//
// Run: go run ./cmd/poc-whisper <audio_file>
// Run: go run ./cmd/poc-whisper <audio_file> --model base.en
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// WhisperSegment represents a single transcription segment from whisper JSON output.
type WhisperSegment struct {
	ID    int     `json:"id"`
	Start float64 `json:"start"`
	End   float64 `json:"end"`
	Text  string  `json:"text"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <audio_file> [--model <model>]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: %s recording.mp3\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: %s recording.wav --model base.en\n", os.Args[0])
		os.Exit(1)
	}

	audioFile := os.Args[1]
	model := "base"

	// Parse --model flag
	for i := 2; i < len(os.Args); i++ {
		if os.Args[i] == "--model" && i+1 < len(os.Args) {
			model = os.Args[i+1]
			i++
		}
	}

	// Verify audio file exists
	if _, err := os.Stat(audioFile); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: audio file not found: %s\n", audioFile)
		os.Exit(1)
	}

	fmt.Printf("POC Whisper Transcription\n")
	fmt.Printf("  Audio: %s\n", audioFile)
	fmt.Printf("  Model: %s\n\n", model)

	// Step 1: Find whisper binary
	whisperPath, err := findWhisper()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		fmt.Fprintln(os.Stderr, "\nInstall whisper: pip install openai-whisper")
		os.Exit(1)
	}
	fmt.Printf("=== Whisper binary found: %s ===\n", whisperPath)

	// Step 2: Get whisper version
	version, err := getWhisperVersion(whisperPath)
	if err != nil {
		fmt.Printf("  (could not determine version: %v)\n", err)
	} else {
		fmt.Printf("  Version: %s\n", version)
	}

	// Step 3: Transcribe with JSON output
	fmt.Printf("\n=== Transcribing ===\n")
	segments, fullText, err := transcribe(whisperPath, audioFile, model)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error transcribing: %v\n", err)
		os.Exit(1)
	}

	// Step 4: Display results
	fmt.Printf("\n=== Results: %d segments ===\n", len(segments))
	limit := 10
	if len(segments) < limit {
		limit = len(segments)
	}
	for i := 0; i < limit; i++ {
		s := segments[i]
		fmt.Printf("[%6.1fs → %6.1fs] %s\n", s.Start, s.End, strings.TrimSpace(s.Text))
	}
	if len(segments) > limit {
		fmt.Printf("... and %d more segments\n", len(segments)-limit)
	}

	fmt.Printf("\n=== Full text (%d chars) ===\n", len(fullText))
	if len(fullText) > 500 {
		fmt.Println(fullText[:500] + "...")
	} else {
		fmt.Println(fullText)
	}

	fmt.Println("\nPOC whisper transcription: SUCCESS")
}

// findWhisper looks for the whisper binary in standard locations.
func findWhisper() (string, error) {
	// Try PATH first
	if path, err := exec.LookPath("whisper"); err == nil {
		return path, nil
	}

	// Try common homebrew/pip locations
	pocHome, _ := os.UserHomeDir()
	candidates := []string{
		"/opt/homebrew/bin/whisper",
		"/usr/local/bin/whisper",
		filepath.Join(pocHome, ".local", "bin", "whisper"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}

	return "", fmt.Errorf("whisper binary not found in PATH or common locations")
}

// getWhisperVersion returns the whisper version string.
func getWhisperVersion(whisperPath string) (string, error) {
	cmd := exec.Command(whisperPath, "--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// transcribe runs whisper on the audio file and returns parsed segments and full text.
func transcribe(whisperPath string, audioFile string, model string) ([]WhisperSegment, string, error) {
	// Create temp dir for whisper output
	tmpDir, err := os.MkdirTemp("", "yt-whisper-poc-*")
	if err != nil {
		return nil, "", fmt.Errorf("create temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Run whisper with JSON output format
	cmd := exec.Command(whisperPath,
		audioFile,
		"--model", model,
		"--output_format", "json",
		"--output_dir", tmpDir,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	fmt.Printf("  Running: %s\n", strings.Join(cmd.Args, " "))
	if err := cmd.Run(); err != nil {
		return nil, "", fmt.Errorf("whisper command failed: %w", err)
	}

	// Find the JSON output file
	base := strings.TrimSuffix(filepath.Base(audioFile), filepath.Ext(audioFile))
	jsonPath := filepath.Join(tmpDir, base+".json")

	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, "", fmt.Errorf("read whisper JSON output: %w", err)
	}

	// Parse whisper JSON output
	var whisperOutput struct {
		Text     string           `json:"text"`
		Segments []WhisperSegment `json:"segments"`
	}
	if err := json.Unmarshal(jsonData, &whisperOutput); err != nil {
		return nil, "", fmt.Errorf("parse whisper JSON: %w", err)
	}

	return whisperOutput.Segments, whisperOutput.Text, nil
}
