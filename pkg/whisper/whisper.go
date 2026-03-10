// Package whisper provides speech-to-text transcription via the whisper CLI.
package whisper

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Segment represents a single transcription segment with timing.
type Segment struct {
	ID    int     `json:"id"`
	Start float64 `json:"start"`
	End   float64 `json:"end"`
	Text  string  `json:"text"`
}

// Result holds the full transcription result.
type Result struct {
	Text     string    `json:"text"`
	Segments []Segment `json:"segments"`
	Language string    `json:"language"`
}

// FindBinary looks for the whisper binary in PATH and common locations.
func FindBinary() (string, error) {
	if path, err := exec.LookPath("whisper"); err == nil {
		return path, nil
	}
	candidates := []string{
		"/opt/homebrew/bin/whisper",
		"/usr/local/bin/whisper",
		filepath.Join(os.Getenv("HOME"), ".local/bin/whisper"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", fmt.Errorf("whisper binary not found")
}

// Transcribe runs whisper on an audio file and returns the parsed result.
func Transcribe(audioPath string, model string, language string) (*Result, error) {
	whisperPath, err := FindBinary()
	if err != nil {
		return nil, err
	}

	tmpDir, err := os.MkdirTemp("", "yt-whisper-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	args := []string{
		audioPath,
		"--model", model,
		"--output_format", "json",
		"--output_dir", tmpDir,
	}
	if language != "" {
		args = append(args, "--language", language)
	}

	cmd := exec.Command(whisperPath, args...)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("whisper failed: %w", err)
	}

	// Find JSON output
	base := strings.TrimSuffix(filepath.Base(audioPath), filepath.Ext(audioPath))
	jsonPath := filepath.Join(tmpDir, base+".json")

	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, fmt.Errorf("read whisper output: %w", err)
	}

	var result Result
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("parse whisper output: %w", err)
	}
	return &result, nil
}

// TranscribeText is a convenience function that returns just the text.
func TranscribeText(audioPath string, model string, language string) (string, error) {
	result, err := Transcribe(audioPath, model, language)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(result.Text), nil
}
