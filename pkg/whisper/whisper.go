// Package whisper provides speech-to-text transcription via the whisper CLI.
package whisper

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
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

// VenvDir returns the path to the m3c-tools Python virtual environment.
func VenvDir() string {
	return filepath.Join(os.Getenv("HOME"), ".m3c-tools", "venv")
}

// VenvWhisperPath returns the path to the whisper binary in the m3c-tools venv.
func VenvWhisperPath() string {
	return filepath.Join(VenvDir(), "bin", "whisper")
}

// FindBinary looks for the whisper binary in the m3c-tools venv first,
// then falls back to PATH and common system locations.
func FindBinary() (string, error) {
	// Priority 1: m3c-tools dedicated venv (created by `m3c-tools setup`)
	if venvPath := VenvWhisperPath(); fileExists(venvPath) {
		return venvPath, nil
	}
	// Priority 2: system PATH
	if path, err := exec.LookPath("whisper"); err == nil {
		return path, nil
	}
	// Priority 3: common install locations
	candidates := []string{
		"/opt/homebrew/bin/whisper",
		"/usr/local/bin/whisper",
		filepath.Join(os.Getenv("HOME"), ".local/bin/whisper"),
	}
	for _, c := range candidates {
		if fileExists(c) {
			return c, nil
		}
	}
	return "", fmt.Errorf("whisper binary not found (run 'm3c-tools setup' to install)")
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Transcribe runs whisper on an audio file and returns the parsed result.
func Transcribe(audioPath string, model string, language string) (*Result, error) {
	return TranscribeWithContext(context.Background(), audioPath, model, language)
}

// TranscribeWithContext runs whisper with cancellation/timeout support.
func TranscribeWithContext(ctx context.Context, audioPath string, model string, language string) (*Result, error) {
	whisperPath, err := FindBinary()
	if err != nil {
		return nil, err
	}

	tmpDir, err := os.MkdirTemp("", "yt-whisper-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	args := []string{
		audioPath,
		"--model", model,
		"--output_format", "json",
		"--output_dir", tmpDir,
	}
	if language != "" {
		args = append(args, "--language", language)
	}

	cmd := exec.CommandContext(ctx, whisperPath, args...)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("whisper timed out: %w", err)
		}
		if ctx.Err() == context.Canceled {
			return nil, fmt.Errorf("whisper canceled: %w", err)
		}
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

// TranscribeTextWithTimeout transcribes with a hard timeout.
func TranscribeTextWithTimeout(audioPath string, model string, language string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		return TranscribeText(audioPath, model, language)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	result, err := TranscribeWithContext(ctx, audioPath, model, language)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(result.Text), nil
}
