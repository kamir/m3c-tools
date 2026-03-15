// Package whisper provides speech-to-text transcription via the whisper CLI.
package whisper

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
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

// ProgressEvent reports real-time transcription progress from whisper's verbose output.
type ProgressEvent struct {
	SegmentIndex int     // 0-based segment counter
	StartTime    float64 // segment start in seconds
	EndTime      float64 // segment end in seconds
	Text         string  // decoded text for this segment
}

// ProgressFunc is called for each segment whisper decodes when verbose mode is enabled.
type ProgressFunc func(event ProgressEvent)

// segmentLineRE matches whisper's verbose output: [00:00.000 --> 00:05.120]  Some text...
var segmentLineRE = regexp.MustCompile(`^\[(\d+:\d+\.\d+)\s*-->\s*(\d+:\d+\.\d+)\]\s*(.*)$`)

// parseTimestamp parses "MM:SS.mmm" or "HH:MM:SS.mmm" into seconds.
func parseTimestamp(s string) float64 {
	parts := strings.Split(s, ":")
	switch len(parts) {
	case 2: // MM:SS.mmm
		m, _ := strconv.ParseFloat(parts[0], 64)
		sec, _ := strconv.ParseFloat(parts[1], 64)
		return m*60 + sec
	case 3: // HH:MM:SS.mmm
		h, _ := strconv.ParseFloat(parts[0], 64)
		m, _ := strconv.ParseFloat(parts[1], 64)
		sec, _ := strconv.ParseFloat(parts[2], 64)
		return h*3600 + m*60 + sec
	}
	return 0
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
	return TranscribeWithProgress(context.Background(), audioPath, model, language, nil)
}

// TranscribeWithContext runs whisper with cancellation/timeout support.
func TranscribeWithContext(ctx context.Context, audioPath string, model string, language string) (*Result, error) {
	return TranscribeWithProgress(ctx, audioPath, model, language, nil)
}

// TranscribeWithProgress runs whisper in verbose mode, calling onProgress for
// each decoded segment. If onProgress is nil, segments are logged to the
// standard logger. Stderr output from whisper is always logged.
func TranscribeWithProgress(ctx context.Context, audioPath string, model string, language string, onProgress ProgressFunc) (*Result, error) {
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
		"--verbose", "True",
	}
	if language != "" {
		args = append(args, "--language", language)
	}

	cmd := exec.CommandContext(ctx, whisperPath, args...)

	// Force Python to use unbuffered stdout so segment lines appear immediately
	// when piped. Without this, Python fully buffers stdout (~8KB) when not
	// connected to a TTY, delaying segment output until the buffer fills or
	// the process exits.
	cmd.Env = append(os.Environ(), "PYTHONUNBUFFERED=1")

	// Capture stdout for segment lines (whisper prints verbose segments to stdout).
	stdoutPipe, stdoutPipeErr := cmd.StdoutPipe()
	if stdoutPipeErr != nil {
		cmd.Stdout = os.Stdout
	}

	// Capture stderr for warnings/errors (model loading, FP16 fallback, etc.).
	stderrPipe, stderrPipeErr := cmd.StderrPipe()
	if stderrPipeErr != nil {
		cmd.Stderr = os.Stderr
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("whisper start: %w", err)
	}

	// Heartbeat: log every 15s while whisper is running so the user knows it's alive.
	whisperStart := time.Now()
	heartbeatDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-heartbeatDone:
				return
			case <-ticker.C:
				log.Printf("[whisper] still transcribing %s ... elapsed=%s",
					filepath.Base(audioPath), time.Since(whisperStart).Round(time.Second))
			}
		}
	}()

	// Parse stdout for segment lines (whisper prints "[HH:MM.mmm --> HH:MM.mmm] text" to stdout).
	stdoutDone := make(chan struct{})
	go func() {
		defer close(stdoutDone)
		if stdoutPipeErr != nil {
			return
		}
		scanner := bufio.NewScanner(stdoutPipe)
		segIdx := 0
		for scanner.Scan() {
			line := scanner.Text()
			if m := segmentLineRE.FindStringSubmatch(line); m != nil {
				start := parseTimestamp(m[1])
				end := parseTimestamp(m[2])
				text := strings.TrimSpace(m[3])
				evt := ProgressEvent{
					SegmentIndex: segIdx,
					StartTime:    start,
					EndTime:      end,
					Text:         text,
				}
				segIdx++
				if onProgress != nil {
					onProgress(evt)
				} else {
					log.Printf("[whisper] segment %d [%.1fs-%.1fs] %s", evt.SegmentIndex, evt.StartTime, evt.EndTime, evt.Text)
				}
			}
		}
	}()

	// Parse stderr for warnings and errors — log everything.
	stderrDone := make(chan struct{})
	go func() {
		defer close(stderrDone)
		if stderrPipeErr != nil {
			return
		}
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			log.Printf("[whisper] %s", scanner.Text())
		}
	}()

	// Wait for both pipe goroutines to finish before cmd.Wait (avoid pipe races).
	<-stdoutDone
	<-stderrDone
	close(heartbeatDone)

	if err := cmd.Wait(); err != nil {
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
	return TranscribeTextWithTimeoutProgress(audioPath, model, language, timeout, nil)
}

// TranscribeTextWithTimeoutProgress transcribes with a timeout and optional progress callback.
// When onProgress is non-nil, it is called for each decoded segment. When nil, segments
// are logged to the standard logger at [whisper] prefix.
func TranscribeTextWithTimeoutProgress(audioPath string, model string, language string, timeout time.Duration, onProgress ProgressFunc) (string, error) {
	ctx := context.Background()
	cancel := func() {}
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()

	result, err := TranscribeWithProgress(ctx, audioPath, model, language, onProgress)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(result.Text), nil
}
