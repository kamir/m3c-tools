package pocket

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ffmpegPaths are common locations for ffmpeg on macOS (menubar apps have restricted PATH).
var ffmpegPaths = []string{
	"ffmpeg", // system PATH
	"/opt/homebrew/bin/ffmpeg",
	"/usr/local/bin/ffmpeg",
	"/usr/bin/ffmpeg",
}

// findFFmpeg returns the path to ffmpeg, checking common locations.
func findFFmpeg() (string, error) {
	for _, p := range ffmpegPaths {
		if path, err := exec.LookPath(p); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("ffmpeg not found — install with: brew install ffmpeg")
}

// MergeGroup concatenates recordings in a group into a single MP3.
// Uses ffmpeg concat demuxer: ffmpeg -f concat -safe 0 -i list.txt -c copy output.mp3
// Returns the path to the merged file.
func MergeGroup(group RecordingGroup, outputDir string) (string, error) {
	if len(group.Recordings) == 0 {
		return "", fmt.Errorf("empty group")
	}
	if len(group.Recordings) == 1 {
		return group.Recordings[0].FilePath, nil
	}

	ffmpeg, err := findFFmpeg()
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", fmt.Errorf("creating output dir: %w", err)
	}

	// Build concat file list
	listPath := filepath.Join(outputDir, group.ID+"_filelist.txt")
	var lines []string
	for _, rec := range group.Recordings {
		escaped := strings.ReplaceAll(rec.FilePath, "'", "'\\''")
		lines = append(lines, fmt.Sprintf("file '%s'", escaped))
	}
	if err := os.WriteFile(listPath, []byte(strings.Join(lines, "\n")+"\n"), 0644); err != nil {
		return "", fmt.Errorf("writing file list: %w", err)
	}
	defer os.Remove(listPath)

	outputPath := filepath.Join(outputDir, group.ID+".mp3")

	cmd := exec.Command(ffmpeg,
		"-f", "concat",
		"-safe", "0",
		"-i", listPath,
		"-c", "copy",
		"-y",
		outputPath,
	)
	cmd.Stderr = os.Stderr

	log.Printf("[pocket] merging %d recordings → %s (using %s)", len(group.Recordings), outputPath, ffmpeg)
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("ffmpeg merge failed: %w (ffmpeg=%s)", err, ffmpeg)
	}

	info, _ := os.Stat(outputPath)
	if info != nil {
		log.Printf("[pocket] merged file: %s (%d bytes)", outputPath, info.Size())
	}

	return outputPath, nil
}

// BuildFileList generates the ffmpeg concat file list content (for testing).
func BuildFileList(recordings []Recording) string {
	var lines []string
	for _, rec := range recordings {
		escaped := strings.ReplaceAll(rec.FilePath, "'", "'\\''")
		lines = append(lines, fmt.Sprintf("file '%s'", escaped))
	}
	return strings.Join(lines, "\n") + "\n"
}
