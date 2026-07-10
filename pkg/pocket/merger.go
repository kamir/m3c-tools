package pocket

import (
	"errors"
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

// errUnsafeConcatPath is returned when a recording path cannot be safely
// represented as a single ffmpeg concat-demuxer "file '...'" directive.
// Sentinel so callers/tests can match with errors.Is.
var errUnsafeConcatPath = errors.New("unsafe path for ffmpeg concat list")

// concatEscape renders rec path as the body of a single-quoted ffmpeg concat
// "file '...'" directive. The ffmpeg concat demuxer is LINE-oriented: a newline
// (or carriage return) terminates the directive regardless of quoting, so a
// path carrying \n/\r could split the token and inject a second, attacker-chosen
// "file '/etc/passwd'" line — and we run with -safe 0, which disables ffmpeg's
// own path guard. Single-quote escaping ('\'') alone does NOT stop this. We
// therefore reject any path containing a newline, carriage return, or NUL (none
// of which can appear in a legitimate Pocket recording path) and only then apply
// the POSIX single-quote escape for the benign-but-quote-bearing case.
func concatEscape(path string) (string, error) {
	if strings.ContainsAny(path, "\n\r\x00") {
		return "", fmt.Errorf("%w: %q contains a newline, CR, or NUL", errUnsafeConcatPath, path)
	}
	return strings.ReplaceAll(path, "'", "'\\''"), nil
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
		escaped, err := concatEscape(rec.FilePath)
		if err != nil {
			return "", err
		}
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
// Unsafe paths (containing newline/CR/NUL) are silently dropped — callers that
// need to detect rejection should use BuildFileListChecked. This keeps the
// generated list free of injected directives even if used outside MergeGroup.
func BuildFileList(recordings []Recording) string {
	out, _ := BuildFileListChecked(recordings)
	return out
}

// BuildFileListChecked is the error-returning form of BuildFileList: it fails
// closed (errUnsafeConcatPath) on any path that cannot be safely encoded as a
// single concat "file '...'" directive, instead of emitting a list that ffmpeg
// would parse as multiple directives. This is the same guard MergeGroup applies
// before invoking ffmpeg with -safe 0.
func BuildFileListChecked(recordings []Recording) (string, error) {
	var lines []string
	for _, rec := range recordings {
		escaped, err := concatEscape(rec.FilePath)
		if err != nil {
			return "", err
		}
		lines = append(lines, fmt.Sprintf("file '%s'", escaped))
	}
	return strings.Join(lines, "\n") + "\n", nil
}
