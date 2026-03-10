// Package importer — configuration for audio import pipeline.
package importer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ImportConfig holds settings for the audio import pipeline,
// loaded from IMPORT_* environment variables.
type ImportConfig struct {
	// AudioSource is the root directory to scan for audio files (IMPORT_AUDIO_SOURCE).
	AudioSource string

	// AudioDest is the destination base directory for imported MEMORY folders (IMPORT_AUDIO_DEST).
	AudioDest string

	// ContentType is the content-type label for ER1 uploads (IMPORT_CONTENT_TYPE).
	ContentType string

	// TrackerFile is the path to the transcript tracker file (IMPORT_TRACKER_FILE).
	TrackerFile string
}

// DefaultImportConfig returns an ImportConfig with default values.
// All paths use ~ expansion relative to the user's home directory.
func DefaultImportConfig() *ImportConfig {
	return &ImportConfig{
		AudioSource: "",
		AudioDest:   "~/ER1",
		ContentType: "Audio-Track vom Diktiergerät",
		TrackerFile: "~/.m3c-tools/transcript_tracker.md",
	}
}

// LoadImportConfig reads import settings from environment variables.
// Missing values fall back to defaults. Tilde (~) prefixes are expanded
// to the user's home directory.
func LoadImportConfig() (*ImportConfig, error) {
	cfg := DefaultImportConfig()

	if v := os.Getenv("IMPORT_AUDIO_SOURCE"); v != "" {
		cfg.AudioSource = v
	}
	if v := os.Getenv("IMPORT_AUDIO_DEST"); v != "" {
		cfg.AudioDest = v
	}
	if v := os.Getenv("IMPORT_CONTENT_TYPE"); v != "" {
		cfg.ContentType = v
	}
	if v := os.Getenv("IMPORT_TRACKER_FILE"); v != "" {
		cfg.TrackerFile = v
	}

	// Expand tilde in all path fields.
	var err error
	if cfg.AudioSource, err = expandTilde(cfg.AudioSource); err != nil {
		return nil, fmt.Errorf("IMPORT_AUDIO_SOURCE: %w", err)
	}
	if cfg.AudioDest, err = expandTilde(cfg.AudioDest); err != nil {
		return nil, fmt.Errorf("IMPORT_AUDIO_DEST: %w", err)
	}
	if cfg.TrackerFile, err = expandTilde(cfg.TrackerFile); err != nil {
		return nil, fmt.Errorf("IMPORT_TRACKER_FILE: %w", err)
	}

	return cfg, nil
}

// Validate checks that required fields are set and paths are plausible.
// Returns an error describing the first problem found, or nil if valid.
func (c *ImportConfig) Validate() error {
	if c.AudioSource == "" {
		return fmt.Errorf("IMPORT_AUDIO_SOURCE is required but not set")
	}
	if c.AudioDest == "" {
		return fmt.Errorf("IMPORT_AUDIO_DEST is required but not set")
	}
	if c.ContentType == "" {
		return fmt.Errorf("IMPORT_CONTENT_TYPE is required but not set")
	}
	if c.TrackerFile == "" {
		return fmt.Errorf("IMPORT_TRACKER_FILE is required but not set")
	}
	return nil
}

// Summary returns a human-readable one-liner for logging.
func (c *ImportConfig) Summary() string {
	src := c.AudioSource
	if src == "" {
		src = "(not set)"
	}
	return fmt.Sprintf("Import: src=%s dest=%s type=%q tracker=%s",
		src, c.AudioDest, c.ContentType, c.TrackerFile)
}

// SourceDir returns the resolved absolute path of the audio source directory.
// Returns an error if AudioSource is empty or cannot be resolved.
func (c *ImportConfig) SourceDir() (string, error) {
	if c.AudioSource == "" {
		return "", fmt.Errorf("IMPORT_AUDIO_SOURCE is not set")
	}
	return filepath.Abs(c.AudioSource)
}

// DestDir returns the resolved absolute path of the audio destination directory.
// Returns an error if AudioDest is empty or cannot be resolved.
func (c *ImportConfig) DestDir() (string, error) {
	if c.AudioDest == "" {
		return "", fmt.Errorf("IMPORT_AUDIO_DEST is not set")
	}
	return filepath.Abs(c.AudioDest)
}

// expandTilde replaces a leading "~/" with the user's home directory.
// Returns the path unchanged if it doesn't start with "~/".
// Returns an empty string unchanged.
func expandTilde(path string) (string, error) {
	if path == "" || !strings.HasPrefix(path, "~/") {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot expand ~: %w", err)
	}
	return filepath.Join(home, path[2:]), nil
}
