package er1

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// MemoryFolder represents a local MEMORY directory created on ER1 upload failure.
// It stores the payload files locally so they can be retried later.
type MemoryFolder struct {
	Path     string // full path to the MEMORY-{timestamp}/ directory
	MemoryID string // e.g. "MEMORY-20260309-120000"
}

// DefaultMemoryPath returns the default root directory for MEMORY folders.
// Uses ER1_MEMORY_PATH env var, falling back to ~/.m3c-tools/MEMORY.
func DefaultMemoryPath() string {
	if v := os.Getenv("ER1_MEMORY_PATH"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".m3c-tools", "MEMORY")
	}
	return filepath.Join(home, ".m3c-tools", "MEMORY")
}

// MemoryID generates a MEMORY folder name from a timestamp.
// Format: MEMORY-YYYYMMDD-HHMMSS
func MemoryID(t time.Time) string {
	return fmt.Sprintf("MEMORY-%s", t.Format("20060102-150405"))
}

// CreateMemoryFolder creates a MEMORY directory for storing payload files
// when an ER1 upload fails. It is idempotent: if the folder already exists,
// it returns the existing folder without error.
//
// The folder is created at {rootDir}/MEMORY-{YYYYMMDD_HHMMSS}/.
// If rootDir is empty, DefaultMemoryPath() is used.
func CreateMemoryFolder(rootDir string, t time.Time) (*MemoryFolder, error) {
	if rootDir == "" {
		rootDir = DefaultMemoryPath()
	}

	memID := MemoryID(t)
	folderPath := filepath.Join(rootDir, memID)

	// MkdirAll is idempotent — succeeds if directory already exists
	if err := os.MkdirAll(folderPath, 0700); err != nil {
		return nil, fmt.Errorf("create memory folder %s: %w", folderPath, err)
	}

	return &MemoryFolder{
		Path:     folderPath,
		MemoryID: memID,
	}, nil
}

// WriteTranscript writes transcript content to the MEMORY folder.
func (m *MemoryFolder) WriteTranscript(data []byte, filename string) error {
	return os.WriteFile(filepath.Join(m.Path, filename), data, 0644)
}

// WriteAudio writes audio data to the MEMORY folder.
func (m *MemoryFolder) WriteAudio(data []byte, filename string) error {
	return os.WriteFile(filepath.Join(m.Path, filename), data, 0644)
}

// WriteImage writes image data to the MEMORY folder.
func (m *MemoryFolder) WriteImage(data []byte, filename string) error {
	return os.WriteFile(filepath.Join(m.Path, filename), data, 0644)
}

// WriteTags writes tags (one per line) to tag.txt in the MEMORY folder.
func (m *MemoryFolder) WriteTags(tags []string) error {
	var content []byte
	for _, tag := range tags {
		content = append(content, []byte(tag+"\n")...)
	}
	return os.WriteFile(filepath.Join(m.Path, "tag.txt"), content, 0644)
}

// SavePayload persists an entire UploadPayload into the MEMORY folder,
// writing transcript, audio, image, and tags files.
func (m *MemoryFolder) SavePayload(payload *UploadPayload) error {
	if err := m.WriteTranscript(payload.TranscriptData, payload.TranscriptFilename); err != nil {
		return fmt.Errorf("write transcript: %w", err)
	}

	if payload.AudioData != nil {
		if err := m.WriteAudio(payload.AudioData, payload.AudioFilename); err != nil {
			return fmt.Errorf("write audio: %w", err)
		}
	}

	if payload.ImageData != nil {
		if err := m.WriteImage(payload.ImageData, payload.ImageFilename); err != nil {
			return fmt.Errorf("write image: %w", err)
		}
	}

	if payload.Tags != "" {
		tags := splitTagsMemory(payload.Tags)
		if err := m.WriteTags(tags); err != nil {
			return fmt.Errorf("write tags: %w", err)
		}
	}

	return nil
}

// splitTagsMemory splits a comma-separated tag string into trimmed, non-empty tags.
func splitTagsMemory(tagStr string) []string {
	parts := strings.Split(tagStr, ",")
	var result []string
	for _, p := range parts {
		s := strings.TrimSpace(p)
		if s != "" {
			result = append(result, s)
		}
	}
	return result
}

