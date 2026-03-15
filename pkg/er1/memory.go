package er1

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// memoryMeta holds metadata fields that aren't part of the file content
// but must be preserved for lossless retry.
type memoryMeta struct {
	ContentType        string `json:"content_type,omitempty"`
	DocID              string `json:"doc_id,omitempty"`
	TranscriptFilename string `json:"transcript_filename,omitempty"`
	AudioFilename      string `json:"audio_filename,omitempty"`
	ImageFilename      string `json:"image_filename,omitempty"`
}

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
	return os.WriteFile(filepath.Join(m.Path, filename), data, 0600)
}

// WriteAudio writes audio data to the MEMORY folder.
func (m *MemoryFolder) WriteAudio(data []byte, filename string) error {
	return os.WriteFile(filepath.Join(m.Path, filename), data, 0600)
}

// WriteImage writes image data to the MEMORY folder.
func (m *MemoryFolder) WriteImage(data []byte, filename string) error {
	return os.WriteFile(filepath.Join(m.Path, filename), data, 0600)
}

// WriteTags writes tags (one per line) to tag.txt in the MEMORY folder.
func (m *MemoryFolder) WriteTags(tags []string) error {
	var content []byte
	for _, tag := range tags {
		content = append(content, []byte(tag+"\n")...)
	}
	return os.WriteFile(filepath.Join(m.Path, "tag.txt"), content, 0600)
}

// SavePayload persists an entire UploadPayload into the MEMORY folder,
// writing transcript, audio, image, tags, and metadata files.
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

	// Save metadata for lossless retry (content_type, doc_id, filenames).
	meta := memoryMeta{
		ContentType:        payload.ContentType,
		DocID:              payload.DocID,
		TranscriptFilename: payload.TranscriptFilename,
		AudioFilename:      payload.AudioFilename,
		ImageFilename:      payload.ImageFilename,
	}
	metaBytes, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}
	if err := os.WriteFile(filepath.Join(m.Path, "metadata.json"), metaBytes, 0600); err != nil {
		return fmt.Errorf("write metadata: %w", err)
	}

	return nil
}

// LoadPayload reads the saved files from a MEMORY folder and reconstructs an UploadPayload.
// It first checks for metadata.json (written by SavePayload) to identify exact filenames
// and restore ContentType/DocID. For legacy MEMORY folders without metadata.json, it falls
// back to scanning by file extension.
func (m *MemoryFolder) LoadPayload() (*UploadPayload, error) {
	entries, err := os.ReadDir(m.Path)
	if err != nil {
		return nil, fmt.Errorf("read memory folder: %w", err)
	}

	// Try to load metadata.json first for exact file matching.
	var meta memoryMeta
	metaPath := filepath.Join(m.Path, "metadata.json")
	if metaBytes, err := os.ReadFile(metaPath); err == nil {
		_ = json.Unmarshal(metaBytes, &meta)
	}

	payload := &UploadPayload{
		ContentType: meta.ContentType,
		DocID:       meta.DocID,
	}

	// If metadata knows the exact filenames, load them directly.
	if meta.TranscriptFilename != "" {
		data, err := os.ReadFile(filepath.Join(m.Path, meta.TranscriptFilename))
		if err != nil {
			return nil, fmt.Errorf("read transcript %s: %w", meta.TranscriptFilename, err)
		}
		payload.TranscriptData = data
		payload.TranscriptFilename = meta.TranscriptFilename
	}
	if meta.AudioFilename != "" {
		data, err := os.ReadFile(filepath.Join(m.Path, meta.AudioFilename))
		if err != nil {
			return nil, fmt.Errorf("read audio %s: %w", meta.AudioFilename, err)
		}
		payload.AudioData = data
		payload.AudioFilename = meta.AudioFilename
	}
	if meta.ImageFilename != "" {
		data, err := os.ReadFile(filepath.Join(m.Path, meta.ImageFilename))
		if err != nil {
			return nil, fmt.Errorf("read image %s: %w", meta.ImageFilename, err)
		}
		payload.ImageData = data
		payload.ImageFilename = meta.ImageFilename
	}

	// Scan remaining files for tags and any fields not already set by metadata.
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		fpath := filepath.Join(m.Path, name)

		switch {
		case name == "tag.txt":
			data, err := os.ReadFile(fpath)
			if err != nil {
				return nil, fmt.Errorf("read tags: %w", err)
			}
			var tags []string
			for _, line := range strings.Split(string(data), "\n") {
				t := strings.TrimSpace(line)
				if t != "" {
					tags = append(tags, t)
				}
			}
			payload.Tags = strings.Join(tags, ",")

		case name == "metadata.json":
			continue // already handled

		case strings.HasSuffix(name, ".txt"):
			if payload.TranscriptData != nil {
				continue // already loaded from metadata
			}
			data, err := os.ReadFile(fpath)
			if err != nil {
				return nil, fmt.Errorf("read transcript: %w", err)
			}
			payload.TranscriptData = data
			payload.TranscriptFilename = name

		case strings.HasSuffix(name, ".mp3"),
			strings.HasSuffix(name, ".wav"),
			strings.HasSuffix(name, ".ogg"),
			strings.HasSuffix(name, ".m4a"):
			if payload.AudioData != nil {
				continue // already loaded from metadata
			}
			data, err := os.ReadFile(fpath)
			if err != nil {
				return nil, fmt.Errorf("read audio: %w", err)
			}
			payload.AudioData = data
			payload.AudioFilename = name

		case strings.HasSuffix(name, ".png"),
			strings.HasSuffix(name, ".jpg"),
			strings.HasSuffix(name, ".jpeg"):
			if payload.ImageData != nil {
				continue // already loaded from metadata
			}
			data, err := os.ReadFile(fpath)
			if err != nil {
				return nil, fmt.Errorf("read image: %w", err)
			}
			payload.ImageData = data
			payload.ImageFilename = name
		}
	}

	if payload.TranscriptData == nil {
		return nil, fmt.Errorf("no transcript file found in %s", m.Path)
	}

	return payload, nil
}

// ListMemoryFolders returns all MEMORY-* folders in the given root directory.
func ListMemoryFolders(rootDir string) ([]*MemoryFolder, error) {
	if rootDir == "" {
		rootDir = DefaultMemoryPath()
	}
	entries, err := os.ReadDir(rootDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var folders []*MemoryFolder
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "MEMORY-") {
			folders = append(folders, &MemoryFolder{
				Path:     filepath.Join(rootDir, e.Name()),
				MemoryID: e.Name(),
			})
		}
	}
	return folders, nil
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

