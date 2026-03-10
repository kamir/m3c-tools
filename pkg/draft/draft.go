// Package draft handles saving and loading capture drafts.
//
// When a user clicks "Cancel (Save Draft)" in the Observation Window,
// the current capture state is serialized to JSON and saved under
// ~/.m3c-tools/drafts/. Drafts can be resumed later without data loss.
package draft

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// DefaultDraftsDir returns the default drafts directory: ~/.m3c-tools/drafts/
func DefaultDraftsDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.TempDir()
	}
	return filepath.Join(home, ".m3c-tools", "drafts")
}

// Channel identifies the capture channel that produced the draft.
type Channel string

const (
	ChannelScreenshot Channel = "screenshot" // Channel B
	ChannelTranscript Channel = "transcript" // Channel A
	ChannelImpulse    Channel = "impulse"    // Channel C
	ChannelImport     Channel = "import"     // Channel D
)

// Draft holds the serializable state of a capture that was cancelled
// before being uploaded to ER1.
type Draft struct {
	// ID is a unique identifier for this draft (timestamp-based).
	ID string `json:"id"`

	// Channel identifies which capture flow produced this draft.
	Channel Channel `json:"channel"`

	// Tags are the user-entered tags at the time of cancellation.
	Tags []string `json:"tags,omitempty"`

	// Notes are the user-entered summary/notes text.
	Notes string `json:"notes,omitempty"`

	// ScreenshotPath is the path to the captured screenshot image (Channel B).
	ScreenshotPath string `json:"screenshot_path,omitempty"`

	// TranscriptText is the transcript content (if available).
	TranscriptText string `json:"transcript_text,omitempty"`

	// RecordingPath is the path to the audio recording file (if any).
	RecordingPath string `json:"recording_path,omitempty"`

	// VideoID is the YouTube video ID (Channel A).
	VideoID string `json:"video_id,omitempty"`

	// ContentType is the observation type label (e.g. "Screenshot", "Progress").
	ContentType string `json:"content_type,omitempty"`

	// CreatedAt is when the draft was saved.
	CreatedAt time.Time `json:"created_at"`
}

// Save writes the draft as a JSON file to the specified directory.
// The filename is derived from the draft ID. The directory is created
// if it does not exist. Returns the full path of the saved file.
func Save(dir string, d *Draft) (string, error) {
	if d.ID == "" {
		d.ID = generateID()
	}
	if d.CreatedAt.IsZero() {
		d.CreatedAt = time.Now()
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("draft: create dir %s: %w", dir, err)
	}

	filename := fmt.Sprintf("draft-%s.json", d.ID)
	path := filepath.Join(dir, filename)

	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return "", fmt.Errorf("draft: marshal: %w", err)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", fmt.Errorf("draft: write %s: %w", path, err)
	}

	return path, nil
}

// SaveToDefault saves the draft to the default drafts directory.
func SaveToDefault(d *Draft) (string, error) {
	return Save(DefaultDraftsDir(), d)
}

// Load reads a draft from a JSON file.
func Load(path string) (*Draft, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("draft: read %s: %w", path, err)
	}

	var d Draft
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("draft: unmarshal %s: %w", path, err)
	}

	return &d, nil
}

// List returns all draft files in the given directory, sorted by name
// (which is timestamp-based, so effectively sorted by creation time).
func List(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // no drafts dir yet
		}
		return nil, fmt.Errorf("draft: list %s: %w", dir, err)
	}

	var paths []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if filepath.Ext(e.Name()) == ".json" {
			paths = append(paths, filepath.Join(dir, e.Name()))
		}
	}
	return paths, nil
}

// generateID creates a unique draft ID based on the current timestamp.
func generateID() string {
	return time.Now().Format("20060102-150405.000")
}
