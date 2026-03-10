// Package menubar provides types, configuration, and callback interfaces for
// building macOS menu bar applications using the menuet library. It extracts
// reusable patterns from cmd/poc-menubar into a proper library package.
package menubar

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ActionType identifies the kind of menu action triggered by the user.
type ActionType string

const (
	ActionFetchTranscript  ActionType = "fetch_transcript"
	ActionCaptureScreenshot ActionType = "capture_screenshot"
	ActionQuickImpulse     ActionType = "quick_impulse"
	ActionRecordImpression ActionType = "record_impression"
	ActionCopyTranscript   ActionType = "copy_transcript"
	ActionBatchImport      ActionType = "batch_import"
	ActionUploadER1        ActionType = "upload_er1"
	ActionOpenLog          ActionType = "open_log"
	ActionQuit             ActionType = "quit"
)

// Status represents the current operational state of the menu bar app.
type Status string

const (
	StatusIdle       Status = "idle"
	StatusFetching   Status = "fetching"
	StatusUploading  Status = "uploading"
	StatusRecording  Status = "recording"
	StatusError      Status = "error"
)

// HistoryEntry records a completed transcript fetch or upload action.
type HistoryEntry struct {
	VideoID   string
	Language  string
	Timestamp time.Time
	Label     string // display string for the menu, e.g. "🇬🇧 dQw4w9WgXcQ - 2026-03-09 14:30"
}

// NewHistoryEntry creates a HistoryEntry with a formatted label.
func NewHistoryEntry(videoID, langFlag string) HistoryEntry {
	now := time.Now()
	return HistoryEntry{
		VideoID:   videoID,
		Language:  langFlag,
		Timestamp: now,
		Label:     fmt.Sprintf("%s %s - %s", langFlag, videoID, now.Format("2006-01-02 15:04")),
	}
}

// MenuConfig holds the static configuration for the menu bar application.
type MenuConfig struct {
	AppName  string // application display name
	AppLabel string // macOS bundle identifier, e.g. "com.kamir.m3c-tools"
	Title    string // text shown in the menu bar
	IconPath string // absolute path to the menu bar icon (PNG), or empty for text-only
	LogPath  string // path to log file opened by "Open Log File"
}

// DefaultConfig returns a MenuConfig with sensible defaults for m3c-tools.
func DefaultConfig() MenuConfig {
	return MenuConfig{
		AppName:  "M3C Tools",
		AppLabel: "com.kamir.m3c-tools",
		Title:    "M3C",
		IconPath: FindIcon("maindset_icon.png"),
		LogPath:  "/tmp/m3c-tools.log",
	}
}

// ActionCallback is invoked when a menu item is clicked. The ActionType
// identifies the action; the data string carries context (e.g. a video ID).
type ActionCallback func(action ActionType, data string)

// InputPromptFunc shows a dialog to collect text input from the user.
// It returns the entered text and true if confirmed, or ("", false) if cancelled.
type InputPromptFunc func(title, message, placeholder string) (string, bool)

// NotifyFunc sends a user-visible notification with a title and message.
type NotifyFunc func(title, message string)

// AlertFunc shows an alert dialog and returns the button index and input values.
type AlertFunc func(title, info string, buttons []string, inputs []string) (buttonIndex int, inputValues []string)

// Handlers groups the callback functions that the menu bar app invokes
// in response to user interactions. Each field is optional; nil callbacks
// are treated as no-ops.
type Handlers struct {
	// OnAction is called for every menu action (fetch, screenshot, impulse, etc.)
	OnAction ActionCallback

	// Prompt shows a text-input dialog (used for video ID entry).
	Prompt InputPromptFunc

	// Notify sends a macOS notification.
	Notify NotifyFunc

	// Alert shows an alert dialog with buttons and optional text inputs.
	Alert AlertFunc

	// OnUploadER1 performs an ER1 upload for a given video ID. If set,
	// the "Upload to ER1" menu item becomes active.
	OnUploadER1 ER1UploadFunc
}

// ER1UploadFunc is a callback that performs an ER1 upload for the given video ID.
// It returns a result summary and an error. The menu bar app calls this
// asynchronously and updates the status display accordingly.
type ER1UploadFunc func(videoID string) (*ER1UploadResult, error)

// ER1UploadResult captures the outcome of an ER1 upload for display in the menu.
type ER1UploadResult struct {
	VideoID string // video that was uploaded
	DocID   string // ER1 document ID on success
	Message string // human-readable result message
	Queued  bool   // true if the upload was queued for retry (offline)
}

// CleanVideoID extracts a bare YouTube video ID from a URL or raw string.
// It handles youtube.com/watch?v=..., youtu.be/..., and strips query params.
func CleanVideoID(raw string) string {
	if strings.Contains(raw, "youtube.com") || strings.Contains(raw, "youtu.be") {
		if strings.Contains(raw, "v=") {
			parts := strings.Split(raw, "v=")
			raw = parts[len(parts)-1]
		} else if strings.Contains(raw, "youtu.be/") {
			parts := strings.Split(raw, "youtu.be/")
			raw = parts[len(parts)-1]
		}
	}
	raw = strings.Split(raw, "&")[0]
	raw = strings.Split(raw, "?")[0]
	return raw
}

// HistoryStore provides thread-safe storage for transcript history entries.
// It is used by the App but can also be used standalone in tests.
type HistoryStore struct {
	mu      sync.Mutex
	entries []HistoryEntry
}

// Add appends a history entry.
func (s *HistoryStore) Add(entry HistoryEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, entry)
}

// All returns a snapshot of all entries.
func (s *HistoryStore) All() []HistoryEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]HistoryEntry, len(s.entries))
	copy(out, s.entries)
	return out
}

// Len returns the number of entries.
func (s *HistoryStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// Clear removes all entries.
func (s *HistoryStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = nil
}

// CopyToClipboard writes text to the macOS clipboard via pbcopy.
func CopyToClipboard(text string) error {
	cmd := exec.Command("pbcopy")
	cmd.Stdin = strings.NewReader(text)
	return cmd.Run()
}

// FindIcon searches for an icon file by name in common locations:
// the current directory, two levels up (repo root), and next to the executable.
// Returns the absolute path if found, or empty string.
func FindIcon(name string) string {
	candidates := []string{
		name,
		filepath.Join("..", "..", name),
	}
	exe, err := os.Executable()
	if err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), name))
	}
	for _, c := range candidates {
		if abs, err := filepath.Abs(c); err == nil {
			if _, err := os.Stat(abs); err == nil {
				return abs
			}
		}
	}
	return ""
}
