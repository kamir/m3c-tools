//go:build darwin

// Package menubar provides types, configuration, and callback interfaces for
// building macOS menu bar applications using the menuet library. It extracts
// reusable patterns from cmd/poc-menubar into a proper library package.
package menubar

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

func defaultLogPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "m3c-tools.log")
	}
	return filepath.Join(home, ".m3c-tools", "m3c-tools.log")
}

// ActionType identifies the kind of menu action triggered by the user.
type ActionType string

const (
	ActionFetchTranscript   ActionType = "fetch_transcript"
	ActionCaptureScreenshot ActionType = "capture_screenshot"
	ActionQuickImpulse      ActionType = "quick_impulse"
	ActionRecordImpression  ActionType = "record_impression"
	ActionCopyTranscript    ActionType = "copy_transcript"
	ActionBatchImport       ActionType = "batch_import"
	ActionUploadER1         ActionType = "upload_er1"
	ActionLoginER1          ActionType = "login_er1"
	ActionLogoutER1         ActionType = "logout_er1"
	ActionShowTrackingDB    ActionType = "show_tracking_db"
	ActionOpenLog           ActionType = "open_log"
	ActionStarGitHub        ActionType = "star_github"
	ActionPlaudSync         ActionType = "plaud_sync"
	ActionPocketSync        ActionType = "pocket_sync"
	ActionQuit              ActionType = "quit"
)

// GitHubRepoURL is the project's GitHub repository URL.
const GitHubRepoURL = "https://github.com/kamir/m3c-tools"

// Status represents the current operational state of the menu bar app.
type Status string

const (
	StatusIdle      Status = "idle"
	StatusFetching  Status = "fetching"
	StatusUploading Status = "uploading"
	StatusRecording Status = "recording"
	StatusError     Status = "error"
)

// BulkRunPhase represents the current step for an audio bulk operation item.
type BulkRunPhase string

const (
	BulkPhaseQueued      BulkRunPhase = "queued"
	BulkPhaseImport      BulkRunPhase = "import"
	BulkPhaseTranscribe  BulkRunPhase = "transcribe"
	BulkPhaseUpload      BulkRunPhase = "upload"
	BulkPhaseDone        BulkRunPhase = "done"
	BulkPhaseFailed      BulkRunPhase = "failed"
	BulkPhaseReprocess   BulkRunPhase = "reprocess"
	BulkPhaseUnavailable BulkRunPhase = "unavailable"
)

// BulkRunState holds live state for a currently running bulk audio operation.
type BulkRunState struct {
	Active      bool
	RunID       string
	Action      string
	Total       int
	Done        int
	Success     int
	Failed      int
	CurrentFile string
	Phase       BulkRunPhase
	StartedAt   time.Time
	LastError   string
}

// BulkProgressEvent is emitted by the bulk runner to synchronize logs + UI.
type BulkProgressEvent struct {
	RunID       string
	Action      string
	Event       string // RUN_START | ITEM_START | ITEM_PHASE | ITEM_DONE | RUN_DONE
	Item        string
	Index       int // 1-based item index when relevant
	Total       int
	Phase       BulkRunPhase
	Outcome     string // ok | failed | skipped
	Done        int
	Success     int
	Failed      int
	Elapsed     time.Duration
	Error       string
	CurrentFile string
}

// Observation represents a unified timeline entry from the tracking DB.
type Observation struct {
	Title       string    // display title (recording title, video ID, filename)
	Type        string    // "plaud", "audio", "transcript", "screenshot", "impulse"
	Status      string    // "imported", "uploaded", "failed"
	DocID       string    // ER1 document ID (for deep-linking)
	ProcessedAt time.Time // when it was processed
	HasTranscript bool
}

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
	// Prefer the new design-system template icon; fall back to the legacy icon.
	icon := FindIcon("menubar-icon.png")
	if icon == "" {
		icon = FindIcon("maindset_icon.png")
	}
	return MenuConfig{
		AppName:  "M3C Tools",
		AppLabel: "com.kamir.m3c-tools",
		Title:    "",
		IconPath: icon,
		LogPath:  defaultLogPath(),
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

	// ListTrackingRecords returns recent tracking DB records for display
	// in the "Tracking DB" submenu. Returns up to limit records.
	ListTrackingRecords func(limit int) ([]TrackingRecord, error)

	// ListRecentObservations returns recent observations across all types
	// for the unified History timeline. Returns up to limit records.
	ListRecentObservations func(limit int) ([]Observation, error)

	// ListProfiles returns available config profiles for the Profile submenu.
	// Returns profiles, active profile name, and any error.
	ListProfiles func() ([]ConfigProfile, string, error)

	// SwitchProfile switches to the named profile and reloads config.
	SwitchProfile func(name string) error

	// OpenProfileEditor launches the local web-based profile settings editor.
	OpenProfileEditor func()
}

// ConfigProfile represents a configuration profile shown in the menubar submenu.
type ConfigProfile struct {
	Name        string
	Description string
	ER1URL      string
	IsActive    bool
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

// videoIDRegexp matches a valid YouTube video ID (11 alphanumeric, hyphen, or underscore chars).
var videoIDRegexp = regexp.MustCompile(`^[A-Za-z0-9_-]{11}$`)

// CleanVideoID extracts a bare YouTube video ID from a URL or raw string.
// It handles youtube.com/watch?v=..., youtu.be/..., and strips query params.
// Returns empty string if the result is not a valid 11-character video ID.
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
	if !videoIDRegexp.MatchString(raw) {
		return ""
	}
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
// the current directory, design/icons/, two levels up (repo root),
// and next to the executable. Returns the absolute path if found, or empty string.
func FindIcon(name string) string {
	candidates := []string{
		name,
		filepath.Join("design", "icons", name),
		filepath.Join("..", "..", name),
		filepath.Join("..", "..", "design", "icons", name),
	}
	exe, err := os.Executable()
	if err == nil {
		exeDir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(exeDir, name),
			filepath.Join(exeDir, "..", "..", "design", "icons", name),
		)
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
