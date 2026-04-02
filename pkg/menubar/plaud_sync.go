// plaud_sync.go — Non-darwin stubs for cross-platform compilation.
//
//go:build !darwin

package menubar

import "time"

// BulkRunPhase describes the current phase of a bulk operation.
type BulkRunPhase string

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

// PlaudSyncRecord holds one recording row for the Plaud Sync window.
type PlaudSyncRecord struct {
	Title       string
	Duration    string
	Date        string
	Status      string
	RecordingID string
}

// ShowPlaudSyncWindow is a no-op on non-darwin platforms.
func ShowPlaudSyncWindow(records []PlaudSyncRecord, accountInfo string, defaultTags ...string) {}

// GetPlaudCustomTags returns empty on non-darwin platforms.
func GetPlaudCustomTags() string { return "" }

// SetPlaudSyncStatus is a no-op on non-darwin platforms.
func SetPlaudSyncStatus(recordingID, status string) {}

// SetPlaudSyncProgress is a no-op on non-darwin platforms.
func SetPlaudSyncProgress(state BulkRunState) {}

// IsPlaudSyncWindowOpen always returns false on non-darwin platforms.
func IsPlaudSyncWindowOpen() bool { return false }

// ReloadPlaudSyncTable is a no-op on non-darwin platforms.
func ReloadPlaudSyncTable() {}

// SetPlaudSyncCallback is a no-op on non-darwin platforms.
func SetPlaudSyncCallback(cb func(action string, recordingIDs []string, customTags string)) {}
