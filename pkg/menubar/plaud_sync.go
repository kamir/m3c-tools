// plaud_sync.go — Non-darwin stubs for cross-platform compilation.
//
//go:build !darwin

package menubar

// PlaudSyncRecord holds one recording row for the Plaud Sync window.
type PlaudSyncRecord struct {
	Title       string
	Duration    string
	Date        string
	Status      string
	RecordingID string
}

// ShowPlaudSyncWindow is a no-op on non-darwin platforms.
func ShowPlaudSyncWindow(records []PlaudSyncRecord, accountInfo string) {}

// SetPlaudSyncStatus is a no-op on non-darwin platforms.
func SetPlaudSyncStatus(recordingID, status string) {}

// SetPlaudSyncProgress is a no-op on non-darwin platforms.
func SetPlaudSyncProgress(state BulkRunState) {}

// IsPlaudSyncWindowOpen always returns false on non-darwin platforms.
func IsPlaudSyncWindowOpen() bool { return false }

// ReloadPlaudSyncTable is a no-op on non-darwin platforms.
func ReloadPlaudSyncTable() {}

// SetPlaudSyncCallback is a no-op on non-darwin platforms.
func SetPlaudSyncCallback(cb func(action string, recordingIDs []string)) {}
