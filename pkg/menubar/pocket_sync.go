// pocket_sync.go — Non-darwin stubs for cross-platform compilation.
//
//go:build !darwin

package menubar

// ShowPocketSyncWindow is a no-op on non-darwin platforms.
func ShowPocketSyncWindow(records []PocketSyncRecord, deviceInfo string, defaultTags ...string) {}

// GetPocketCustomTags returns empty on non-darwin platforms.
func GetPocketCustomTags() string { return "" }

// SetPocketSyncStatus is a no-op on non-darwin platforms.
func SetPocketSyncStatus(filePath, status string) {}

// SetPocketSyncProgress is a no-op on non-darwin platforms.
func SetPocketSyncProgress(state BulkRunState) {}

// IsPocketSyncWindowOpen always returns false on non-darwin platforms.
func IsPocketSyncWindowOpen() bool { return false }

// ReloadPocketSyncTable is a no-op on non-darwin platforms.
func ReloadPocketSyncTable() {}

// SetPocketStatusText is a no-op on non-darwin platforms.
func SetPocketStatusText(text string) {}

// SetPocketSyncCallback is a no-op on non-darwin platforms.
func SetPocketSyncCallback(cb func(action string, filePaths []string, customTags string)) {}

// CollapseGroupInTable is a no-op on non-darwin platforms.
func CollapseGroupInTable(memberFilePaths []string, groupTitle, duration, size, status, docID string) {}
