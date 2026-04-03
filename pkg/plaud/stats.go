package plaud

import (
	"fmt"
	"sort"
	"strings"
)

// SyncStats tracks detailed counters throughout a Plaud sync run.
// Used by FR-0009 (sync progress statistics), FR-0010 (duplicate prevention),
// and FR-0011 (tray notification summary).
type SyncStats struct {
	// LocalTotal is the number of recordings listed from the Plaud cloud.
	LocalTotal int
	// LocalExisting is how many were already in the local tracking DB (skipped).
	LocalExisting int
	// LocalNew is how many recordings remain after local DB dedup (candidates for sync).
	LocalNew int
	// AlreadyInER1 is how many were caught by server-side dedup (SPEC-0117).
	AlreadyInER1 int
	// UploadedNew is how many were successfully uploaded this run.
	UploadedNew int
	// UploadFailed is how many uploads failed.
	UploadFailed int
	// SavedLocally is how many were saved locally as fallback after upload failure.
	SavedLocally int
	// UploadErrors categorizes upload errors by type for diagnostics.
	UploadErrors map[string]int
}

// NewSyncStats creates a SyncStats with initialized maps.
func NewSyncStats() *SyncStats {
	return &SyncStats{
		UploadErrors: make(map[string]int),
	}
}

// RecordUploadError increments the UploadFailed counter and categorizes the error.
func (s *SyncStats) RecordUploadError(err error) {
	s.UploadFailed++
	category := categorizeError(err)
	s.UploadErrors[category]++
}

// TotalProcessed returns the number of recordings that were actually processed
// (uploaded + failed), excluding those skipped by dedup.
func (s *SyncStats) TotalProcessed() int {
	return s.UploadedNew + s.UploadFailed + s.SavedLocally
}

// TotalSkipped returns the number of recordings skipped by either dedup layer.
func (s *SyncStats) TotalSkipped() int {
	return s.LocalExisting + s.AlreadyInER1
}

// FormatSummary returns a formatted multi-line summary block for CLI output.
func (s *SyncStats) FormatSummary() string {
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString("-- Plaud Sync Summary --------------------------\n")
	b.WriteString(fmt.Sprintf("  Total recordings:  %4d\n", s.LocalTotal))
	b.WriteString(fmt.Sprintf("  Already local:     %4d\n", s.LocalExisting))
	if s.AlreadyInER1 > 0 {
		b.WriteString(fmt.Sprintf("  Already in ER1:    %4d\n", s.AlreadyInER1))
	}
	b.WriteString(fmt.Sprintf("  Downloaded (new):  %4d\n", s.LocalNew-s.AlreadyInER1))
	b.WriteString(fmt.Sprintf("  Uploaded (new):    %4d\n", s.UploadedNew))
	if s.SavedLocally > 0 {
		b.WriteString(fmt.Sprintf("  Saved locally:     %4d\n", s.SavedLocally))
	}
	b.WriteString(fmt.Sprintf("  Upload failed:     %4d\n", s.UploadFailed))
	if len(s.UploadErrors) > 0 {
		// Sort error categories for deterministic output.
		cats := make([]string, 0, len(s.UploadErrors))
		for cat := range s.UploadErrors {
			cats = append(cats, cat)
		}
		sort.Strings(cats)
		for _, cat := range cats {
			b.WriteString(fmt.Sprintf("    %s: %d\n", cat, s.UploadErrors[cat]))
		}
	}
	b.WriteString("------------------------------------------------\n")
	return b.String()
}

// FormatNotification returns a compact single-line summary for tray notifications.
func (s *SyncStats) FormatNotification() string {
	if s.UploadFailed > 0 {
		return fmt.Sprintf("Synced %d new, %d failed (of %d total)", s.UploadedNew, s.UploadFailed, s.LocalTotal)
	}
	if s.UploadedNew == 0 {
		return fmt.Sprintf("All %d recordings already synced", s.LocalTotal)
	}
	return fmt.Sprintf("Synced %d new recordings (of %d total)", s.UploadedNew, s.LocalTotal)
}

// categorizeError maps an error to a short category string.
func categorizeError(err error) string {
	if err == nil {
		return "unknown"
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "CSRF"):
		return "csrf"
	case strings.Contains(msg, "401") || strings.Contains(msg, "Unauthorized"):
		return "auth"
	case strings.Contains(msg, "403") || strings.Contains(msg, "Forbidden"):
		return "forbidden"
	case strings.Contains(msg, "timeout") || strings.Contains(msg, "Timeout"):
		return "timeout"
	case strings.Contains(msg, "connection refused"):
		return "connection"
	case strings.Contains(msg, "API_KEY"):
		return "missing-key"
	case strings.Contains(msg, "413") || strings.Contains(msg, "too large"):
		return "too-large"
	default:
		return "other"
	}
}
