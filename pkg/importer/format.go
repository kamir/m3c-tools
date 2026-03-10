// Package importer — scan output formatting with tracking status and parsed tags.
package importer

import (
	"fmt"
	"strings"

	"github.com/kamir/m3c-tools/pkg/impression"
)

// FileStatus represents the tracking state of a scanned file.
type FileStatus string

const (
	StatusNew       FileStatus = "new"       // Not yet processed (untracked).
	StatusImported  FileStatus = "imported"  // Recorded in tracking DB.
	StatusUploaded  FileStatus = "uploaded"  // Successfully uploaded to ER1.
	StatusFailed    FileStatus = "failed"    // Previous import attempt failed.
	StatusDuplicate FileStatus = "duplicate" // Content hash already tracked.
)

// FileEntry combines a scanned audio file with its tracking status and parsed tags.
type FileEntry struct {
	File   AudioFile              // The scanned audio file.
	Status FileStatus             // Tracking status from the DB.
	Tags   []string               // Tags parsed from the filename.
	Info   impression.FilenameInfo // Full parsed filename info.
}

// StatusChecker is a function that checks the tracking status of a file.
// Implementations typically look up the file path or hash in a tracking DB.
// Returns the status string and any error. An empty status means untracked (new).
type StatusChecker func(filePath string) (FileStatus, error)

// BuildFileEntries combines scan results with tracking status and filename-parsed tags.
// If checker is nil, all files are marked as StatusNew.
func BuildFileEntries(result *ScanResult, checker StatusChecker) ([]FileEntry, error) {
	entries := make([]FileEntry, 0, len(result.Files))
	for _, f := range result.Files {
		status := StatusNew
		if checker != nil {
			s, err := checker(f.Path)
			if err != nil {
				return nil, fmt.Errorf("check status for %s: %w", f.Path, err)
			}
			if s != "" {
				status = s
			}
		}

		info := impression.ParseFilename(f.Name)
		entry := FileEntry{
			File:   f,
			Status: status,
			Tags:   info.Tags,
			Info:   info,
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// FormatScanOutput formats a list of FileEntries as a human-readable CLI table
// showing filename, status (tracked/untracked), size, and parsed tags.
func FormatScanOutput(entries []FileEntry, scannedDir string) string {
	if len(entries) == 0 {
		return "No audio files found.\n"
	}

	var b strings.Builder

	// Header
	fmt.Fprintf(&b, "Scanned: %s\n", scannedDir)
	fmt.Fprintf(&b, "Found %d audio file(s):\n\n", len(entries))

	// Calculate column widths for alignment
	maxNameLen := 4 // minimum "Name"
	maxStatusLen := 6 // minimum "Status"
	for _, e := range entries {
		if len(e.File.Name) > maxNameLen {
			maxNameLen = len(e.File.Name)
		}
		sl := len(string(e.Status))
		if sl > maxStatusLen {
			maxStatusLen = sl
		}
	}
	// Cap name width for readability
	if maxNameLen > 50 {
		maxNameLen = 50
	}

	// Table header
	nameHeader := fmt.Sprintf("%-*s", maxNameLen, "Name")
	statusHeader := fmt.Sprintf("%-*s", maxStatusLen, "Status")
	fmt.Fprintf(&b, "  %s  %s  %-10s  %s\n", nameHeader, statusHeader, "Size", "Tags")
	fmt.Fprintf(&b, "  %s  %s  %s  %s\n",
		strings.Repeat("─", maxNameLen),
		strings.Repeat("─", maxStatusLen),
		strings.Repeat("─", 10),
		strings.Repeat("─", 20))

	// Counters
	counts := map[FileStatus]int{}

	for _, e := range entries {
		counts[e.Status]++

		// Truncate long filenames
		name := e.File.Name
		if len(name) > maxNameLen {
			name = name[:maxNameLen-1] + "…"
		}

		// Format size
		sizeStr := formatSize(e.File.Size)

		// Format tags
		tagStr := ""
		if len(e.Tags) > 0 {
			tagStr = strings.Join(e.Tags, ", ")
		}

		// Status indicator
		indicator := statusIndicator(e.Status)

		fmt.Fprintf(&b, "  %-*s  %s %-*s  %-10s  %s\n",
			maxNameLen, name,
			indicator, maxStatusLen-2, string(e.Status), // -2 for indicator+space
			sizeStr,
			tagStr)
	}

	// Summary
	b.WriteByte('\n')
	fmt.Fprintf(&b, "Summary: %d total", len(entries))
	if counts[StatusNew] > 0 {
		fmt.Fprintf(&b, ", %d new", counts[StatusNew])
	}
	if counts[StatusImported] > 0 {
		fmt.Fprintf(&b, ", %d imported", counts[StatusImported])
	}
	if counts[StatusUploaded] > 0 {
		fmt.Fprintf(&b, ", %d uploaded", counts[StatusUploaded])
	}
	if counts[StatusFailed] > 0 {
		fmt.Fprintf(&b, ", %d failed", counts[StatusFailed])
	}
	if counts[StatusDuplicate] > 0 {
		fmt.Fprintf(&b, ", %d duplicate", counts[StatusDuplicate])
	}
	b.WriteByte('\n')

	return b.String()
}

// FormatScanOutputCompact formats entries in a compact single-line-per-file format
// suitable for piping or scripting. Format: STATUS<tab>FILENAME<tab>SIZE<tab>TAGS
func FormatScanOutputCompact(entries []FileEntry) string {
	var b strings.Builder
	for _, e := range entries {
		tagStr := ""
		if len(e.Tags) > 0 {
			tagStr = strings.Join(e.Tags, ",")
		}
		fmt.Fprintf(&b, "%s\t%s\t%d\t%s\n", e.Status, e.File.Path, e.File.Size, tagStr)
	}
	return b.String()
}

// statusIndicator returns a visual indicator character for the tracking status.
func statusIndicator(s FileStatus) string {
	switch s {
	case StatusNew:
		return "+"
	case StatusImported:
		return "✓"
	case StatusUploaded:
		return "↑"
	case StatusFailed:
		return "✗"
	case StatusDuplicate:
		return "="
	default:
		return "?"
	}
}

// formatSize formats a byte count as a human-readable string.
func formatSize(bytes int64) string {
	switch {
	case bytes >= 1024*1024*1024:
		return fmt.Sprintf("%.1f GB", float64(bytes)/(1024*1024*1024))
	case bytes >= 1024*1024:
		return fmt.Sprintf("%.1f MB", float64(bytes)/(1024*1024))
	case bytes >= 1024:
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}
