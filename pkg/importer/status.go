// Package importer — tracked/untracked status detection for discovered files.
//
// StatusCheckerFromDB creates a StatusChecker that compares discovered files
// against the tracking database (processed_files table) to determine whether
// each file is new (untracked), already imported, uploaded, failed, or a
// content-duplicate of a previously tracked file.
package importer

import (
	"fmt"
	"log"
	"os"

	"github.com/kamir/m3c-tools/pkg/tracking"
)

// StatusCheckerFromDB returns a StatusChecker that queries a tracking.FilesDB
// to determine the status of each discovered file. The checker uses a two-phase
// lookup strategy:
//
//  1. Path lookup — fast check if the exact file path is already recorded.
//  2. Hash lookup — if the path is new, compute SHA-256 and check whether the
//     same content was imported from a different path (duplicate detection).
//
// If the DB is nil, the returned checker always returns StatusNew (all files
// appear untracked). This supports graceful degradation when the DB is
// unavailable.
//
// The importType parameter scopes the check (e.g., "audio", "screenshot").
// If empty, it defaults to "audio".
func StatusCheckerFromDB(db *tracking.FilesDB, importType string) StatusChecker {
	if db == nil {
		return func(filePath string) (FileStatus, error) {
			return StatusNew, nil
		}
	}

	if importType == "" {
		importType = "audio"
	}

	return func(filePath string) (FileStatus, error) {
		// Phase 1: path-based lookup (fast, no I/O beyond DB query).
		rec, err := db.GetByPath(filePath)
		if err != nil {
			return "", fmt.Errorf("path lookup: %w", err)
		}
		if rec != nil {
			return dbStatusToFileStatus(rec.Status), nil
		}

		// Phase 2: hash-based duplicate detection.
		// Only hash if the file still exists on disk.
		if _, statErr := os.Stat(filePath); statErr != nil {
			// File doesn't exist on disk — treat as new (scanner may have
			// found it just before deletion).
			return StatusNew, nil
		}

		hash, err := tracking.HashFile(filePath)
		if err != nil {
			// Hash failure is non-fatal: log and treat as new.
			log.Printf("WARN status-checker hash failed for %s: %v", filePath, err)
			return StatusNew, nil
		}

		processed, err := db.IsFileProcessed(hash, importType)
		if err != nil {
			return "", fmt.Errorf("hash lookup: %w", err)
		}
		if processed {
			return StatusDuplicate, nil
		}

		return StatusNew, nil
	}
}

// StatusCheckerFromDBPathOnly returns a StatusChecker that only performs
// path-based lookups (no content hashing). This is faster but won't detect
// content duplicates across different file paths. Useful when performance
// matters more than duplicate detection (e.g., large directories).
func StatusCheckerFromDBPathOnly(db *tracking.FilesDB) StatusChecker {
	if db == nil {
		return func(filePath string) (FileStatus, error) {
			return StatusNew, nil
		}
	}

	return func(filePath string) (FileStatus, error) {
		rec, err := db.GetByPath(filePath)
		if err != nil {
			return "", fmt.Errorf("path lookup: %w", err)
		}
		if rec == nil {
			return StatusNew, nil
		}
		return dbStatusToFileStatus(rec.Status), nil
	}
}

// StatusSummary holds aggregate counts of file statuses from a scan.
type StatusSummary struct {
	Total     int // Total files scanned.
	New       int // Untracked files (not in DB).
	Imported  int // Recorded in DB but not yet uploaded.
	Uploaded  int // Successfully uploaded to ER1.
	Failed    int // Previous import/upload attempt failed.
	Duplicate int // Content hash matches a tracked file at a different path.
}

// SummarizeEntries computes a StatusSummary from a slice of FileEntry.
func SummarizeEntries(entries []FileEntry) StatusSummary {
	s := StatusSummary{Total: len(entries)}
	for _, e := range entries {
		switch e.Status {
		case StatusNew:
			s.New++
		case StatusImported:
			s.Imported++
		case StatusUploaded:
			s.Uploaded++
		case StatusFailed:
			s.Failed++
		case StatusDuplicate:
			s.Duplicate++
		}
	}
	return s
}

// FilterByStatus returns only those entries matching the given status.
func FilterByStatus(entries []FileEntry, status FileStatus) []FileEntry {
	var filtered []FileEntry
	for _, e := range entries {
		if e.Status == status {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

// dbStatusToFileStatus maps a database status string to a FileStatus constant.
func dbStatusToFileStatus(dbStatus string) FileStatus {
	switch dbStatus {
	case "uploaded":
		return StatusUploaded
	case "failed":
		return StatusFailed
	case "imported":
		return StatusImported
	default:
		return StatusImported
	}
}
