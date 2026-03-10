// Package importer — markdown-based tracker file for import deduplication.
//
// The tracker file is a simple line-oriented markdown file that records
// which audio files have been imported. Each entry is a line containing
// the filename (base name, not full path). The file is human-readable
// and can be edited manually.
//
// Format:
//
//	# M3C Import Tracker
//	# Auto-generated — do not edit while import is running.
//
//	recording-2024-01-15.mp3
//	meeting-notes.wav
//	dictation_final.m4a
//
// The tracker file path is configured via IMPORT_TRACKER_FILE
// (default: ~/.m3c-tools/transcript_tracker.md).
package importer

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const trackerHeader = `# M3C Import Tracker
# Auto-generated — do not edit while import is running.
# Last updated: %s
`

// Tracker manages a line-oriented file that records imported audio filenames.
// It provides read, write, and check operations with an in-memory cache
// for fast lookups. All methods are safe for concurrent use.
type Tracker struct {
	mu       sync.RWMutex
	path     string            // Absolute path to the tracker file.
	entries  map[string]bool   // In-memory set of tracked filenames.
	loaded   bool              // Whether entries have been loaded from disk.
}

// NewTracker creates a Tracker for the given file path.
// The tracker file is not read until Load() or IsTracked() is called.
// The parent directory is created if it doesn't exist.
func NewTracker(path string) (*Tracker, error) {
	if path == "" {
		return nil, fmt.Errorf("tracker file path is empty")
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve tracker path: %w", err)
	}

	return &Tracker{
		path:    absPath,
		entries: make(map[string]bool),
	}, nil
}

// Path returns the absolute path of the tracker file.
func (t *Tracker) Path() string {
	return t.path
}

// Load reads the tracker file from disk and populates the in-memory cache.
// If the file doesn't exist, the cache is initialized empty (no error).
// Subsequent calls to Load() re-read the file, replacing the cache.
func (t *Tracker) Load() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	entries := make(map[string]bool)

	f, err := os.Open(t.path)
	if err != nil {
		if os.IsNotExist(err) {
			t.entries = entries
			t.loaded = true
			return nil
		}
		return fmt.Errorf("open tracker file: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entries[line] = true
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read tracker file: %w", err)
	}

	t.entries = entries
	t.loaded = true
	return nil
}

// IsTracked checks whether the given filename (base name) has been recorded.
// If the tracker has not been loaded yet, it calls Load() first.
// Returns false for empty filenames.
func (t *Tracker) IsTracked(filename string) (bool, error) {
	if filename == "" {
		return false, nil
	}

	t.mu.RLock()
	loaded := t.loaded
	t.mu.RUnlock()

	if !loaded {
		if err := t.Load(); err != nil {
			return false, err
		}
	}

	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.entries[filename], nil
}

// Add records one or more filenames as imported. The entries are added to
// the in-memory cache and appended to the tracker file on disk. Duplicate
// entries are silently skipped (not written again).
//
// If the tracker file doesn't exist, it is created with a header.
func (t *Tracker) Add(filenames ...string) error {
	if len(filenames) == 0 {
		return nil
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// Ensure loaded so we can check for duplicates.
	if !t.loaded {
		t.mu.Unlock()
		if err := t.Load(); err != nil {
			t.mu.Lock()
			return err
		}
		t.mu.Lock()
	}

	// Collect only new entries.
	var newEntries []string
	for _, name := range filenames {
		name = strings.TrimSpace(name)
		if name == "" || t.entries[name] {
			continue
		}
		newEntries = append(newEntries, name)
		t.entries[name] = true
	}

	if len(newEntries) == 0 {
		return nil // All entries already tracked.
	}

	// Ensure parent directory exists.
	dir := filepath.Dir(t.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create tracker dir: %w", err)
	}

	// If the file doesn't exist, write the header first.
	needsHeader := false
	if _, err := os.Stat(t.path); os.IsNotExist(err) {
		needsHeader = true
	}

	f, err := os.OpenFile(t.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open tracker file for writing: %w", err)
	}
	defer f.Close()

	if needsHeader {
		header := fmt.Sprintf(trackerHeader, time.Now().UTC().Format(time.RFC3339))
		if _, err := f.WriteString(header + "\n"); err != nil {
			return fmt.Errorf("write tracker header: %w", err)
		}
	}

	for _, name := range newEntries {
		if _, err := fmt.Fprintln(f, name); err != nil {
			return fmt.Errorf("write tracker entry: %w", err)
		}
	}

	return nil
}

// Count returns the number of tracked entries.
// If the tracker has not been loaded yet, it calls Load() first.
func (t *Tracker) Count() (int, error) {
	t.mu.RLock()
	loaded := t.loaded
	t.mu.RUnlock()

	if !loaded {
		if err := t.Load(); err != nil {
			return 0, err
		}
	}

	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.entries), nil
}

// Entries returns a sorted list of all tracked filenames.
// If the tracker has not been loaded yet, it calls Load() first.
func (t *Tracker) Entries() ([]string, error) {
	t.mu.RLock()
	loaded := t.loaded
	t.mu.RUnlock()

	if !loaded {
		if err := t.Load(); err != nil {
			return nil, err
		}
	}

	t.mu.RLock()
	defer t.mu.RUnlock()

	result := make([]string, 0, len(t.entries))
	for name := range t.entries {
		result = append(result, name)
	}
	return result, nil
}

// StatusCheckerFromTracker returns a StatusChecker that uses the tracker file
// to determine whether a file has been previously imported. It checks the
// base filename (not the full path) against the tracker's entries.
//
// Files found in the tracker are reported as StatusImported.
// Files not found are reported as StatusNew.
func StatusCheckerFromTracker(tracker *Tracker) StatusChecker {
	if tracker == nil {
		return func(filePath string) (FileStatus, error) {
			return StatusNew, nil
		}
	}

	return func(filePath string) (FileStatus, error) {
		basename := filepath.Base(filePath)
		tracked, err := tracker.IsTracked(basename)
		if err != nil {
			return "", fmt.Errorf("tracker check: %w", err)
		}
		if tracked {
			return StatusImported, nil
		}
		return StatusNew, nil
	}
}
