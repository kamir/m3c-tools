package pocket

import (
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Recording represents a single MP3 file discovered on the Pocket device.
type Recording struct {
	FilePath    string    `json:"file_path"`
	Date        string    `json:"date"`         // YYYY-MM-DD from folder
	Time        string    `json:"time"`         // HH:mm:ss from filename
	Timestamp   time.Time `json:"timestamp"`    // Parsed full datetime
	SizeBytes   int64     `json:"size_bytes"`
	DurationSec float64   `json:"duration_sec"` // Estimated from size (32kbps MP3)
	FileHash    string    `json:"file_hash"`    // SHA-256
	Status      string    `json:"status"`       // "new", "staged", "synced"
}

// DedupeKey returns a unique key for this recording (used for tracking).
func (r Recording) DedupeKey() string {
	return fmt.Sprintf("pocket://%s/%s", r.Date, filepath.Base(r.FilePath))
}

// Scan discovers MP3 recordings in the Pocket RECORD directory.
// Returns recordings sorted by timestamp (oldest first).
func Scan(recordPath string) ([]Recording, error) {
	var recordings []Recording

	err := filepath.WalkDir(recordPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() || !strings.HasSuffix(strings.ToLower(d.Name()), ".mp3") {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}

		rec, err := parseRecording(path, info)
		if err != nil {
			log.Printf("[pocket] skipping %s: %v", path, err)
			return nil
		}

		recordings = append(recordings, rec)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("scanning %s: %w", recordPath, err)
	}

	sort.Slice(recordings, func(i, j int) bool {
		return recordings[i].Timestamp.Before(recordings[j].Timestamp)
	})

	return recordings, nil
}

// parseRecording extracts metadata from a Pocket recording file.
// Filename format: YYYYMMDDHHmmss.mp3
func parseRecording(path string, info os.FileInfo) (Recording, error) {
	name := strings.TrimSuffix(info.Name(), ".mp3")
	name = strings.TrimSuffix(name, ".MP3")

	ts, err := ParseFilenameTimestamp(name)
	if err != nil {
		return Recording{}, fmt.Errorf("parse timestamp from %q: %w", info.Name(), err)
	}

	// Extract date from parent directory name (YYYY-MM-DD)
	date := filepath.Base(filepath.Dir(path))

	// Estimate duration: Pocket records at 32kbps mono MP3
	// 32000 bits/s = 4000 bytes/s
	durationSec := float64(info.Size()) / 4000.0

	return Recording{
		FilePath:    path,
		Date:        date,
		Time:        ts.Format("15:04:05"),
		Timestamp:   ts,
		SizeBytes:   info.Size(),
		DurationSec: durationSec,
		Status:      "new",
	}, nil
}

// ParseFilenameTimestamp parses a Pocket filename timestamp (YYYYMMDDHHmmss).
func ParseFilenameTimestamp(name string) (time.Time, error) {
	if len(name) < 14 {
		return time.Time{}, fmt.Errorf("filename too short: %q", name)
	}
	return time.Parse("20060102150405", name[:14])
}

// HashFile computes the SHA-256 hash of a file.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
