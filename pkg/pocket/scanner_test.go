package pocket

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseFilenameTimestamp(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    time.Time
		wantErr bool
	}{
		{"normal", "20260402163416", time.Date(2026, 4, 2, 16, 34, 16, 0, time.UTC), false},
		{"midnight", "20260101000000", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), false},
		{"too_short", "2026040", time.Time{}, true},
		{"empty", "", time.Time{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseFilenameTimestamp(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseFilenameTimestamp(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && !got.Equal(tt.want) {
				t.Errorf("ParseFilenameTimestamp(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestScan(t *testing.T) {
	// Create a temp directory structure mimicking the Pocket device
	tmpDir := t.TempDir()
	dateDir := filepath.Join(tmpDir, "2026-04-02")
	os.MkdirAll(dateDir, 0755)

	// Create fake MP3 files with valid timestamp names
	files := []string{"20260402163416.mp3", "20260402171200.mp3", "20260402091530.mp3"}
	for _, f := range files {
		os.WriteFile(filepath.Join(dateDir, f), make([]byte, 4000), 0644) // 1 second at 32kbps
	}

	// Also create a non-MP3 file (should be ignored)
	os.WriteFile(filepath.Join(dateDir, "notes.txt"), []byte("hello"), 0644)

	recordings, err := Scan(tmpDir)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	if len(recordings) != 3 {
		t.Fatalf("Scan() returned %d recordings, want 3", len(recordings))
	}

	// Should be sorted by timestamp (earliest first)
	if recordings[0].Time != "09:15:30" {
		t.Errorf("First recording time = %q, want 09:15:30", recordings[0].Time)
	}
	if recordings[2].Time != "17:12:00" {
		t.Errorf("Last recording time = %q, want 17:12:00", recordings[2].Time)
	}

	// Check date extraction
	for _, r := range recordings {
		if r.Date != "2026-04-02" {
			t.Errorf("Recording date = %q, want 2026-04-02", r.Date)
		}
		if r.Status != "new" {
			t.Errorf("Recording status = %q, want new", r.Status)
		}
	}
}

func TestDedupeKey(t *testing.T) {
	r := Recording{
		FilePath: "/Volumes/Pocket/RECORD/2026-04-02/20260402163416.mp3",
		Date:     "2026-04-02",
	}
	want := "pocket://2026-04-02/20260402163416.mp3"
	if got := r.DedupeKey(); got != want {
		t.Errorf("DedupeKey() = %q, want %q", got, want)
	}
}

func TestScanEmptyDir(t *testing.T) {
	tmpDir := t.TempDir()
	recordings, err := Scan(tmpDir)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	if len(recordings) != 0 {
		t.Errorf("Scan() returned %d recordings for empty dir, want 0", len(recordings))
	}
}
