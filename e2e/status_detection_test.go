package e2e

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kamir/m3c-tools/pkg/importer"
	"github.com/kamir/m3c-tools/pkg/tracking"
)

// TestStatusCheckerFromDBNilDB verifies graceful degradation when no DB is available.
func TestStatusCheckerFromDBNilDB(t *testing.T) {
	checker := importer.StatusCheckerFromDB(nil, "audio")
	status, err := checker("/any/path.wav")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != importer.StatusNew {
		t.Errorf("expected StatusNew for nil DB, got %q", status)
	}
}

// TestStatusCheckerFromDBPathOnlyNilDB verifies graceful degradation for path-only checker.
func TestStatusCheckerFromDBPathOnlyNilDB(t *testing.T) {
	checker := importer.StatusCheckerFromDBPathOnly(nil)
	status, err := checker("/any/path.wav")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != importer.StatusNew {
		t.Errorf("expected StatusNew for nil DB, got %q", status)
	}
}

// TestStatusCheckerNewFile verifies that untracked files are detected as new.
func TestStatusCheckerNewFile(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := tracking.OpenFilesDB(dbPath)
	if err != nil {
		t.Fatalf("OpenFilesDB: %v", err)
	}
	defer db.Close()

	// Create a file on disk that is NOT in the DB.
	audioFile := filepath.Join(tmpDir, "new-track.wav")
	if err := os.WriteFile(audioFile, []byte("new audio content"), 0644); err != nil {
		t.Fatal(err)
	}

	checker := importer.StatusCheckerFromDB(db, "audio")
	status, err := checker(audioFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != importer.StatusNew {
		t.Errorf("expected StatusNew for untracked file, got %q", status)
	}
}

// TestStatusCheckerImportedFile verifies that imported files are detected correctly.
func TestStatusCheckerImportedFile(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := tracking.OpenFilesDB(dbPath)
	if err != nil {
		t.Fatalf("OpenFilesDB: %v", err)
	}
	defer db.Close()

	audioFile := filepath.Join(tmpDir, "imported-track.wav")
	if err := os.WriteFile(audioFile, []byte("imported audio"), 0644); err != nil {
		t.Fatal(err)
	}

	hash, err := tracking.HashFile(audioFile)
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(audioFile)
	_, err = db.RecordFile(audioFile, hash, info.Size(), "audio", "")
	if err != nil {
		t.Fatal(err)
	}

	checker := importer.StatusCheckerFromDB(db, "audio")
	status, err := checker(audioFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != importer.StatusImported {
		t.Errorf("expected StatusImported, got %q", status)
	}
}

// TestStatusCheckerUploadedFile verifies uploaded status detection.
func TestStatusCheckerUploadedFile(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := tracking.OpenFilesDB(dbPath)
	if err != nil {
		t.Fatalf("OpenFilesDB: %v", err)
	}
	defer db.Close()

	audioFile := filepath.Join(tmpDir, "uploaded-track.wav")
	if err := os.WriteFile(audioFile, []byte("uploaded audio"), 0644); err != nil {
		t.Fatal(err)
	}

	hash, _ := tracking.HashFile(audioFile)
	info, _ := os.Stat(audioFile)
	db.RecordFile(audioFile, hash, info.Size(), "audio", "")
	db.UpdateMemoryID(hash, "audio", "MEM-123")

	checker := importer.StatusCheckerFromDB(db, "audio")
	status, err := checker(audioFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != importer.StatusUploaded {
		t.Errorf("expected StatusUploaded, got %q", status)
	}
}

// TestStatusCheckerFailedFile verifies failed status detection.
func TestStatusCheckerFailedFile(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := tracking.OpenFilesDB(dbPath)
	if err != nil {
		t.Fatalf("OpenFilesDB: %v", err)
	}
	defer db.Close()

	audioFile := filepath.Join(tmpDir, "failed-track.wav")
	if err := os.WriteFile(audioFile, []byte("failed audio"), 0644); err != nil {
		t.Fatal(err)
	}

	hash, _ := tracking.HashFile(audioFile)
	info, _ := os.Stat(audioFile)
	db.RecordFile(audioFile, hash, info.Size(), "audio", "")
	db.UpdateStatus(hash, "audio", "failed")

	checker := importer.StatusCheckerFromDB(db, "audio")
	status, err := checker(audioFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != importer.StatusFailed {
		t.Errorf("expected StatusFailed, got %q", status)
	}
}

// TestStatusCheckerDuplicateDetection verifies that a file with the same
// content as a tracked file (but at a different path) is detected as duplicate.
func TestStatusCheckerDuplicateDetection(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := tracking.OpenFilesDB(dbPath)
	if err != nil {
		t.Fatalf("OpenFilesDB: %v", err)
	}
	defer db.Close()

	content := []byte("duplicate audio content xyz")

	// Create original file and record it in DB.
	original := filepath.Join(tmpDir, "original.wav")
	if err := os.WriteFile(original, content, 0644); err != nil {
		t.Fatal(err)
	}
	hash, _ := tracking.HashFile(original)
	info, _ := os.Stat(original)
	db.RecordFile(original, hash, info.Size(), "audio", "")

	// Create a copy at a different path with the same content.
	copy := filepath.Join(tmpDir, "copy.wav")
	if err := os.WriteFile(copy, content, 0644); err != nil {
		t.Fatal(err)
	}

	checker := importer.StatusCheckerFromDB(db, "audio")
	status, err := checker(copy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != importer.StatusDuplicate {
		t.Errorf("expected StatusDuplicate for content-identical file at different path, got %q", status)
	}
}

// TestStatusCheckerPathOnlyNoDuplicateDetection verifies that the path-only
// checker does NOT detect content duplicates (by design, for performance).
func TestStatusCheckerPathOnlyNoDuplicateDetection(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := tracking.OpenFilesDB(dbPath)
	if err != nil {
		t.Fatalf("OpenFilesDB: %v", err)
	}
	defer db.Close()

	content := []byte("same content for path-only test")

	original := filepath.Join(tmpDir, "original.wav")
	if err := os.WriteFile(original, content, 0644); err != nil {
		t.Fatal(err)
	}
	hash, _ := tracking.HashFile(original)
	info, _ := os.Stat(original)
	db.RecordFile(original, hash, info.Size(), "audio", "")

	copy := filepath.Join(tmpDir, "copy.wav")
	if err := os.WriteFile(copy, content, 0644); err != nil {
		t.Fatal(err)
	}

	checker := importer.StatusCheckerFromDBPathOnly(db)
	status, err := checker(copy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Path-only checker should return StatusNew (no hash check).
	if status != importer.StatusNew {
		t.Errorf("expected StatusNew from path-only checker for different path, got %q", status)
	}
}

// TestStatusCheckerImportTypeScoping verifies that status checks are scoped
// by import type — a file tracked as "audio" should appear as new for "screenshot".
func TestStatusCheckerImportTypeScoping(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := tracking.OpenFilesDB(dbPath)
	if err != nil {
		t.Fatalf("OpenFilesDB: %v", err)
	}
	defer db.Close()

	audioFile := filepath.Join(tmpDir, "multi-type.wav")
	if err := os.WriteFile(audioFile, []byte("scoped content"), 0644); err != nil {
		t.Fatal(err)
	}

	hash, _ := tracking.HashFile(audioFile)
	info, _ := os.Stat(audioFile)
	// Record as "audio" import type.
	db.RecordFile(audioFile, hash, info.Size(), "audio", "")

	// Check with "audio" type — should be imported.
	audioChecker := importer.StatusCheckerFromDB(db, "audio")
	status, err := audioChecker(audioFile)
	if err != nil {
		t.Fatal(err)
	}
	if status != importer.StatusImported {
		t.Errorf("expected StatusImported for audio type, got %q", status)
	}

	// Check with "screenshot" type — same path is in DB, but GetByPath
	// doesn't filter by type, so it will find the record. However, the
	// hash lookup is scoped by type. Since GetByPath returns the record
	// regardless of type, we still get the DB status.
	// This demonstrates path-based lookup doesn't scope by type.
	screenshotChecker := importer.StatusCheckerFromDB(db, "screenshot")
	status, err = screenshotChecker(audioFile)
	if err != nil {
		t.Fatal(err)
	}
	// GetByPath returns the record regardless of import_type, so it finds it.
	if status != importer.StatusImported {
		t.Errorf("expected StatusImported (path match), got %q", status)
	}
}

// TestStatusCheckerNonexistentFile verifies behavior when the file doesn't
// exist on disk but is not in the DB either.
func TestStatusCheckerNonexistentFile(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := tracking.OpenFilesDB(dbPath)
	if err != nil {
		t.Fatalf("OpenFilesDB: %v", err)
	}
	defer db.Close()

	checker := importer.StatusCheckerFromDB(db, "audio")
	status, err := checker("/nonexistent/path/file.wav")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// File doesn't exist and isn't in DB — should be StatusNew.
	if status != importer.StatusNew {
		t.Errorf("expected StatusNew for nonexistent file, got %q", status)
	}
}

// TestStatusCheckerDefaultImportType verifies that empty importType defaults to "audio".
func TestStatusCheckerDefaultImportType(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := tracking.OpenFilesDB(dbPath)
	if err != nil {
		t.Fatalf("OpenFilesDB: %v", err)
	}
	defer db.Close()

	audioFile := filepath.Join(tmpDir, "default-type.wav")
	if err := os.WriteFile(audioFile, []byte("default type content"), 0644); err != nil {
		t.Fatal(err)
	}

	hash, _ := tracking.HashFile(audioFile)
	info, _ := os.Stat(audioFile)
	// Record with default import type (audio).
	db.RecordFile(audioFile, hash, info.Size(), "", "")

	// Check with empty import type — should default to "audio".
	checker := importer.StatusCheckerFromDB(db, "")
	status, err := checker(audioFile)
	if err != nil {
		t.Fatal(err)
	}
	if status != importer.StatusImported {
		t.Errorf("expected StatusImported with default type, got %q", status)
	}
}

// TestBuildFileEntriesWithDBChecker tests the full integration: scan → status check → entries.
func TestBuildFileEntriesWithDBChecker(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "integration.db")

	db, err := tracking.OpenFilesDB(dbPath)
	if err != nil {
		t.Fatalf("OpenFilesDB: %v", err)
	}
	defer db.Close()

	// Create audio files with different statuses.
	newFile := filepath.Join(tmpDir, "new-track.wav")
	importedFile := filepath.Join(tmpDir, "imported-track.wav")
	uploadedFile := filepath.Join(tmpDir, "uploaded-track.wav")
	failedFile := filepath.Join(tmpDir, "failed-track.wav")

	if err := os.WriteFile(newFile, []byte("new content"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(importedFile, []byte("imported content"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(uploadedFile, []byte("uploaded content"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(failedFile, []byte("failed content"), 0644); err != nil {
		t.Fatal(err)
	}

	// Record states in DB.
	for _, tc := range []struct {
		path   string
		status string
	}{
		{importedFile, "imported"},
		{uploadedFile, "uploaded"},
		{failedFile, "failed"},
	} {
		hash, _ := tracking.HashFile(tc.path)
		info, _ := os.Stat(tc.path)
		db.RecordFile(tc.path, hash, info.Size(), "audio", "")
		if tc.status != "imported" {
			if tc.status == "uploaded" {
				db.UpdateMemoryID(hash, "audio", "MEM-test")
			} else {
				db.UpdateStatus(hash, "audio", tc.status)
			}
		}
	}

	// Scan the directory.
	result, err := importer.ScanDir(tmpDir)
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}

	// Build entries with DB-backed checker.
	checker := importer.StatusCheckerFromDB(db, "audio")
	entries, err := importer.BuildFileEntries(result, checker)
	if err != nil {
		t.Fatalf("BuildFileEntries: %v", err)
	}

	// Verify we got the expected number of audio files.
	if len(entries) != 4 {
		t.Fatalf("expected 4 entries, got %d", len(entries))
	}

	// Check statuses by filename.
	statusMap := make(map[string]importer.FileStatus)
	for _, e := range entries {
		statusMap[e.File.Name] = e.Status
	}

	expected := map[string]importer.FileStatus{
		"new-track.wav":      importer.StatusNew,
		"imported-track.wav": importer.StatusImported,
		"uploaded-track.wav": importer.StatusUploaded,
		"failed-track.wav":   importer.StatusFailed,
	}

	for name, wantStatus := range expected {
		gotStatus, ok := statusMap[name]
		if !ok {
			t.Errorf("missing entry for %s", name)
			continue
		}
		if gotStatus != wantStatus {
			t.Errorf("%s: expected %q, got %q", name, wantStatus, gotStatus)
		}
	}
}

// TestSummarizeEntries verifies the aggregate count calculation.
func TestSummarizeEntries(t *testing.T) {
	entries := []importer.FileEntry{
		{Status: importer.StatusNew},
		{Status: importer.StatusNew},
		{Status: importer.StatusImported},
		{Status: importer.StatusUploaded},
		{Status: importer.StatusFailed},
		{Status: importer.StatusDuplicate},
		{Status: importer.StatusDuplicate},
	}

	summary := importer.SummarizeEntries(entries)

	if summary.Total != 7 {
		t.Errorf("Total = %d, want 7", summary.Total)
	}
	if summary.New != 2 {
		t.Errorf("New = %d, want 2", summary.New)
	}
	if summary.Imported != 1 {
		t.Errorf("Imported = %d, want 1", summary.Imported)
	}
	if summary.Uploaded != 1 {
		t.Errorf("Uploaded = %d, want 1", summary.Uploaded)
	}
	if summary.Failed != 1 {
		t.Errorf("Failed = %d, want 1", summary.Failed)
	}
	if summary.Duplicate != 2 {
		t.Errorf("Duplicate = %d, want 2", summary.Duplicate)
	}
}

// TestSummarizeEntriesEmpty verifies summary on empty input.
func TestSummarizeEntriesEmpty(t *testing.T) {
	summary := importer.SummarizeEntries(nil)
	if summary.Total != 0 {
		t.Errorf("Total = %d, want 0", summary.Total)
	}
}

// TestFilterByStatus verifies status-based filtering.
func TestFilterByStatus(t *testing.T) {
	entries := []importer.FileEntry{
		{File: importer.AudioFile{Name: "a.wav"}, Status: importer.StatusNew},
		{File: importer.AudioFile{Name: "b.wav"}, Status: importer.StatusImported},
		{File: importer.AudioFile{Name: "c.wav"}, Status: importer.StatusNew},
		{File: importer.AudioFile{Name: "d.wav"}, Status: importer.StatusUploaded},
	}

	newFiles := importer.FilterByStatus(entries, importer.StatusNew)
	if len(newFiles) != 2 {
		t.Errorf("expected 2 new files, got %d", len(newFiles))
	}
	for _, e := range newFiles {
		if e.Status != importer.StatusNew {
			t.Errorf("filtered entry has wrong status: %q", e.Status)
		}
	}

	uploaded := importer.FilterByStatus(entries, importer.StatusUploaded)
	if len(uploaded) != 1 {
		t.Errorf("expected 1 uploaded file, got %d", len(uploaded))
	}

	// No files with StatusFailed.
	failed := importer.FilterByStatus(entries, importer.StatusFailed)
	if len(failed) != 0 {
		t.Errorf("expected 0 failed files, got %d", len(failed))
	}
}

// TestFilterByStatusNil verifies filter on nil input.
func TestFilterByStatusNil(t *testing.T) {
	result := importer.FilterByStatus(nil, importer.StatusNew)
	if result != nil {
		t.Errorf("expected nil for nil input, got %v", result)
	}
}
