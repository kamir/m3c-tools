package e2e

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kamir/m3c-tools/pkg/tracking"
)

func TestFilesDBCreateAndQuery(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_files.db")

	db, err := tracking.OpenFilesDB(dbPath)
	if err != nil {
		t.Fatalf("OpenFilesDB: %v", err)
	}
	defer db.Close()

	// Verify DB file was created.
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("DB file not created: %v", err)
	}

	// Insert a record.
	rec, err := db.RecordFile("/path/to/audio.wav", "abc123hash", 1024, "audio", "")
	if err != nil {
		t.Fatalf("RecordFile: %v", err)
	}
	if rec == nil {
		t.Fatal("RecordFile returned nil")
	}
	if rec.FilePath != "/path/to/audio.wav" {
		t.Errorf("FilePath = %q, want /path/to/audio.wav", rec.FilePath)
	}
	if rec.FileHash != "abc123hash" {
		t.Errorf("FileHash = %q, want abc123hash", rec.FileHash)
	}
	if rec.FileSize != 1024 {
		t.Errorf("FileSize = %d, want 1024", rec.FileSize)
	}
	if rec.ImportType != "audio" {
		t.Errorf("ImportType = %q, want audio", rec.ImportType)
	}
	if rec.Status != "imported" {
		t.Errorf("Status = %q, want imported", rec.Status)
	}
	if rec.ProcessedAt.IsZero() {
		t.Error("ProcessedAt is zero")
	}

	// Query by hash.
	got, err := db.GetByHash("abc123hash", "audio")
	if err != nil {
		t.Fatalf("GetByHash: %v", err)
	}
	if got == nil {
		t.Fatal("GetByHash returned nil")
	}
	if got.FilePath != "/path/to/audio.wav" {
		t.Errorf("GetByHash FilePath = %q, want /path/to/audio.wav", got.FilePath)
	}

	// Query non-existent.
	missing, err := db.GetByHash("nonexistent", "audio")
	if err != nil {
		t.Fatalf("GetByHash for missing: %v", err)
	}
	if missing != nil {
		t.Error("Expected nil for non-existent hash")
	}
}

func TestFilesDBDeduplication(t *testing.T) {
	db, err := tracking.OpenFilesDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("OpenFilesDB: %v", err)
	}
	defer db.Close()

	// Insert first record.
	_, err = db.RecordFile("/path/a.wav", "hash-aaa", 1000, "audio", "")
	if err != nil {
		t.Fatalf("First insert: %v", err)
	}

	// Insert duplicate with same hash and import_type should be ignored.
	rec, err := db.RecordFile("/path/b.wav", "hash-aaa", 1000, "audio", "")
	if err != nil {
		t.Fatalf("Duplicate insert: %v", err)
	}
	// Should return the existing record (original path).
	if rec.FilePath != "/path/a.wav" {
		t.Errorf("Duplicate insert returned path %q, want /path/a.wav (original)", rec.FilePath)
	}

	// Count should be 1.
	count, err := db.CountFiles()
	if err != nil {
		t.Fatalf("CountFiles: %v", err)
	}
	if count != 1 {
		t.Errorf("Expected 1 file after duplicate insert, got %d", count)
	}

	// Same hash but different import_type should create a new record.
	_, err = db.RecordFile("/path/a.wav", "hash-aaa", 1000, "screenshot", "")
	if err != nil {
		t.Fatalf("Different type insert: %v", err)
	}
	count, err = db.CountFiles()
	if err != nil {
		t.Fatalf("CountFiles: %v", err)
	}
	if count != 2 {
		t.Errorf("Expected 2 files with different import types, got %d", count)
	}
}

func TestFilesDBIsFileProcessed(t *testing.T) {
	db, err := tracking.OpenFilesDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("OpenFilesDB: %v", err)
	}
	defer db.Close()

	// Not processed yet.
	processed, err := db.IsFileProcessed("hash-xxx", "audio")
	if err != nil {
		t.Fatalf("IsFileProcessed: %v", err)
	}
	if processed {
		t.Error("Expected file to not be processed")
	}

	// Record the file.
	_, err = db.RecordFile("/audio/file.wav", "hash-xxx", 2048, "audio", "MEM-001")
	if err != nil {
		t.Fatalf("RecordFile: %v", err)
	}

	// Now it should be processed.
	processed, err = db.IsFileProcessed("hash-xxx", "audio")
	if err != nil {
		t.Fatalf("IsFileProcessed after insert: %v", err)
	}
	if !processed {
		t.Error("Expected file to be processed after insert")
	}

	// Different import type should not be processed.
	processed, err = db.IsFileProcessed("hash-xxx", "screenshot")
	if err != nil {
		t.Fatalf("IsFileProcessed different type: %v", err)
	}
	if processed {
		t.Error("Expected file to not be processed for different import type")
	}
}

func TestFilesDBIsPathProcessed(t *testing.T) {
	db, err := tracking.OpenFilesDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("OpenFilesDB: %v", err)
	}
	defer db.Close()

	_, err = db.RecordFile("/audio/voice.wav", "hash-voice", 4096, "audio", "")
	if err != nil {
		t.Fatalf("RecordFile: %v", err)
	}

	processed, err := db.IsPathProcessed("/audio/voice.wav", "audio")
	if err != nil {
		t.Fatal(err)
	}
	if !processed {
		t.Error("Expected path to be processed")
	}

	processed, err = db.IsPathProcessed("/audio/other.wav", "audio")
	if err != nil {
		t.Fatal(err)
	}
	if processed {
		t.Error("Expected different path to not be processed")
	}
}

func TestFilesDBUpdateStatus(t *testing.T) {
	db, err := tracking.OpenFilesDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("OpenFilesDB: %v", err)
	}
	defer db.Close()

	_, err = db.RecordFile("/f.wav", "hash-f", 512, "audio", "")
	if err != nil {
		t.Fatal(err)
	}

	err = db.UpdateStatus("hash-f", "audio", "failed")
	if err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}

	rec, err := db.GetByHash("hash-f", "audio")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "failed" {
		t.Errorf("Status = %q, want failed", rec.Status)
	}
}

func TestFilesDBUpdateMemoryID(t *testing.T) {
	db, err := tracking.OpenFilesDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("OpenFilesDB: %v", err)
	}
	defer db.Close()

	_, err = db.RecordFile("/f.wav", "hash-mem", 512, "audio", "")
	if err != nil {
		t.Fatal(err)
	}

	err = db.UpdateMemoryID("hash-mem", "audio", "MEMORY-20260309-150000")
	if err != nil {
		t.Fatalf("UpdateMemoryID: %v", err)
	}

	rec, err := db.GetByHash("hash-mem", "audio")
	if err != nil {
		t.Fatal(err)
	}
	if rec.MemoryID != "MEMORY-20260309-150000" {
		t.Errorf("MemoryID = %q, want MEMORY-20260309-150000", rec.MemoryID)
	}
	if rec.Status != "uploaded" {
		t.Errorf("Status = %q, want uploaded (set by UpdateMemoryID)", rec.Status)
	}
}

func TestFilesDBListAndCount(t *testing.T) {
	db, err := tracking.OpenFilesDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("OpenFilesDB: %v", err)
	}
	defer db.Close()

	db.RecordFile("/a.wav", "hash-a", 100, "audio", "")
	db.RecordFile("/b.wav", "hash-b", 200, "audio", "")
	db.RecordFile("/c.png", "hash-c", 300, "screenshot", "")
	db.UpdateStatus("hash-b", "audio", "failed")

	// List all.
	files, err := db.ListFiles(100)
	if err != nil {
		t.Fatalf("ListFiles: %v", err)
	}
	if len(files) != 3 {
		t.Errorf("ListFiles count = %d, want 3", len(files))
	}

	// Count all.
	count, err := db.CountFiles()
	if err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Errorf("CountFiles = %d, want 3", count)
	}

	// Count by status.
	imported, err := db.CountFilesByStatus("imported")
	if err != nil {
		t.Fatal(err)
	}
	if imported != 2 {
		t.Errorf("imported count = %d, want 2", imported)
	}

	failed, err := db.CountFilesByStatus("failed")
	if err != nil {
		t.Fatal(err)
	}
	if failed != 1 {
		t.Errorf("failed count = %d, want 1", failed)
	}

	// List by status.
	failedFiles, err := db.ListByStatus("failed", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(failedFiles) != 1 {
		t.Errorf("ListByStatus(failed) count = %d, want 1", len(failedFiles))
	}
}

func TestFilesDBRemoveByHash(t *testing.T) {
	db, err := tracking.OpenFilesDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("OpenFilesDB: %v", err)
	}
	defer db.Close()

	db.RecordFile("/a.wav", "hash-del", 100, "audio", "")

	processed, _ := db.IsFileProcessed("hash-del", "audio")
	if !processed {
		t.Fatal("Expected file to be processed before removal")
	}

	err = db.RemoveByHash("hash-del", "audio")
	if err != nil {
		t.Fatalf("RemoveByHash: %v", err)
	}

	processed, _ = db.IsFileProcessed("hash-del", "audio")
	if processed {
		t.Error("Expected file to not be processed after removal")
	}
}

func TestFilesDBGetByPath(t *testing.T) {
	db, err := tracking.OpenFilesDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("OpenFilesDB: %v", err)
	}
	defer db.Close()

	db.RecordFile("/recordings/session.wav", "hash-sess", 8192, "audio", "MEM-X")

	rec, err := db.GetByPath("/recordings/session.wav")
	if err != nil {
		t.Fatal(err)
	}
	if rec == nil {
		t.Fatal("GetByPath returned nil")
	}
	if rec.FileHash != "hash-sess" {
		t.Errorf("FileHash = %q, want hash-sess", rec.FileHash)
	}

	// Non-existent path.
	rec, err = db.GetByPath("/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if rec != nil {
		t.Error("Expected nil for non-existent path")
	}
}

func TestHashFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")

	// Write known content.
	content := []byte("hello world\n")
	if err := os.WriteFile(testFile, content, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	hash1, err := tracking.HashFile(testFile)
	if err != nil {
		t.Fatalf("HashFile: %v", err)
	}
	if hash1 == "" {
		t.Error("HashFile returned empty string")
	}
	t.Logf("Hash: %s", hash1)

	// Same content should produce same hash.
	testFile2 := filepath.Join(tmpDir, "test2.txt")
	if err := os.WriteFile(testFile2, content, 0644); err != nil {
		t.Fatal(err)
	}
	hash2, err := tracking.HashFile(testFile2)
	if err != nil {
		t.Fatal(err)
	}
	if hash1 != hash2 {
		t.Errorf("Same content produced different hashes: %s vs %s", hash1, hash2)
	}

	// Different content should produce different hash.
	testFile3 := filepath.Join(tmpDir, "test3.txt")
	if err := os.WriteFile(testFile3, []byte("different"), 0644); err != nil {
		t.Fatal(err)
	}
	hash3, err := tracking.HashFile(testFile3)
	if err != nil {
		t.Fatal(err)
	}
	if hash1 == hash3 {
		t.Error("Different content produced same hash")
	}
}

// TestFilesDBHashIntegration tests the full workflow: hash a file, record it,
// check for duplicates on rescan.
func TestFilesDBHashIntegration(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "integration.db")

	db, err := tracking.OpenFilesDB(dbPath)
	if err != nil {
		t.Fatalf("OpenFilesDB: %v", err)
	}
	defer db.Close()

	// Create a test audio file.
	audioFile := filepath.Join(tmpDir, "recording.wav")
	if err := os.WriteFile(audioFile, []byte("fake wav content"), 0644); err != nil {
		t.Fatal(err)
	}

	// Simulate first scan: hash and record.
	hash, err := tracking.HashFile(audioFile)
	if err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(audioFile)
	if err != nil {
		t.Fatal(err)
	}

	processed, err := db.IsFileProcessed(hash, "audio")
	if err != nil {
		t.Fatal(err)
	}
	if processed {
		t.Fatal("File should not be processed on first scan")
	}

	// Record the file.
	rec, err := db.RecordFile(audioFile, hash, info.Size(), "audio", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Recorded: %s -> %s", rec.FilePath, rec.FileHash)

	// Simulate second scan: should be detected as duplicate.
	processed, err = db.IsFileProcessed(hash, "audio")
	if err != nil {
		t.Fatal(err)
	}
	if !processed {
		t.Error("File should be detected as already processed on second scan")
	}

	// Even if the file is copied to a new location, same content = same hash = duplicate.
	copyPath := filepath.Join(tmpDir, "copy.wav")
	if err := os.WriteFile(copyPath, []byte("fake wav content"), 0644); err != nil {
		t.Fatal(err)
	}
	copyHash, err := tracking.HashFile(copyPath)
	if err != nil {
		t.Fatal(err)
	}
	if copyHash != hash {
		t.Fatal("Copy should have same hash")
	}

	processed, err = db.IsFileProcessed(copyHash, "audio")
	if err != nil {
		t.Fatal(err)
	}
	if !processed {
		t.Error("Copied file with same content should be detected as duplicate")
	}
}
