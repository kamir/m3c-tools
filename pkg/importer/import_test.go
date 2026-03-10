package importer_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/importer"
	"github.com/kamir/m3c-tools/pkg/tracking"
)

// createTestAudioFiles creates sample audio files in the given directory
// and returns the list of created file paths.
func createTestAudioFiles(t *testing.T, dir string) []string {
	t.Helper()
	files := []struct {
		name    string
		content string
	}{
		{"meeting_2026-03-09_notes.wav", "fake wav data for meeting"},
		{"interview_voice.mp3", "fake mp3 data for interview"},
		{"podcast_episode1.m4a", "fake m4a data for podcast"},
	}

	var paths []string
	for _, f := range files {
		p := filepath.Join(dir, f.name)
		if err := os.WriteFile(p, []byte(f.content), 0644); err != nil {
			t.Fatalf("create test file %s: %v", f.name, err)
		}
		paths = append(paths, p)
	}
	return paths
}

func TestImportAudio_NewFiles(t *testing.T) {
	srcDir := t.TempDir()
	destDir := t.TempDir()
	dbPath := filepath.Join(t.TempDir(), "test-tracking.db")

	createTestAudioFiles(t, srcDir)

	cfg := &importer.ImportConfig{
		AudioSource: srcDir,
		AudioDest:   destDir,
		ContentType: "Test-Audio-Type",
		TrackerFile: filepath.Join(t.TempDir(), "tracker.md"),
	}

	db, err := tracking.OpenFilesDB(dbPath)
	if err != nil {
		t.Fatalf("open tracking DB: %v", err)
	}
	defer db.Close()

	result, err := importer.ImportAudio(cfg, db, nil)
	if err != nil {
		t.Fatalf("ImportAudio() error: %v", err)
	}

	if result.TotalScanned != 3 {
		t.Errorf("TotalScanned = %d, want 3", result.TotalScanned)
	}
	if len(result.Imported) != 3 {
		t.Errorf("Imported = %d, want 3", len(result.Imported))
	}
	if len(result.Skipped) != 0 {
		t.Errorf("Skipped = %d, want 0", len(result.Skipped))
	}
	if len(result.Failed) != 0 {
		t.Errorf("Failed = %d, want 0", len(result.Failed))
	}

	// Verify each imported file has a MEMORY folder.
	for _, imp := range result.Imported {
		if !strings.Contains(imp.MemoryID, "MEMORY-") {
			t.Errorf("MemoryID %q does not contain MEMORY-", imp.MemoryID)
		}
		// Verify the dest file exists.
		if _, err := os.Stat(imp.Dest); err != nil {
			t.Errorf("dest file %s does not exist: %v", imp.Dest, err)
		}
		// Verify tag.txt exists in the MEMORY folder.
		memoryDir := filepath.Dir(imp.Dest)
		tagFile := filepath.Join(memoryDir, "tag.txt")
		if _, err := os.Stat(tagFile); err != nil {
			t.Errorf("tag.txt not found in %s: %v", memoryDir, err)
		}
		// Verify content-type is in tag.txt.
		tagData, err := os.ReadFile(tagFile)
		if err != nil {
			t.Errorf("read tag.txt: %v", err)
			continue
		}
		if !strings.Contains(string(tagData), "content-type:Test-Audio-Type") {
			t.Errorf("tag.txt missing content-type, got: %s", tagData)
		}
		// Verify hash is non-empty.
		if imp.Hash == "" {
			t.Error("imported file hash is empty")
		}
	}

	// Verify files are recorded in tracking DB.
	count, err := db.CountFiles()
	if err != nil {
		t.Fatalf("count files: %v", err)
	}
	if count != 3 {
		t.Errorf("tracking DB count = %d, want 3", count)
	}
}

func TestImportAudio_SkipsAlreadyImported(t *testing.T) {
	srcDir := t.TempDir()
	destDir := t.TempDir()
	dbPath := filepath.Join(t.TempDir(), "test-tracking.db")

	createTestAudioFiles(t, srcDir)

	cfg := &importer.ImportConfig{
		AudioSource: srcDir,
		AudioDest:   destDir,
		ContentType: "Test-Audio-Type",
		TrackerFile: filepath.Join(t.TempDir(), "tracker.md"),
	}

	db, err := tracking.OpenFilesDB(dbPath)
	if err != nil {
		t.Fatalf("open tracking DB: %v", err)
	}
	defer db.Close()

	// First import: all files are new.
	result1, err := importer.ImportAudio(cfg, db, nil)
	if err != nil {
		t.Fatalf("first ImportAudio() error: %v", err)
	}
	if len(result1.Imported) != 3 {
		t.Fatalf("first import: expected 3 imported, got %d", len(result1.Imported))
	}

	// Second import: all files should be skipped (already tracked).
	result2, err := importer.ImportAudio(cfg, db, nil)
	if err != nil {
		t.Fatalf("second ImportAudio() error: %v", err)
	}
	if len(result2.Imported) != 0 {
		t.Errorf("second import: Imported = %d, want 0", len(result2.Imported))
	}
	if len(result2.Skipped) != 3 {
		t.Errorf("second import: Skipped = %d, want 3", len(result2.Skipped))
	}

	// Verify the tracking DB still has exactly 3 records.
	count, err := db.CountFiles()
	if err != nil {
		t.Fatalf("count files: %v", err)
	}
	if count != 3 {
		t.Errorf("tracking DB count = %d, want 3", count)
	}
}

func TestImportAudio_NilDB_AllNew(t *testing.T) {
	srcDir := t.TempDir()
	destDir := t.TempDir()

	createTestAudioFiles(t, srcDir)

	cfg := &importer.ImportConfig{
		AudioSource: srcDir,
		AudioDest:   destDir,
		ContentType: "Test-Type",
		TrackerFile: filepath.Join(t.TempDir(), "tracker.md"),
	}

	// Nil DB: all files appear as new, import proceeds without tracking.
	result, err := importer.ImportAudio(cfg, nil, nil)
	if err != nil {
		t.Fatalf("ImportAudio(nil db) error: %v", err)
	}

	if len(result.Imported) != 3 {
		t.Errorf("Imported = %d, want 3", len(result.Imported))
	}

	// Verify files were actually copied.
	for _, imp := range result.Imported {
		if _, err := os.Stat(imp.Dest); err != nil {
			t.Errorf("dest file %s missing: %v", imp.Dest, err)
		}
	}
}

func TestImportAudio_FilterExtensions(t *testing.T) {
	srcDir := t.TempDir()
	destDir := t.TempDir()

	createTestAudioFiles(t, srcDir) // .wav, .mp3, .m4a

	cfg := &importer.ImportConfig{
		AudioSource: srcDir,
		AudioDest:   destDir,
		ContentType: "Test-Type",
		TrackerFile: filepath.Join(t.TempDir(), "tracker.md"),
	}

	// Filter to only .wav files.
	result, err := importer.ImportAudio(cfg, nil, []string{".wav"})
	if err != nil {
		t.Fatalf("ImportAudio(filter=.wav) error: %v", err)
	}

	if result.TotalScanned != 1 {
		t.Errorf("TotalScanned = %d, want 1", result.TotalScanned)
	}
	if len(result.Imported) != 1 {
		t.Errorf("Imported = %d, want 1", len(result.Imported))
	}
	if len(result.Imported) > 0 && !strings.HasSuffix(result.Imported[0].Source, ".wav") {
		t.Errorf("imported file %s is not a .wav", result.Imported[0].Source)
	}
}

func TestImportAudio_EmptySourceDir(t *testing.T) {
	srcDir := t.TempDir()
	destDir := t.TempDir()

	cfg := &importer.ImportConfig{
		AudioSource: srcDir,
		AudioDest:   destDir,
		ContentType: "Test-Type",
		TrackerFile: filepath.Join(t.TempDir(), "tracker.md"),
	}

	result, err := importer.ImportAudio(cfg, nil, nil)
	if err != nil {
		t.Fatalf("ImportAudio(empty dir) error: %v", err)
	}

	if result.TotalScanned != 0 {
		t.Errorf("TotalScanned = %d, want 0", result.TotalScanned)
	}
	if len(result.Imported) != 0 {
		t.Errorf("Imported = %d, want 0", len(result.Imported))
	}
}

func TestImportAudio_NilConfig(t *testing.T) {
	_, err := importer.ImportAudio(nil, nil, nil)
	if err == nil {
		t.Fatal("ImportAudio(nil config) expected error, got nil")
	}
}

func TestImportAudio_ContentDuplicateDetection(t *testing.T) {
	srcDir1 := t.TempDir()
	srcDir2 := t.TempDir()
	destDir := t.TempDir()
	dbPath := filepath.Join(t.TempDir(), "test-tracking.db")

	// Create the same content under different filenames/paths.
	content := "identical audio content for dedup test"
	os.WriteFile(filepath.Join(srcDir1, "original.wav"), []byte(content), 0644)
	os.WriteFile(filepath.Join(srcDir2, "copy.wav"), []byte(content), 0644)

	db, err := tracking.OpenFilesDB(dbPath)
	if err != nil {
		t.Fatalf("open tracking DB: %v", err)
	}
	defer db.Close()

	// Import from first source.
	cfg1 := &importer.ImportConfig{
		AudioSource: srcDir1,
		AudioDest:   destDir,
		ContentType: "Test-Type",
		TrackerFile: filepath.Join(t.TempDir(), "tracker.md"),
	}
	result1, err := importer.ImportAudio(cfg1, db, nil)
	if err != nil {
		t.Fatalf("first import error: %v", err)
	}
	if len(result1.Imported) != 1 {
		t.Fatalf("first import: expected 1 imported, got %d", len(result1.Imported))
	}

	// Import from second source with same content.
	cfg2 := &importer.ImportConfig{
		AudioSource: srcDir2,
		AudioDest:   destDir,
		ContentType: "Test-Type",
		TrackerFile: filepath.Join(t.TempDir(), "tracker.md"),
	}
	result2, err := importer.ImportAudio(cfg2, db, nil)
	if err != nil {
		t.Fatalf("second import error: %v", err)
	}

	// The duplicate file should be detected via hash and skipped as "duplicate".
	if len(result2.Skipped) != 1 {
		t.Errorf("second import: Skipped = %d, want 1", len(result2.Skipped))
	}
	if len(result2.Imported) != 0 {
		t.Errorf("second import: Imported = %d, want 0", len(result2.Imported))
	}
	if len(result2.Skipped) > 0 && result2.Skipped[0].Status != importer.StatusDuplicate {
		t.Errorf("skipped status = %q, want %q", result2.Skipped[0].Status, importer.StatusDuplicate)
	}
}

func TestImportResult_Summary(t *testing.T) {
	r := &importer.ImportResult{
		TotalScanned: 10,
		Imported:     make([]importer.ImportedFile, 5),
		Skipped:      make([]importer.SkippedFile, 3),
		Failed:       make([]importer.FailedFile, 2),
	}
	s := r.Summary()
	if !strings.Contains(s, "scanned=10") {
		t.Errorf("Summary() = %q, want containing scanned=10", s)
	}
	if !strings.Contains(s, "imported=5") {
		t.Errorf("Summary() = %q, want containing imported=5", s)
	}
	if !strings.Contains(s, "skipped=3") {
		t.Errorf("Summary() = %q, want containing skipped=3", s)
	}
	if !strings.Contains(s, "failed=2") {
		t.Errorf("Summary() = %q, want containing failed=2", s)
	}
}

func TestImportAudio_TagsParsedFromFilename(t *testing.T) {
	srcDir := t.TempDir()
	destDir := t.TempDir()

	// Create a file with tags in the name.
	os.WriteFile(filepath.Join(srcDir, "meeting_brainstorm_2026-03-09.wav"), []byte("audio"), 0644)

	cfg := &importer.ImportConfig{
		AudioSource: srcDir,
		AudioDest:   destDir,
		ContentType: "Meeting-Audio",
		TrackerFile: filepath.Join(t.TempDir(), "tracker.md"),
	}

	result, err := importer.ImportAudio(cfg, nil, nil)
	if err != nil {
		t.Fatalf("ImportAudio() error: %v", err)
	}
	if len(result.Imported) != 1 {
		t.Fatalf("Imported = %d, want 1", len(result.Imported))
	}

	tags := result.Imported[0].Tags
	// Tags should contain "import" (obs type), "audio-import", and filename-derived tags.
	if !strings.Contains(tags, "import") {
		t.Errorf("tags %q should contain 'import'", tags)
	}
	if !strings.Contains(tags, "meeting") {
		t.Errorf("tags %q should contain 'meeting'", tags)
	}
	if !strings.Contains(tags, "brainstorm") {
		t.Errorf("tags %q should contain 'brainstorm'", tags)
	}
}
