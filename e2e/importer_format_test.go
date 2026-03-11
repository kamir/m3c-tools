package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/importer"
	"github.com/kamir/m3c-tools/pkg/tracking"
)

func TestBuildFileEntriesNoChecker(t *testing.T) {
	root := t.TempDir()
	files := []string{
		"meeting-notes-2026-03-09.wav",
		"project_alpha_draft.mp3",
		"20260310_143000_standup.flac",
	}
	for _, name := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte("audio-data"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	result, err := importer.ScanDir(root)
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}

	// No checker → all files should be StatusNew
	entries, err := importer.BuildFileEntries(result, nil)
	if err != nil {
		t.Fatalf("BuildFileEntries: %v", err)
	}

	if len(entries) != 3 {
		t.Fatalf("Expected 3 entries, got %d", len(entries))
	}

	for _, e := range entries {
		if e.Status != importer.StatusNew {
			t.Errorf("Expected status 'new' for %s, got %q", e.File.Name, e.Status)
		}
		t.Logf("  %s: status=%s tags=%v", e.File.Name, e.Status, e.Tags)
	}
}

func TestBuildFileEntriesParsedTags(t *testing.T) {
	root := t.TempDir()

	// Files with embedded tags in their names
	testFiles := map[string][]string{
		"meeting-notes-2026-03-09.wav":    {"meeting", "notes"},
		"project_alpha_draft.mp3":         {"project", "alpha", "draft"},
		"20260310_143000_standup.flac":     {"standup"},
		"interview.aac":                   {"interview"},
	}

	for name := range testFiles {
		if err := os.WriteFile(filepath.Join(root, name), []byte("audio"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	result, err := importer.ScanDir(root)
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}

	entries, err := importer.BuildFileEntries(result, nil)
	if err != nil {
		t.Fatalf("BuildFileEntries: %v", err)
	}

	// Build a lookup by filename
	byName := map[string]importer.FileEntry{}
	for _, e := range entries {
		byName[e.File.Name] = e
	}

	for name, expectedTags := range testFiles {
		e, ok := byName[name]
		if !ok {
			t.Errorf("Missing entry for %s", name)
			continue
		}
		for _, tag := range expectedTags {
			found := false
			for _, t2 := range e.Tags {
				if t2 == tag {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("File %s: expected tag %q, got tags %v", name, tag, e.Tags)
			}
		}
	}
}

func TestBuildFileEntriesWithChecker(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"tracked.wav", "untracked.wav", "failed.wav"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("data"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	result, err := importer.ScanDir(root)
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}

	// Mock checker: return status based on filename
	checker := func(filePath string) (importer.FileStatus, error) {
		base := filepath.Base(filePath)
		switch base {
		case "tracked.wav":
			return importer.StatusImported, nil
		case "failed.wav":
			return importer.StatusFailed, nil
		default:
			return importer.StatusNew, nil
		}
	}

	entries, err := importer.BuildFileEntries(result, checker)
	if err != nil {
		t.Fatalf("BuildFileEntries: %v", err)
	}

	byName := map[string]importer.FileEntry{}
	for _, e := range entries {
		byName[e.File.Name] = e
	}

	if byName["tracked.wav"].Status != importer.StatusImported {
		t.Errorf("tracked.wav: expected imported, got %s", byName["tracked.wav"].Status)
	}
	if byName["untracked.wav"].Status != importer.StatusNew {
		t.Errorf("untracked.wav: expected new, got %s", byName["untracked.wav"].Status)
	}
	if byName["failed.wav"].Status != importer.StatusFailed {
		t.Errorf("failed.wav: expected failed, got %s", byName["failed.wav"].Status)
	}
}

func TestFormatScanOutputTable(t *testing.T) {
	entries := []importer.FileEntry{
		{
			File:   importer.AudioFile{Path: "/tmp/a.wav", Name: "meeting-notes.wav", Ext: ".wav", Size: 2048},
			Status: importer.StatusNew,
			Tags:   []string{"meeting", "notes"},
		},
		{
			File:   importer.AudioFile{Path: "/tmp/b.mp3", Name: "interview_2026-03-09.mp3", Ext: ".mp3", Size: 1048576},
			Status: importer.StatusImported,
			Tags:   []string{"interview"},
		},
		{
			File:   importer.AudioFile{Path: "/tmp/c.flac", Name: "podcast.flac", Ext: ".flac", Size: 5242880},
			Status: importer.StatusUploaded,
			Tags:   []string{"podcast"},
		},
		{
			File:   importer.AudioFile{Path: "/tmp/d.ogg", Name: "broken.ogg", Ext: ".ogg", Size: 100},
			Status: importer.StatusFailed,
			Tags:   nil,
		},
	}

	output := importer.FormatScanOutput(entries, "/tmp")

	// Should contain directory
	if !strings.Contains(output, "/tmp") {
		t.Error("Output should contain scanned directory")
	}

	// Should contain count
	if !strings.Contains(output, "4 audio file(s)") {
		t.Error("Output should contain file count")
	}

	// Should contain filenames
	for _, name := range []string{"meeting-notes.wav", "interview_2026-03-09.mp3", "podcast.flac", "broken.ogg"} {
		if !strings.Contains(output, name) {
			t.Errorf("Output should contain filename %q", name)
		}
	}

	// Should contain status labels
	for _, status := range []string{"new", "imported", "uploaded", "failed"} {
		if !strings.Contains(output, status) {
			t.Errorf("Output should contain status %q", status)
		}
	}

	// Should contain tags
	for _, tag := range []string{"meeting", "notes", "interview", "podcast"} {
		if !strings.Contains(output, tag) {
			t.Errorf("Output should contain tag %q", tag)
		}
	}

	// Should contain status indicators
	if !strings.Contains(output, "+") {
		t.Error("Output should contain '+' indicator for new files")
	}

	// Should contain summary line
	if !strings.Contains(output, "Summary:") {
		t.Error("Output should contain Summary line")
	}
	if !strings.Contains(output, "1 new") {
		t.Error("Summary should show new count")
	}
	if !strings.Contains(output, "1 imported") {
		t.Error("Summary should show imported count")
	}
	if !strings.Contains(output, "1 uploaded") {
		t.Error("Summary should show uploaded count")
	}
	if !strings.Contains(output, "1 failed") {
		t.Error("Summary should show failed count")
	}

	t.Logf("Formatted output:\n%s", output)
}

func TestFormatScanOutputEmpty(t *testing.T) {
	output := importer.FormatScanOutput(nil, "/tmp")
	if !strings.Contains(output, "No audio files found") {
		t.Errorf("Empty output should say no files found, got: %s", output)
	}
}

func TestFormatScanOutputCompact(t *testing.T) {
	entries := []importer.FileEntry{
		{
			File:   importer.AudioFile{Path: "/audio/track1.wav", Name: "track1.wav", Ext: ".wav", Size: 4096},
			Status: importer.StatusNew,
			Tags:   []string{"track"},
		},
		{
			File:   importer.AudioFile{Path: "/audio/track2.mp3", Name: "track2.mp3", Ext: ".mp3", Size: 8192},
			Status: importer.StatusImported,
			Tags:   nil,
		},
	}

	output := importer.FormatScanOutputCompact(entries)
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 2 {
		t.Fatalf("Expected 2 lines, got %d: %q", len(lines), output)
	}

	// First line: new file with tags
	parts := strings.Split(lines[0], "\t")
	if len(parts) != 4 {
		t.Fatalf("Expected 4 tab-separated fields, got %d: %q", len(parts), lines[0])
	}
	if parts[0] != "new" {
		t.Errorf("Field 0: expected 'new', got %q", parts[0])
	}
	if parts[1] != "/audio/track1.wav" {
		t.Errorf("Field 1: expected path, got %q", parts[1])
	}
	if parts[2] != "4096" {
		t.Errorf("Field 2: expected '4096', got %q", parts[2])
	}
	if parts[3] != "track" {
		t.Errorf("Field 3: expected 'track', got %q", parts[3])
	}

	// Second line: imported file without tags
	parts2 := strings.Split(lines[1], "\t")
	if parts2[0] != "imported" {
		t.Errorf("Line 2 status: expected 'imported', got %q", parts2[0])
	}
}

func TestBuildFileEntriesWithTrackingDB(t *testing.T) {
	root := t.TempDir()
	dbPath := filepath.Join(root, "test-tracking.db")

	// Create test audio files
	trackedContent := []byte("tracked-audio-content")
	newContent := []byte("new-audio-content")
	if err := os.WriteFile(filepath.Join(root, "tracked.wav"), trackedContent, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "new-recording.wav"), newContent, 0o644); err != nil {
		t.Fatal(err)
	}

	// Open tracking DB and record one file
	db, err := tracking.OpenFilesDB(dbPath)
	if err != nil {
		t.Fatalf("OpenFilesDB: %v", err)
	}

	trackedPath := filepath.Join(root, "tracked.wav")
	hash, err := tracking.HashFile(trackedPath)
	if err != nil {
		t.Fatalf("HashFile: %v", err)
	}
	_, err = db.RecordFile(trackedPath, hash, int64(len(trackedContent)), "audio", "")
	if err != nil {
		t.Fatalf("RecordFile: %v", err)
	}
	db.Close()

	// Reopen DB for the checker
	db, err = tracking.OpenFilesDB(dbPath)
	if err != nil {
		t.Fatalf("Reopen DB: %v", err)
	}
	defer db.Close()

	// Scan directory
	result, err := importer.ScanDir(root)
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}

	// Build checker using DB
	checker := func(filePath string) (importer.FileStatus, error) {
		rec, lookupErr := db.GetByPath(filePath)
		if lookupErr != nil {
			return "", lookupErr
		}
		if rec == nil {
			return importer.StatusNew, nil
		}
		return importer.FileStatus(rec.Status), nil
	}

	entries, err := importer.BuildFileEntries(result, checker)
	if err != nil {
		t.Fatalf("BuildFileEntries: %v", err)
	}

	byName := map[string]importer.FileEntry{}
	for _, e := range entries {
		byName[e.File.Name] = e
	}

	if e, ok := byName["tracked.wav"]; !ok {
		t.Error("Missing tracked.wav")
	} else if e.Status != importer.StatusImported {
		t.Errorf("tracked.wav: expected imported, got %s", e.Status)
	}

	if e, ok := byName["new-recording.wav"]; !ok {
		t.Error("Missing new-recording.wav")
	} else if e.Status != importer.StatusNew {
		t.Errorf("new-recording.wav: expected new, got %s", e.Status)
	}

	// Verify the formatted output shows both statuses
	output := importer.FormatScanOutput(entries, root)
	if !strings.Contains(output, "imported") {
		t.Error("Output should show 'imported' status")
	}
	if !strings.Contains(output, "new") {
		t.Error("Output should show 'new' status")
	}
	t.Logf("Full output:\n%s", output)
}

func TestImporterCLIScanWithStatus(t *testing.T) {
	binPath := filepath.Join("..", "build", "m3c-tools")
	if _, err := os.Stat(binPath); err != nil {
		cmd := exec.Command("go", "build", "-tags", "cgo", "-o", binPath, "./cmd/m3c-tools/")
		cmd.Dir = filepath.Join("..")
		if buildErr := cmd.Run(); buildErr != nil {
			t.Skipf("cannot build binary: %v", buildErr)
		}
	}
	// Verify binary is actually executable
	if out, err := exec.Command(binPath, "help").CombinedOutput(); err != nil {
		t.Skipf("binary not executable: %v\n%s", err, out)
	}

	root := t.TempDir()
	// Create test audio files with meaningful names
	testFiles := []string{
		"meeting-notes-2026-03-09.wav",
		"project_alpha.mp3",
		"standup.flac",
	}
	for _, name := range testFiles {
		if err := os.WriteFile(filepath.Join(root, name), []byte("audio-data"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	// Use a temp DB so we don't pollute the real tracking DB
	dbPath := filepath.Join(root, "test.db")

	out, err := exec.Command(binPath, "import-audio", root, "--db", dbPath).CombinedOutput()
	if err != nil {
		t.Fatalf("import-audio failed: %v\nOutput: %s", err, out)
	}
	output := string(out)

	// Should show found files with status and tags
	if !strings.Contains(output, "3 audio file(s)") {
		t.Errorf("Expected '3 audio file(s)', got:\n%s", output)
	}

	// All files should be "new" since DB is empty
	if !strings.Contains(output, "new") {
		t.Errorf("Expected 'new' status for untracked files, got:\n%s", output)
	}

	// Should show parsed tags from filenames
	if !strings.Contains(output, "meeting") {
		t.Errorf("Expected 'meeting' tag parsed from filename, got:\n%s", output)
	}

	// Should contain summary
	if !strings.Contains(output, "Summary:") {
		t.Errorf("Expected summary line, got:\n%s", output)
	}

	t.Logf("CLI output:\n%s", output)
}

func TestImporterCLICompactOutput(t *testing.T) {
	binPath := filepath.Join("..", "build", "m3c-tools")
	if _, err := os.Stat(binPath); err != nil {
		cmd := exec.Command("go", "build", "-tags", "cgo", "-o", binPath, "./cmd/m3c-tools/")
		cmd.Dir = filepath.Join("..")
		if buildErr := cmd.Run(); buildErr != nil {
			t.Skipf("cannot build binary: %v", buildErr)
		}
	}
	// Verify binary is actually executable
	if out, err := exec.Command(binPath, "help").CombinedOutput(); err != nil {
		t.Skipf("binary not executable: %v\n%s", err, out)
	}

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "track1.wav"), []byte("audio"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	dbPath := filepath.Join(root, "test.db")
	out, err := exec.Command(binPath, "import-audio", root, "--compact", "--db", dbPath).CombinedOutput()
	if err != nil {
		t.Fatalf("import-audio --compact failed: %v\nOutput: %s", err, out)
	}
	output := string(out)

	// Compact output should have tab-separated fields after the scanning message
	lines := strings.Split(strings.TrimSpace(output), "\n")
	// Find the compact output line (after the "Scanning..." line)
	var compactLine string
	for _, line := range lines {
		if strings.HasPrefix(line, "new\t") || strings.HasPrefix(line, "imported\t") {
			compactLine = line
			break
		}
	}
	if compactLine == "" {
		t.Fatalf("Expected compact TSV output line, got:\n%s", output)
	}

	parts := strings.Split(compactLine, "\t")
	if len(parts) != 4 {
		t.Errorf("Expected 4 TSV fields, got %d: %q", len(parts), compactLine)
	}
	if parts[0] != "new" {
		t.Errorf("Expected 'new' status, got %q", parts[0])
	}

	t.Logf("Compact output:\n%s", output)
}
