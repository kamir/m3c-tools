package draft

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSaveAndLoad(t *testing.T) {
	dir := t.TempDir()

	d := &Draft{
		Channel:        ChannelScreenshot,
		Tags:           []string{"screenshot", "observation", "test"},
		Notes:          "Test observation notes",
		ScreenshotPath: "/tmp/test-screenshot.png",
		ContentType:    "Screenshot",
	}

	path, err := Save(dir, d)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("draft file not created: %v", err)
	}

	// Verify ID was auto-generated.
	if d.ID == "" {
		t.Error("expected ID to be generated")
	}

	// Verify CreatedAt was set.
	if d.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be set")
	}

	// Load it back.
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.Channel != ChannelScreenshot {
		t.Errorf("channel = %q, want %q", loaded.Channel, ChannelScreenshot)
	}
	if len(loaded.Tags) != 3 {
		t.Errorf("tags count = %d, want 3", len(loaded.Tags))
	}
	if loaded.Notes != "Test observation notes" {
		t.Errorf("notes = %q, want %q", loaded.Notes, "Test observation notes")
	}
	if loaded.ScreenshotPath != "/tmp/test-screenshot.png" {
		t.Errorf("screenshot_path = %q, want %q", loaded.ScreenshotPath, "/tmp/test-screenshot.png")
	}
	if loaded.ContentType != "Screenshot" {
		t.Errorf("content_type = %q, want %q", loaded.ContentType, "Screenshot")
	}
}

func TestSaveCreatesDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "drafts")

	d := &Draft{
		Channel: ChannelImpulse,
		Notes:   "Quick thought",
	}

	path, err := Save(dir, d)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("draft file not created in nested dir: %v", err)
	}
}

func TestSavePreservesExplicitID(t *testing.T) {
	dir := t.TempDir()

	d := &Draft{
		ID:      "custom-id-123",
		Channel: ChannelTranscript,
	}

	path, err := Save(dir, d)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	expected := filepath.Join(dir, "draft-custom-id-123.json")
	if path != expected {
		t.Errorf("path = %q, want %q", path, expected)
	}
}

func TestSavePreservesExplicitCreatedAt(t *testing.T) {
	dir := t.TempDir()

	ts := time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC)
	d := &Draft{
		Channel:   ChannelScreenshot,
		CreatedAt: ts,
	}

	_, err := Save(dir, d)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	if !d.CreatedAt.Equal(ts) {
		t.Errorf("CreatedAt changed: got %v, want %v", d.CreatedAt, ts)
	}
}

func TestListEmptyDir(t *testing.T) {
	dir := t.TempDir()

	paths, err := List(dir)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(paths) != 0 {
		t.Errorf("expected empty list, got %d entries", len(paths))
	}
}

func TestListNonExistentDir(t *testing.T) {
	paths, err := List("/nonexistent/path/drafts")
	if err != nil {
		t.Fatalf("List should not error on missing dir: %v", err)
	}
	if paths != nil {
		t.Errorf("expected nil, got %v", paths)
	}
}

func TestListMultipleDrafts(t *testing.T) {
	dir := t.TempDir()

	for i := 0; i < 3; i++ {
		d := &Draft{
			Channel: ChannelScreenshot,
			Notes:   "draft note",
		}
		if _, err := Save(dir, d); err != nil {
			t.Fatalf("Save %d failed: %v", i, err)
		}
		// Tiny sleep to ensure unique IDs (millisecond resolution).
		time.Sleep(2 * time.Millisecond)
	}

	paths, err := List(dir)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(paths) != 3 {
		t.Errorf("expected 3 drafts, got %d", len(paths))
	}
}

func TestListIgnoresNonJSON(t *testing.T) {
	dir := t.TempDir()

	// Create a non-JSON file.
	_ = os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("hello"), 0o644)

	// Create a JSON draft.
	d := &Draft{Channel: ChannelScreenshot}
	_, _ = Save(dir, d)

	paths, err := List(dir)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(paths) != 1 {
		t.Errorf("expected 1 draft (ignoring .txt), got %d", len(paths))
	}
}

func TestLoadInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(path, []byte("{invalid json"), 0o644)

	_, err := Load(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/draft.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestDefaultDraftsDir(t *testing.T) {
	dir := DefaultDraftsDir()
	if dir == "" {
		t.Error("DefaultDraftsDir returned empty string")
	}
	// Should end with .m3c-tools/drafts
	if filepath.Base(dir) != "drafts" {
		t.Errorf("expected dir to end with 'drafts', got %q", dir)
	}
	parent := filepath.Base(filepath.Dir(dir))
	if parent != ".m3c-tools" {
		t.Errorf("expected parent dir '.m3c-tools', got %q", parent)
	}
}

func TestAllChannelConstants(t *testing.T) {
	channels := []Channel{ChannelScreenshot, ChannelTranscript, ChannelImpulse, ChannelImport}
	expected := []string{"screenshot", "transcript", "impulse", "import"}

	for i, ch := range channels {
		if string(ch) != expected[i] {
			t.Errorf("channel %d = %q, want %q", i, ch, expected[i])
		}
	}
}
