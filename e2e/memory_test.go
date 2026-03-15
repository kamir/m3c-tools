package e2e

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/er1"
)

func TestMemoryID(t *testing.T) {
	ts := time.Date(2026, 3, 9, 12, 0, 0, 0, time.UTC)
	got := er1.MemoryID(ts)
	want := "MEMORY-20260309-120000"
	if got != want {
		t.Errorf("MemoryID = %q, want %q", got, want)
	}
}

func TestCreateMemoryFolder(t *testing.T) {
	rootDir := t.TempDir()
	ts := time.Date(2026, 3, 9, 14, 30, 45, 0, time.UTC)

	mf, err := er1.CreateMemoryFolder(rootDir, ts)
	if err != nil {
		t.Fatalf("CreateMemoryFolder failed: %v", err)
	}

	// Check MemoryID
	if mf.MemoryID != "MEMORY-20260309-143045" {
		t.Errorf("MemoryID = %q, want MEMORY-20260309-143045", mf.MemoryID)
	}

	// Check directory was created
	info, err := os.Stat(mf.Path)
	if err != nil {
		t.Fatalf("MEMORY folder not created: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("MEMORY path is not a directory")
	}

	// Check path
	wantPath := filepath.Join(rootDir, "MEMORY-20260309-143045")
	if mf.Path != wantPath {
		t.Errorf("Path = %q, want %q", mf.Path, wantPath)
	}
}

func TestCreateMemoryFolderIdempotent(t *testing.T) {
	rootDir := t.TempDir()
	ts := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)

	// Create once
	mf1, err := er1.CreateMemoryFolder(rootDir, ts)
	if err != nil {
		t.Fatalf("first CreateMemoryFolder failed: %v", err)
	}

	// Write a file inside to verify it persists after second call
	marker := filepath.Join(mf1.Path, "marker.txt")
	if err := os.WriteFile(marker, []byte("exists"), 0644); err != nil {
		t.Fatalf("write marker: %v", err)
	}

	// Create again — must succeed and not destroy contents
	mf2, err := er1.CreateMemoryFolder(rootDir, ts)
	if err != nil {
		t.Fatalf("second CreateMemoryFolder failed: %v", err)
	}

	if mf1.Path != mf2.Path {
		t.Errorf("paths differ: %q vs %q", mf1.Path, mf2.Path)
	}

	// Marker file must still exist
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("marker file disappeared after idempotent create: %v", err)
	}
}

func TestSavePayload(t *testing.T) {
	rootDir := t.TempDir()
	ts := time.Date(2026, 3, 9, 12, 0, 0, 0, time.UTC)

	mf, err := er1.CreateMemoryFolder(rootDir, ts)
	if err != nil {
		t.Fatalf("CreateMemoryFolder failed: %v", err)
	}

	payload := &er1.UploadPayload{
		TranscriptData:     []byte("Hello world transcript"),
		TranscriptFilename: "test_transcript.txt",
		AudioData:          []byte("fake-audio-data"),
		AudioFilename:      "test_audio.wav",
		ImageData:          []byte("fake-image-data"),
		ImageFilename:      "test_image.jpg",
		Tags:               "youtube, transcript, test",
	}

	if err := mf.SavePayload(payload); err != nil {
		t.Fatalf("SavePayload failed: %v", err)
	}

	// Verify transcript
	data, err := os.ReadFile(filepath.Join(mf.Path, "test_transcript.txt"))
	if err != nil {
		t.Fatalf("read transcript: %v", err)
	}
	if string(data) != "Hello world transcript" {
		t.Errorf("transcript content = %q", string(data))
	}

	// Verify audio
	data, err = os.ReadFile(filepath.Join(mf.Path, "test_audio.wav"))
	if err != nil {
		t.Fatalf("read audio: %v", err)
	}
	if string(data) != "fake-audio-data" {
		t.Errorf("audio content = %q", string(data))
	}

	// Verify image
	data, err = os.ReadFile(filepath.Join(mf.Path, "test_image.jpg"))
	if err != nil {
		t.Fatalf("read image: %v", err)
	}
	if string(data) != "fake-image-data" {
		t.Errorf("image content = %q", string(data))
	}

	// Verify tags
	data, err = os.ReadFile(filepath.Join(mf.Path, "tag.txt"))
	if err != nil {
		t.Fatalf("read tags: %v", err)
	}
	want := "youtube\ntranscript\ntest\n"
	if string(data) != want {
		t.Errorf("tags = %q, want %q", string(data), want)
	}
}

func TestSaveLoadPayloadRoundTrip(t *testing.T) {
	rootDir := t.TempDir()
	ts := time.Date(2026, 3, 14, 16, 0, 0, 0, time.UTC)

	mf, err := er1.CreateMemoryFolder(rootDir, ts)
	if err != nil {
		t.Fatalf("CreateMemoryFolder: %v", err)
	}

	original := &er1.UploadPayload{
		TranscriptData:     []byte("Audio import transcript"),
		TranscriptFilename: "import_20260314.txt",
		AudioData:          []byte("fake-mp3-data"),
		AudioFilename:      "Recording-RLS-001.mp3",
		ImageData:          []byte("fake-png"),
		ImageFilename:      "logo.png",
		Tags:               "audio-import,recording,rls",
		ContentType:        "Audio-Track vom Diktiergerät",
		DocID:              "abc123",
	}

	if err := mf.SavePayload(original); err != nil {
		t.Fatalf("SavePayload: %v", err)
	}

	// Verify metadata.json was written
	if _, err := os.Stat(filepath.Join(mf.Path, "metadata.json")); err != nil {
		t.Fatalf("metadata.json not written: %v", err)
	}

	loaded, err := mf.LoadPayload()
	if err != nil {
		t.Fatalf("LoadPayload: %v", err)
	}

	// ContentType must survive round-trip
	if loaded.ContentType != original.ContentType {
		t.Errorf("ContentType = %q, want %q", loaded.ContentType, original.ContentType)
	}
	// DocID must survive round-trip
	if loaded.DocID != original.DocID {
		t.Errorf("DocID = %q, want %q", loaded.DocID, original.DocID)
	}
	// Filenames must match exactly
	if loaded.TranscriptFilename != original.TranscriptFilename {
		t.Errorf("TranscriptFilename = %q, want %q", loaded.TranscriptFilename, original.TranscriptFilename)
	}
	if loaded.AudioFilename != original.AudioFilename {
		t.Errorf("AudioFilename = %q, want %q", loaded.AudioFilename, original.AudioFilename)
	}
	if loaded.ImageFilename != original.ImageFilename {
		t.Errorf("ImageFilename = %q, want %q", loaded.ImageFilename, original.ImageFilename)
	}
	// Data must match
	if string(loaded.TranscriptData) != string(original.TranscriptData) {
		t.Errorf("TranscriptData mismatch")
	}
	if string(loaded.AudioData) != string(original.AudioData) {
		t.Errorf("AudioData mismatch")
	}
	if loaded.Tags != original.Tags {
		t.Errorf("Tags = %q, want %q", loaded.Tags, original.Tags)
	}
}

func TestLoadPayloadMultipleFiles(t *testing.T) {
	// Simulates a MEMORY folder with multiple .txt and .wav files.
	// With metadata.json, LoadPayload should pick the correct ones.
	rootDir := t.TempDir()
	ts := time.Date(2026, 3, 10, 15, 7, 56, 0, time.UTC)

	mf, err := er1.CreateMemoryFolder(rootDir, ts)
	if err != nil {
		t.Fatalf("CreateMemoryFolder: %v", err)
	}

	// Save the intended payload
	payload := &er1.UploadPayload{
		TranscriptData:     []byte("correct transcript"),
		TranscriptFilename: "vid_C_transcript.txt",
		AudioData:          []byte("correct audio"),
		AudioFilename:      "vid123_audio.wav",
		ContentType:        "Test-Type",
	}
	if err := mf.SavePayload(payload); err != nil {
		t.Fatalf("SavePayload: %v", err)
	}

	// Add extra files that would confuse legacy LoadPayload
	os.WriteFile(filepath.Join(mf.Path, "vid_A_transcript.txt"), []byte("wrong A"), 0644)
	os.WriteFile(filepath.Join(mf.Path, "vid_B_transcript.txt"), []byte("wrong B"), 0644)
	os.WriteFile(filepath.Join(mf.Path, "fail_video_audio.wav"), []byte("wrong audio"), 0644)

	loaded, err := mf.LoadPayload()
	if err != nil {
		t.Fatalf("LoadPayload: %v", err)
	}

	// Must pick the file from metadata, not the last alphabetical match
	if loaded.TranscriptFilename != "vid_C_transcript.txt" {
		t.Errorf("TranscriptFilename = %q, want vid_C_transcript.txt", loaded.TranscriptFilename)
	}
	if string(loaded.TranscriptData) != "correct transcript" {
		t.Errorf("TranscriptData = %q, want 'correct transcript'", string(loaded.TranscriptData))
	}
	if loaded.AudioFilename != "vid123_audio.wav" {
		t.Errorf("AudioFilename = %q, want vid123_audio.wav", loaded.AudioFilename)
	}
	if string(loaded.AudioData) != "correct audio" {
		t.Errorf("AudioData = %q, want 'correct audio'", string(loaded.AudioData))
	}
	if loaded.ContentType != "Test-Type" {
		t.Errorf("ContentType = %q, want Test-Type", loaded.ContentType)
	}
}

func TestLoadPayloadLegacyNoMetadata(t *testing.T) {
	// MEMORY folder without metadata.json — legacy fallback behavior
	rootDir := t.TempDir()
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	mf, err := er1.CreateMemoryFolder(rootDir, ts)
	if err != nil {
		t.Fatalf("CreateMemoryFolder: %v", err)
	}

	// Write files directly (no SavePayload, no metadata.json)
	os.WriteFile(filepath.Join(mf.Path, "transcript.txt"), []byte("legacy transcript"), 0644)
	os.WriteFile(filepath.Join(mf.Path, "audio.mp3"), []byte("legacy audio"), 0644)
	os.WriteFile(filepath.Join(mf.Path, "tag.txt"), []byte("tag1\ntag2\n"), 0644)

	loaded, err := mf.LoadPayload()
	if err != nil {
		t.Fatalf("LoadPayload: %v", err)
	}

	if string(loaded.TranscriptData) != "legacy transcript" {
		t.Errorf("TranscriptData = %q", string(loaded.TranscriptData))
	}
	if string(loaded.AudioData) != "legacy audio" {
		t.Errorf("AudioData = %q", string(loaded.AudioData))
	}
	if loaded.Tags != "tag1,tag2" {
		t.Errorf("Tags = %q, want 'tag1,tag2'", loaded.Tags)
	}
	// Without metadata.json, ContentType should be empty
	if loaded.ContentType != "" {
		t.Errorf("ContentType = %q, want empty", loaded.ContentType)
	}
}

func TestSavePayloadOptionalFields(t *testing.T) {
	rootDir := t.TempDir()
	ts := time.Now()

	mf, err := er1.CreateMemoryFolder(rootDir, ts)
	if err != nil {
		t.Fatalf("CreateMemoryFolder failed: %v", err)
	}

	// Payload with only transcript (no audio, no image, no tags)
	payload := &er1.UploadPayload{
		TranscriptData:     []byte("transcript only"),
		TranscriptFilename: "transcript.txt",
	}

	if err := mf.SavePayload(payload); err != nil {
		t.Fatalf("SavePayload failed: %v", err)
	}

	// Transcript should exist
	if _, err := os.Stat(filepath.Join(mf.Path, "transcript.txt")); err != nil {
		t.Errorf("transcript not written: %v", err)
	}

	// tag.txt should NOT exist (no tags provided)
	if _, err := os.Stat(filepath.Join(mf.Path, "tag.txt")); !os.IsNotExist(err) {
		t.Errorf("tag.txt should not exist when no tags provided")
	}
}
