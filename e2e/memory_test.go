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
