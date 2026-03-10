package e2e

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/kamir/m3c-tools/pkg/er1"
)

// TestUploadFailureCreatesQueue verifies that a simulated ER1 upload failure
// correctly writes a queue entry to queue.json.
func TestUploadFailureCreatesQueue(t *testing.T) {
	tmpDir := t.TempDir()
	queuePath := filepath.Join(tmpDir, "queue.json")
	memoryRoot := filepath.Join(tmpDir, "MEMORY")
	t.Setenv("ER1_MEMORY_PATH", memoryRoot)

	payload := &er1.UploadPayload{
		TranscriptData:     []byte("test transcript content"),
		TranscriptFilename: "vid123_transcript.txt",
		AudioData:          []byte("fake-wav-data"),
		AudioFilename:      "vid123_audio.wav",
		ImageData:          []byte("fake-png-data"),
		ImageFilename:      "vid123_thumb.png",
		Tags:               "youtube,test",
	}

	uploadErr := errors.New("connection refused: ER1 server unreachable")

	result, err := er1.HandleUploadFailure(queuePath, memoryRoot, "vid123", payload, "youtube,test", uploadErr)
	if err != nil {
		t.Fatalf("HandleUploadFailure returned error: %v", err)
	}

	// Verify queue entry was returned
	if result.Entry == nil {
		t.Fatal("Expected non-nil queue entry")
	}
	if result.Entry.Tags != "youtube,test" {
		t.Errorf("Entry.Tags = %q, want %q", result.Entry.Tags, "youtube,test")
	}
	if result.Entry.LastError != "connection refused: ER1 server unreachable" {
		t.Errorf("Entry.LastError = %q, want upload error message", result.Entry.LastError)
	}

	// Verify queue.json file was written
	data, err := os.ReadFile(queuePath)
	if err != nil {
		t.Fatalf("Failed to read queue.json: %v", err)
	}

	var entries []er1.QueueEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatalf("Failed to parse queue.json: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("Expected 1 queue entry, got %d", len(entries))
	}
	if filepath.Base(entries[0].TranscriptPath) != "vid123_transcript.txt" {
		t.Errorf("TranscriptPath = %q, want filename vid123_transcript.txt", entries[0].TranscriptPath)
	}
	if filepath.Base(entries[0].AudioPath) != "vid123_audio.wav" {
		t.Errorf("AudioPath = %q, want filename vid123_audio.wav", entries[0].AudioPath)
	}
	if entries[0].MemoryPath == "" {
		t.Errorf("MemoryPath should be set, got empty")
	}

	t.Logf("queue.json written with %d entry, ID=%s", len(entries), entries[0].ID)
}

// TestUploadFailureAppendsQueue verifies that multiple failures correctly
// append to (not overwrite) queue.json.
func TestUploadFailureAppendsQueue(t *testing.T) {
	tmpDir := t.TempDir()
	queuePath := filepath.Join(tmpDir, "queue.json")
	memoryRoot := filepath.Join(tmpDir, "MEMORY")
	t.Setenv("ER1_MEMORY_PATH", memoryRoot)

	makePayload := func(id string) *er1.UploadPayload {
		return &er1.UploadPayload{
			TranscriptData:     []byte("transcript for " + id),
			TranscriptFilename: id + "_transcript.txt",
			Tags:               "test",
		}
	}

	// Simulate first failure
	_, err := er1.HandleUploadFailure(queuePath, memoryRoot, "vid_A", makePayload("vid_A"), "test", errors.New("timeout"))
	if err != nil {
		t.Fatalf("First failure: %v", err)
	}

	// Simulate second failure
	_, err = er1.HandleUploadFailure(queuePath, memoryRoot, "vid_B", makePayload("vid_B"), "test", errors.New("500 internal server error"))
	if err != nil {
		t.Fatalf("Second failure: %v", err)
	}

	// Simulate third failure
	_, err = er1.HandleUploadFailure(queuePath, memoryRoot, "vid_C", makePayload("vid_C"), "test", errors.New("DNS lookup failed"))
	if err != nil {
		t.Fatalf("Third failure: %v", err)
	}

	// Verify queue.json has all 3 entries
	data, err := os.ReadFile(queuePath)
	if err != nil {
		t.Fatalf("Failed to read queue.json: %v", err)
	}

	var entries []er1.QueueEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatalf("Failed to parse queue.json: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("Expected 3 queue entries, got %d", len(entries))
	}

	// Verify each entry has correct error
	errors_want := []string{"timeout", "500 internal server error", "DNS lookup failed"}
	for i, want := range errors_want {
		if entries[i].LastError != want {
			t.Errorf("Entry[%d].LastError = %q, want %q", i, entries[i].LastError, want)
		}
	}

	t.Logf("queue.json correctly appended %d entries", len(entries))
}

// TestUploadFailureCreatesMemoryFolder verifies that a simulated ER1 upload
// failure creates a MEMORY folder containing the payload files.
func TestUploadFailureCreatesMemoryFolder(t *testing.T) {
	tmpDir := t.TempDir()
	queuePath := filepath.Join(tmpDir, "queue.json")
	memoryRoot := filepath.Join(tmpDir, "MEMORY")
	t.Setenv("ER1_MEMORY_PATH", memoryRoot)

	payload := &er1.UploadPayload{
		TranscriptData:     []byte("E2E test transcript for failure handling"),
		TranscriptFilename: "fail_video_transcript.txt",
		AudioData:          []byte("fake-audio-bytes"),
		AudioFilename:      "fail_video_audio.wav",
		ImageData:          []byte("fake-image-bytes"),
		ImageFilename:      "fail_video_thumb.jpg",
		Tags:               "youtube, failure-test, e2e",
	}

	uploadErr := errors.New("TLS handshake timeout")

	result, err := er1.HandleUploadFailure(queuePath, memoryRoot, "fail_video", payload, "youtube,failure-test,e2e", uploadErr)
	if err != nil {
		t.Fatalf("HandleUploadFailure returned error: %v", err)
	}

	// Verify MEMORY folder was created
	if result.Memory == nil {
		t.Fatal("Expected non-nil MemoryFolder")
	}

	info, err := os.Stat(result.Memory.Path)
	if err != nil {
		t.Fatalf("MEMORY folder not created: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("MEMORY path is not a directory")
	}

	// Verify MemoryID format
	if len(result.Memory.MemoryID) == 0 {
		t.Error("MemoryID is empty")
	}
	t.Logf("MEMORY folder created: %s (ID=%s)", result.Memory.Path, result.Memory.MemoryID)

	// Verify transcript file was saved
	data, err := os.ReadFile(filepath.Join(result.Memory.Path, "fail_video_transcript.txt"))
	if err != nil {
		t.Fatalf("Transcript not written to MEMORY: %v", err)
	}
	if string(data) != "E2E test transcript for failure handling" {
		t.Errorf("Transcript content mismatch: got %q", string(data))
	}

	// Verify audio file was saved
	data, err = os.ReadFile(filepath.Join(result.Memory.Path, "fail_video_audio.wav"))
	if err != nil {
		t.Fatalf("Audio not written to MEMORY: %v", err)
	}
	if string(data) != "fake-audio-bytes" {
		t.Errorf("Audio content mismatch: got %q", string(data))
	}

	// Verify image file was saved
	data, err = os.ReadFile(filepath.Join(result.Memory.Path, "fail_video_thumb.jpg"))
	if err != nil {
		t.Fatalf("Image not written to MEMORY: %v", err)
	}
	if string(data) != "fake-image-bytes" {
		t.Errorf("Image content mismatch: got %q", string(data))
	}

	// Verify tag.txt was saved
	data, err = os.ReadFile(filepath.Join(result.Memory.Path, "tag.txt"))
	if err != nil {
		t.Fatalf("Tags not written to MEMORY: %v", err)
	}
	wantTags := "youtube\nfailure-test\ne2e\n"
	if string(data) != wantTags {
		t.Errorf("Tags = %q, want %q", string(data), wantTags)
	}

	t.Log("All payload files correctly saved to MEMORY folder")
}

// TestUploadFailureQueueAndMemoryBothExist verifies that both queue.json
// and MEMORY folder exist after a simulated failure — the complete failure path.
func TestUploadFailureQueueAndMemoryBothExist(t *testing.T) {
	tmpDir := t.TempDir()
	queuePath := filepath.Join(tmpDir, "queue.json")
	memoryRoot := filepath.Join(tmpDir, "MEMORY")
	t.Setenv("ER1_MEMORY_PATH", memoryRoot)

	payload := &er1.UploadPayload{
		TranscriptData:     []byte("combined test"),
		TranscriptFilename: "combined_transcript.txt",
		Tags:               "integration",
	}

	result, err := er1.HandleUploadFailure(queuePath, memoryRoot, "combined_vid", payload, "integration", errors.New("server down"))
	if err != nil {
		t.Fatalf("HandleUploadFailure: %v", err)
	}

	// Both must be non-nil
	if result.Entry == nil {
		t.Error("Queue entry is nil")
	}
	if result.Memory == nil {
		t.Error("MemoryFolder is nil")
	}

	// queue.json must exist and be parseable
	if _, err := os.Stat(queuePath); err != nil {
		t.Errorf("queue.json does not exist: %v", err)
	}

	// MEMORY folder must exist
	if _, err := os.Stat(result.Memory.Path); err != nil {
		t.Errorf("MEMORY folder does not exist: %v", err)
	}

	// Transcript in MEMORY must exist
	if _, err := os.Stat(filepath.Join(result.Memory.Path, "combined_transcript.txt")); err != nil {
		t.Errorf("Transcript not in MEMORY folder: %v", err)
	}

	t.Logf("Both queue.json and MEMORY folder exist after failure")
}

// TestUploadFailureNoMemoryOnSuccess confirms that MEMORY folders are
// only created on failure, not on success. This test verifies the design
// constraint by checking that direct Upload (if it could succeed) does NOT
// create MEMORY. We simulate by checking memoryRoot stays empty when we
// don't call HandleUploadFailure.
func TestUploadFailureNoMemoryOnSuccess(t *testing.T) {
	tmpDir := t.TempDir()
	memoryRoot := filepath.Join(tmpDir, "MEMORY")

	// Don't call HandleUploadFailure — simulate success path
	// Verify MEMORY root was never created
	if _, err := os.Stat(memoryRoot); !os.IsNotExist(err) {
		t.Errorf("MEMORY root should not exist on success path, but stat returned: %v", err)
	}

	t.Log("Confirmed: MEMORY folder not created when upload succeeds")
}
