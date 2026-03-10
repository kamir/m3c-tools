package e2e

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/er1"
	"github.com/kamir/m3c-tools/pkg/impression"
	"github.com/kamir/m3c-tools/pkg/transcript"
)

func TestER1Config(t *testing.T) {
	cfg := er1.LoadConfig()
	if cfg.APIURL == "" {
		t.Error("API URL is empty")
	}
	if cfg.ContextID == "" {
		t.Error("Context ID is empty")
	}
	t.Logf("Config: %s", cfg.Summary())
}

func TestER1Reachable(t *testing.T) {
	cfg := er1.LoadConfig()
	if !er1.IsReachable(cfg) {
		t.Skip("ER1 server not reachable — skipping upload tests")
	}
	t.Log("ER1 server is reachable")
}

func TestER1UploadMinimal(t *testing.T) {
	cfg := er1.LoadConfig()
	if !er1.IsReachable(cfg) {
		t.Skip("ER1 server not reachable")
	}

	payload := &er1.UploadPayload{
		TranscriptData:     []byte("E2E test upload from m3c-tools"),
		TranscriptFilename: "e2e_test.txt",
		Tags:               "e2e-test,go-rewrite",
	}

	resp, err := er1.Upload(cfg, payload)
	if err != nil {
		t.Fatalf("Upload error: %v", err)
	}
	if resp.DocID == "" {
		t.Error("Expected doc_id in response")
	}
	t.Logf("Upload OK: doc_id=%s time=%s", resp.DocID, resp.Time)
}

func TestER1UploadFullPipeline(t *testing.T) {
	cfg := er1.LoadConfig()
	if !er1.IsReachable(cfg) {
		t.Skip("ER1 server not reachable")
	}

	videoID := "NMSHcSq8nMs"

	// Step 1: Fetch transcript
	api := transcript.New()
	fetched, err := api.Fetch(videoID, []string{"en"}, false)
	if err != nil {
		t.Fatalf("Transcript fetch error: %v", err)
	}
	t.Logf("Transcript: %d snippets", len(fetched.Snippets))

	// Step 2: Build composite
	textFmt := transcript.TextFormatter{}
	doc := &impression.CompositeDoc{
		VideoID:        videoID,
		VideoURL:       "https://www.youtube.com/watch?v=" + videoID,
		Language:       fetched.Language,
		LanguageCode:   fetched.LanguageCode,
		IsGenerated:    fetched.IsGenerated,
		SnippetCount:   len(fetched.Snippets),
		TranscriptText: textFmt.FormatTranscript(fetched),
		ImpressionText: "E2E pipeline test from Go rewrite",
		ObsType:        impression.Progress,
		Timestamp:      time.Now(),
	}
	composite := doc.Build()
	t.Logf("Composite: %d chars", len(composite))

	// Step 3: Fetch thumbnail
	fetcher, _ := transcript.NewFetcher(nil)
	thumbData, err := fetcher.FetchThumbnail(videoID)
	if err != nil {
		t.Logf("Thumbnail warning: %v", err)
	} else {
		t.Logf("Thumbnail: %d bytes", len(thumbData))
	}

	// Step 4: Upload to ER1
	tags := impression.BuildVideoTags(videoID, "", impression.Progress)
	resp, err := er1.Upload(cfg, &er1.UploadPayload{
		TranscriptData:     []byte(composite),
		TranscriptFilename: videoID + "_transcript.txt",
		ImageData:          thumbData,
		ImageFilename:      videoID + "_thumbnail.jpg",
		Tags:               tags,
	})
	if err != nil {
		t.Fatalf("Upload error: %v", err)
	}
	t.Logf("Upload SUCCESS: doc_id=%s gcs=%s", resp.DocID, resp.GCSURI)

	// Verify response has full text
	if len(resp.Transcript) < 1000 {
		t.Errorf("Server received truncated transcript: %d chars", len(resp.Transcript))
	} else {
		t.Logf("Server received full transcript: %d chars", len(resp.Transcript))
	}
}

func TestER1EnqueueFailure(t *testing.T) {
	// Test that upload failures are detected and serialized to queue.json
	tmpDir := t.TempDir()
	queuePath := tmpDir + "/queue.json"

	payload := &er1.UploadPayload{
		TranscriptData:     []byte("test transcript content"),
		TranscriptFilename: "vid123_transcript.txt",
		AudioData:          []byte("fake audio"),
		AudioFilename:      "vid123_audio.wav",
		ImageData:          []byte("fake image"),
		ImageFilename:      "vid123_thumbnail.jpg",
		Tags:               "test,upload",
	}
	uploadErr := fmt.Errorf("ER1 upload failed (status 503): Service Unavailable")

	// Enqueue the failure
	entry := er1.EnqueueFailure(queuePath, "vid123", payload, "test,upload", uploadErr)
	if entry == nil {
		t.Fatal("EnqueueFailure returned nil")
	}

	// Verify entry fields
	if entry.TranscriptPath != "vid123_transcript.txt" {
		t.Errorf("Expected transcript path vid123_transcript.txt, got %s", entry.TranscriptPath)
	}
	if entry.AudioPath != "vid123_audio.wav" {
		t.Errorf("Expected audio path vid123_audio.wav, got %s", entry.AudioPath)
	}
	if entry.ImagePath != "vid123_thumbnail.jpg" {
		t.Errorf("Expected image path vid123_thumbnail.jpg, got %s", entry.ImagePath)
	}
	if entry.Tags != "test,upload" {
		t.Errorf("Expected tags test,upload, got %s", entry.Tags)
	}
	if entry.LastError != uploadErr.Error() {
		t.Errorf("Expected error %q, got %q", uploadErr.Error(), entry.LastError)
	}
	if entry.ID == "" {
		t.Error("Expected non-empty ID")
	}

	// Verify the queue.json file was created and contains the entry
	if _, err := os.Stat(queuePath); os.IsNotExist(err) {
		t.Fatal("queue.json was not created")
	}

	// Reload queue and verify persistence
	q := er1.NewQueue(queuePath)
	if q.Len() != 1 {
		t.Fatalf("Expected 1 entry in queue, got %d", q.Len())
	}
	entries := q.Entries()
	if entries[0].LastError != uploadErr.Error() {
		t.Errorf("Persisted error mismatch: %q", entries[0].LastError)
	}
	if entries[0].QueuedAt.IsZero() {
		t.Error("Expected non-zero QueuedAt timestamp")
	}
	t.Logf("Queued entry: id=%s error=%s queued_at=%s", entries[0].ID, entries[0].LastError, entries[0].QueuedAt)

	// Test multiple failures accumulate
	uploadErr2 := fmt.Errorf("connection refused")
	er1.EnqueueFailure(queuePath, "vid456", payload, "retry,test", uploadErr2)
	q2 := er1.NewQueue(queuePath)
	if q2.Len() != 2 {
		t.Errorf("Expected 2 entries after second failure, got %d", q2.Len())
	}
}

func TestER1EnqueueFailureCreatesDir(t *testing.T) {
	// Test that EnqueueFailure creates parent directories if needed
	tmpDir := t.TempDir()
	queuePath := tmpDir + "/nested/subdir/queue.json"

	payload := &er1.UploadPayload{
		TranscriptData:     []byte("test"),
		TranscriptFilename: "test.txt",
	}
	entry := er1.EnqueueFailure(queuePath, "test", payload, "", fmt.Errorf("test error"))
	if entry == nil {
		t.Fatal("EnqueueFailure returned nil")
	}

	if _, err := os.Stat(queuePath); os.IsNotExist(err) {
		t.Fatal("queue.json was not created in nested directory")
	}
	t.Log("Nested directory creation works correctly")
}

func TestER1Queue(t *testing.T) {
	tmpPath := "/tmp/m3c-tools-test-queue.json"
	defer os.Remove(tmpPath)

	q := er1.NewQueue(tmpPath)
	if q.Len() != 0 {
		t.Errorf("Expected empty queue, got %d", q.Len())
	}

	// Add entries
	q.Add(er1.QueueEntry{ID: "test1", Tags: "a,b"})
	q.Add(er1.QueueEntry{ID: "test2", Tags: "c,d"})
	if q.Len() != 2 {
		t.Errorf("Expected 2 entries, got %d", q.Len())
	}

	// Persistence
	q2 := er1.NewQueue(tmpPath)
	if q2.Len() != 2 {
		t.Errorf("Expected 2 entries after reload, got %d", q2.Len())
	}

	// Remove
	q.Remove("test1")
	if q.Len() != 1 {
		t.Errorf("Expected 1 entry after remove, got %d", q.Len())
	}

	// Clear
	q.Clear()
	if q.Len() != 0 {
		t.Errorf("Expected empty after clear, got %d", q.Len())
	}
}
