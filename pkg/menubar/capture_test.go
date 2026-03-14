//go:build darwin

package menubar

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/impression"
)

func TestDefaultCaptureData_Screenshot(t *testing.T) {
	data := DefaultCaptureData(impression.Idea)

	if data.Channel != impression.Idea {
		t.Errorf("channel = %q, want %q", data.Channel, impression.Idea)
	}
	if !strings.Contains(data.Tags, "idea") {
		t.Errorf("tags = %q, want to contain 'idea'", data.Tags)
	}
	if data.ContentType != "Screenshot-Observation" {
		t.Errorf("content type = %q, want %q", data.ContentType, "Screenshot-Observation")
	}
	if data.Timestamp.IsZero() {
		t.Error("timestamp should not be zero")
	}
}

func TestDefaultCaptureData_YouTube(t *testing.T) {
	data := DefaultCaptureData(impression.Progress)

	if data.Channel != impression.Progress {
		t.Errorf("channel = %q, want %q", data.Channel, impression.Progress)
	}
	if !strings.Contains(data.Tags, "youtube") {
		t.Errorf("tags = %q, want to contain 'youtube'", data.Tags)
	}
	if data.ContentType != "YouTube-Video-Impression" {
		t.Errorf("content type = %q, want %q", data.ContentType, "YouTube-Video-Impression")
	}
}

func TestDefaultCaptureData_Impulse(t *testing.T) {
	data := DefaultCaptureData(impression.Impulse)

	if data.Channel != impression.Impulse {
		t.Errorf("channel = %q, want %q", data.Channel, impression.Impulse)
	}
	if !strings.Contains(data.Tags, "impulse") {
		t.Errorf("tags = %q, want to contain 'impulse'", data.Tags)
	}
}

func TestDefaultCaptureData_Import(t *testing.T) {
	data := DefaultCaptureData(impression.Import)

	if !strings.Contains(data.Tags, "import") {
		t.Errorf("tags = %q, want to contain 'import'", data.Tags)
	}
	if !strings.Contains(data.Tags, "audio-import") {
		t.Errorf("tags = %q, want to contain 'audio-import'", data.Tags)
	}
}

func TestUpdateTagsFromUser(t *testing.T) {
	data := DefaultCaptureData(impression.Idea)
	data.UpdateTagsFromUser("  custom, tags, here  ")
	if data.Tags != "custom, tags, here" {
		t.Errorf("tags = %q, want %q", data.Tags, "custom, tags, here")
	}
}

func TestUpdateImpressionFromUser(t *testing.T) {
	data := DefaultCaptureData(impression.Idea)
	data.UpdateImpressionFromUser("  My observation notes  ")
	if data.ImpressionText != "My observation notes" {
		t.Errorf("impression = %q, want %q", data.ImpressionText, "My observation notes")
	}
}

func TestSaveDraft(t *testing.T) {
	// Use a temp directory to avoid writing to actual ~/.m3c-tools/drafts/
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	data := &CaptureData{
		Channel:        impression.Idea,
		Timestamp:      time.Date(2026, 3, 10, 14, 30, 0, 0, time.UTC),
		ImageData:      []byte("fake-png-data"),
		ImagePath:      "screenshot.png",
		AudioData:      []byte("fake-wav-data"),
		TranscriptText: "Hello world transcription",
		ImpressionText: "My notes about this screenshot",
		Tags:           "idea,screenshot,custom-tag",
		ContentType:    "Screenshot-Observation",
	}

	draftDir, err := SaveDraft(data)
	if err != nil {
		t.Fatalf("SaveDraft() error: %v", err)
	}

	// Verify draft directory was created.
	expectedDir := filepath.Join(tmpHome, ".m3c-tools", "drafts", "20260310_143000")
	if draftDir != expectedDir {
		t.Errorf("draft dir = %q, want %q", draftDir, expectedDir)
	}

	// Verify transcript file.
	transcriptPath := filepath.Join(draftDir, "idea_transcript.txt")
	transcriptData, err := os.ReadFile(transcriptPath)
	if err != nil {
		t.Fatalf("read transcript: %v", err)
	}
	if !strings.Contains(string(transcriptData), "SCREENSHOT OBSERVATION") {
		t.Errorf("transcript should contain 'SCREENSHOT OBSERVATION', got: %s", transcriptData[:100])
	}
	if !strings.Contains(string(transcriptData), "My notes about this screenshot") {
		t.Error("transcript should contain impression text")
	}

	// Verify image file.
	imgPath := filepath.Join(draftDir, "idea_20260310_143000.png")
	imgData, err := os.ReadFile(imgPath)
	if err != nil {
		t.Fatalf("read image: %v", err)
	}
	if string(imgData) != "fake-png-data" {
		t.Errorf("image data = %q, want %q", imgData, "fake-png-data")
	}

	// Verify audio file.
	audioPath := filepath.Join(draftDir, "idea_audio.wav")
	audioData, err := os.ReadFile(audioPath)
	if err != nil {
		t.Fatalf("read audio: %v", err)
	}
	if string(audioData) != "fake-wav-data" {
		t.Errorf("audio data = %q, want %q", audioData, "fake-wav-data")
	}

	// Verify metadata JSON.
	metaPath := filepath.Join(draftDir, "draft.json")
	metaData, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatalf("read metadata: %v", err)
	}

	var meta DraftMetadata
	if err := json.Unmarshal(metaData, &meta); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	if meta.Channel != "idea" {
		t.Errorf("meta.Channel = %q, want %q", meta.Channel, "idea")
	}
	if meta.Tags != "idea,screenshot,custom-tag" {
		t.Errorf("meta.Tags = %q, want %q", meta.Tags, "idea,screenshot,custom-tag")
	}
	if meta.ImpressionText != "My notes about this screenshot" {
		t.Errorf("meta.ImpressionText = %q, want %q", meta.ImpressionText, "My notes about this screenshot")
	}
}

func TestSaveDraft_NoAudioNoImage(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	data := &CaptureData{
		Channel:   impression.Impulse,
		Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Tags:      "impulse",
	}

	draftDir, err := SaveDraft(data)
	if err != nil {
		t.Fatalf("SaveDraft() error: %v", err)
	}

	// Transcript should exist.
	_, err = os.Stat(filepath.Join(draftDir, "impulse_transcript.txt"))
	if err != nil {
		t.Errorf("transcript file should exist: %v", err)
	}

	// Audio and image should not exist.
	_, err = os.Stat(filepath.Join(draftDir, "impulse_audio.wav"))
	if !os.IsNotExist(err) {
		t.Error("audio file should not exist when AudioData is nil")
	}
}

func TestBuildCompositeDoc_Idea(t *testing.T) {
	data := &CaptureData{
		Channel:        impression.Idea,
		Timestamp:      time.Date(2026, 3, 10, 14, 30, 0, 0, time.UTC),
		ImpressionText: "Test notes",
	}

	doc := buildCompositeDoc(data)
	result := doc.Build()

	if !strings.Contains(result, "SCREENSHOT OBSERVATION") {
		t.Errorf("composite should contain 'SCREENSHOT OBSERVATION', got: %s", result)
	}
	if !strings.Contains(result, "Test notes") {
		t.Error("composite should contain impression text")
	}
}

func TestBuildCompositeDoc_Progress(t *testing.T) {
	data := &CaptureData{
		Channel:        impression.Progress,
		Timestamp:      time.Date(2026, 3, 10, 14, 30, 0, 0, time.UTC),
		VideoID:        "dQw4w9WgXcQ",
		Language:       "English",
		LanguageCode:   "en",
		IsGenerated:    true,
		SnippetCount:   42,
		TranscriptText: "Full transcript text here",
		ImpressionText: "Great video",
	}

	doc := buildCompositeDoc(data)
	result := doc.Build()

	if !strings.Contains(result, "VIDEO TRANSCRIPT") {
		t.Error("composite should contain 'VIDEO TRANSCRIPT'")
	}
	if !strings.Contains(result, "dQw4w9WgXcQ") {
		t.Error("composite should contain video ID")
	}
	if !strings.Contains(result, "Great video") {
		t.Error("composite should contain impression text")
	}
}

func TestChannelPrefix(t *testing.T) {
	tests := []struct {
		ch   impression.ObservationType
		want string
	}{
		{impression.Progress, "progress"},
		{impression.Idea, "idea"},
		{impression.Impulse, "impulse"},
		{impression.Import, "import"},
		{"unknown", "observation"},
	}
	for _, tt := range tests {
		got := channelPrefix(tt.ch)
		if got != tt.want {
			t.Errorf("channelPrefix(%q) = %q, want %q", tt.ch, got, tt.want)
		}
	}
}

func TestImageFilename(t *testing.T) {
	// With image path that has an extension.
	data := &CaptureData{ImagePath: "/tmp/screenshot.png"}
	got := imageFilename(data, "idea", "20260310_143000")
	if got != "idea_20260310_143000.png" {
		t.Errorf("imageFilename = %q, want %q", got, "idea_20260310_143000.png")
	}

	// Without image path — defaults to .png.
	data2 := &CaptureData{}
	got2 := imageFilename(data2, "impulse", "20260310_143000")
	if got2 != "impulse_20260310_143000.png" {
		t.Errorf("imageFilename = %q, want %q", got2, "impulse_20260310_143000.png")
	}

	// With .jpg extension.
	data3 := &CaptureData{ImagePath: "/tmp/thumb.jpg"}
	got3 := imageFilename(data3, "progress", "20260310_143000")
	if got3 != "progress_20260310_143000.jpg" {
		t.Errorf("imageFilename = %q, want %q", got3, "progress_20260310_143000.jpg")
	}
}

func TestStoreToER1_FailsGracefully(t *testing.T) {
	// Set up a fake ER1 endpoint that doesn't exist — this tests graceful failure.
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	t.Setenv("ER1_API_URL", "https://127.0.0.1:19999/nonexistent")
	t.Setenv("ER1_UPLOAD_TIMEOUT", "1")
	t.Setenv("ER1_API_KEY", "test-key")

	data := &CaptureData{
		Channel:        impression.Idea,
		Timestamp:      time.Now(),
		ImageData:      []byte("fake-image"),
		TranscriptText: "test transcript",
		Tags:           "idea,screenshot",
	}

	result := StoreToER1(data)

	// Should fail gracefully (not panic) and queue for retry.
	if result.Success {
		t.Error("expected upload to fail against nonexistent endpoint")
	}
	if !result.Queued {
		t.Error("expected failed upload to be queued for retry")
	}
	if result.Message == "" {
		t.Error("expected a non-empty result message")
	}

	// Verify queue file was created.
	queuePath := filepath.Join(tmpHome, ".m3c-tools", "queue.json")
	if _, err := os.Stat(queuePath); os.IsNotExist(err) {
		t.Errorf("queue file should exist at %s", queuePath)
	}
}
