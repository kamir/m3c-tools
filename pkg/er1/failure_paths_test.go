package er1

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestHandleUploadFailure_QueuePointsAtMemoryFiles(t *testing.T) {
	dir := t.TempDir()
	queuePath := filepath.Join(dir, "queue.json")
	memoryRoot := filepath.Join(dir, "MEMORY")
	wantText := []byte("ORIGINAL TRANSCRIPT")
	wantAudio := []byte("ORIGINAL AUDIO")
	payload := &UploadPayload{
		TranscriptData:     wantText,
		TranscriptFilename: "vid123_transcript.txt",
		AudioData:          wantAudio,
		AudioFilename:      "vid123_audio.wav",
		Tags:               "youtube",
	}

	result, err := HandleUploadFailure(queuePath, memoryRoot, "vid123", payload, "youtube", errors.New("refused"))
	if err != nil {
		t.Fatalf("HandleUploadFailure: %v", err)
	}
	if result.Entry == nil || result.Memory == nil {
		t.Fatal("expected queue entry and MEMORY folder")
	}
	if !strings.HasPrefix(result.Entry.TranscriptPath, result.Memory.Path) {
		t.Errorf("TranscriptPath = %q, want under %s", result.Entry.TranscriptPath, result.Memory.Path)
	}
	got := PayloadFromQueueEntry(*result.Entry)
	if string(got.TranscriptData) != string(wantText) {
		t.Errorf("retry transcript = %q, want original MEMORY bytes", got.TranscriptData)
	}
	if string(got.AudioData) != string(wantAudio) {
		t.Errorf("retry audio = %q, want original MEMORY bytes", got.AudioData)
	}
}
