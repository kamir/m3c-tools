package er1

import (
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestStartBackgroundRetry_ReadsQueuedFiles(t *testing.T) {
	t.Setenv("ER1_DEVICE_TOKEN", "")
	t.Setenv("M3C_ER1_KEYCHAIN", "off")

	dir := t.TempDir()
	transcriptPath := filepath.Join(dir, "vid_transcript.txt")
	audioPath := filepath.Join(dir, "vid_audio.wav")
	imagePath := filepath.Join(dir, "vid_thumb.jpg")
	wantTranscript := []byte("ORIGINAL TRANSCRIPT BYTES")
	wantAudio := []byte("ORIGINAL AUDIO BYTES")
	wantImage := []byte("ORIGINAL IMAGE BYTES")
	wantTime := "2026-01-02 03:04:05"
	if err := os.WriteFile(transcriptPath, wantTranscript, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(audioPath, wantAudio, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(imagePath, wantImage, 0600); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var gotTranscript, gotAudio, gotImage []byte
	var gotTime string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
			t.Errorf("Content-Type = %q", r.Header.Get("Content-Type"))
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mr := multipart.NewReader(r.Body, params["boundary"])
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Errorf("multipart: %v", err)
				break
			}
			body, _ := io.ReadAll(part)
			name := part.FormName()
			mu.Lock()
			switch name {
			case "transcript_file_ext":
				gotTranscript = append([]byte(nil), body...)
			case "audio_data_ext":
				gotAudio = append([]byte(nil), body...)
			case "image_data":
				gotImage = append([]byte(nil), body...)
			case "current_time":
				gotTime = string(body)
			}
			mu.Unlock()
			_ = part.Close()
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"doc_id":"retry-1","message":"ok"}`))
	}))
	defer srv.Close()

	queuePath := filepath.Join(dir, "queue.json")
	q := NewQueue(queuePath)
	if err := q.Add(QueueEntry{
		ID:             "vid-1",
		TranscriptPath: transcriptPath,
		AudioPath:      audioPath,
		ImagePath:      imagePath,
		Tags:           "youtube",
		CurrentTime:    wantTime,
	}); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		APIURL:        srv.URL,
		APIKey:        "test-key",
		ContextID:     "user-123___mft",
		UploadTimeout: 5,
	}
	bg := StartBackgroundRetry(queuePath, cfg, 20*time.Millisecond, 3)
	defer bg.Stop(2 * time.Second)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if NewQueue(queuePath).Len() == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if NewQueue(queuePath).Len() != 0 {
		t.Fatalf("queue still has %d entries; upload did not succeed", NewQueue(queuePath).Len())
	}

	mu.Lock()
	defer mu.Unlock()
	if string(gotTranscript) != string(wantTranscript) {
		t.Errorf("transcript = %q, want original file bytes (not a retry placeholder)", gotTranscript)
	}
	if string(gotAudio) != string(wantAudio) {
		t.Errorf("audio len=%d prefix=%q, want original file bytes", len(gotAudio), truncate(string(gotAudio), 24))
	}
	if string(gotImage) != string(wantImage) {
		t.Errorf("image len=%d prefix=%q, want original file bytes", len(gotImage), truncate(string(gotImage), 24))
	}
	if gotTime != wantTime {
		t.Errorf("current_time = %q, want %q", gotTime, wantTime)
	}
}
