package er1

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUpload_MissingAPIKey(t *testing.T) {
	cfg := &Config{APIURL: "http://localhost:9999/upload_2", APIKey: ""}
	payload := &UploadPayload{
		TranscriptData:     []byte("test"),
		TranscriptFilename: "test.txt",
	}
	_, err := Upload(cfg, payload)
	if err == nil {
		t.Error("expected error when API key is empty")
	}
}

func TestUpload_ServerAccepts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-KEY") != "test-key" {
			t.Errorf("X-API-KEY = %q, want test-key", r.Header.Get("X-API-KEY"))
		}
		if r.Method != "POST" {
			t.Errorf("Method = %q, want POST", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"doc_id":"abc123","message":"ok"}`))
	}))
	defer server.Close()

	cfg := &Config{
		APIURL:      server.URL + "/upload_2",
		APIKey:      "test-key",
		ContextID:   "user-123___mft",
		ContentType: "test-audio",
	}
	payload := &UploadPayload{
		TranscriptData:     []byte("test transcript content"),
		TranscriptFilename: "recording.txt",
		AudioData:          []byte("fake-audio-bytes"),
		AudioFilename:      "recording.mp3",
		Tags:               "plaud,test",
	}
	resp, err := Upload(cfg, payload)
	if err != nil {
		t.Fatalf("Upload failed: %v", err)
	}
	if resp.DocID != "abc123" {
		t.Errorf("DocID = %q, want abc123", resp.DocID)
	}
}

func TestUpload_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte(`{"error":"internal"}`))
	}))
	defer server.Close()

	cfg := &Config{
		APIURL:    server.URL + "/upload_2",
		APIKey:    "test-key",
		ContextID: "user-123",
	}
	payload := &UploadPayload{
		TranscriptData:     []byte("test"),
		TranscriptFilename: "test.txt",
	}
	_, err := Upload(cfg, payload)
	if err == nil {
		t.Error("expected error on 500 response")
	}
}
