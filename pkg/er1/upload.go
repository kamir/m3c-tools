package er1

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"time"
)

// UploadPayload describes the multipart data to send to ER1.
type UploadPayload struct {
	TranscriptData     []byte // composite document content
	TranscriptFilename string // e.g. "videoID_transcript.txt"
	AudioData          []byte // WAV audio data (optional — placeholder if nil)
	AudioFilename      string // e.g. "videoID_audio.wav"
	ImageData          []byte // JPEG/PNG image data (optional — placeholder if nil)
	ImageFilename      string // e.g. "videoID_thumbnail.jpg"
	Tags               string // comma-separated tags
}

// UploadResponse is the parsed response from ER1 on success.
type UploadResponse struct {
	DocID          string `json:"doc_id"`
	CollectionName string `json:"collection_name"`
	GCSURI         string `json:"gcs_uri"`
	GCSURIImg      string `json:"gcs_uri_img"`
	Transcript     string `json:"transcript"`
	Time           string `json:"time"`
	Message        string `json:"message"`
}

// Upload sends a multimodal payload to the ER1 server.
func Upload(cfg *Config, payload *UploadPayload) (*UploadResponse, error) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	// Form fields
	_ = writer.WriteField("context_id", cfg.ContextID)
	_ = writer.WriteField("content_type", cfg.ContentType)
	_ = writer.WriteField("tags", payload.Tags)

	// Transcript (always required)
	txPart, err := writer.CreateFormFile("transcript_file_ext", payload.TranscriptFilename)
	if err != nil {
		return nil, fmt.Errorf("create transcript part: %w", err)
	}
	_, _ = txPart.Write(payload.TranscriptData)

	// Audio (required by ER1 server)
	audioData := payload.AudioData
	audioName := payload.AudioFilename
	if audioData == nil {
		audioData = SilentWAV(1) // 1 second silence placeholder
		audioName = "placeholder.wav"
	}
	audioPart, err := writer.CreateFormFile("audio_data_ext", audioName)
	if err != nil {
		return nil, fmt.Errorf("create audio part: %w", err)
	}
	_, _ = audioPart.Write(audioData)

	// Image (required by ER1 server — crashes without it)
	imgData := payload.ImageData
	imgName := payload.ImageFilename
	if imgData == nil {
		imgData = PlaceholderPNG()
		imgName = "placeholder.png"
	}
	imgPart, err := writer.CreateFormFile("image_data", imgName)
	if err != nil {
		return nil, fmt.Errorf("create image part: %w", err)
	}
	_, _ = imgPart.Write(imgData)

	_ = writer.Close()

	// Build request
	req, err := http.NewRequest("POST", cfg.APIURL, &body)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	for k, v := range cfg.AuthHeaders() {
		req.Header.Set(k, v)
	}

	// Send
	client := &http.Client{
		Timeout: time.Duration(cfg.UploadTimeout) * time.Second,
	}
	if !cfg.VerifySSL {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("upload request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("ER1 upload failed (status %d): %s",
			resp.StatusCode, truncate(string(respBody), 200))
	}

	var result UploadResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return &result, nil
}

// IsReachable checks if the ER1 server is reachable via HEAD request.
func IsReachable(cfg *Config) bool {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	if !cfg.VerifySSL {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	req, err := http.NewRequest("HEAD", cfg.APIURL, nil)
	if err != nil {
		return false
	}
	for k, v := range cfg.AuthHeaders() {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return true // any response = reachable
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}
