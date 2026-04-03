package er1

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
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
	ContentType        string // per-observation content type (overrides cfg.ContentType if set)
	DocID              string // if set, request ER1 to overwrite this existing document
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
// BUG-0093: Requires a valid API key to bypass server-side CSRF protection.
// Without X-API-KEY, the server treats the request as a browser submission
// and rejects it with "CSRF session expired" (Forbidden Request).
func Upload(cfg *Config, payload *UploadPayload) (*UploadResponse, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("ER1_API_KEY is not set — upload requires an API key to authenticate. " +
			"Run 'm3c-tools setup' or 'm3c-tools config show' to configure your API key")
	}

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	// Form fields
	_ = writer.WriteField("context_id", cfg.ContextID)
	contentType := cfg.ContentType
	if payload.ContentType != "" {
		contentType = payload.ContentType
	}
	_ = writer.WriteField("content_type", contentType)
	_ = writer.WriteField("tags", payload.Tags)
	if payload.DocID != "" {
		_ = writer.WriteField("doc_id", payload.DocID)
	}

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
		if isAudioImportPayload(contentType, payload.Tags) {
			if logo := PlaceholderLogoPNG(); len(logo) > 0 {
				imgData = logo
				imgName = "placeholder-logo.png"
			} else {
				imgData = PlaceholderPNG()
				imgName = "placeholder.png"
			}
		} else {
			imgData = PlaceholderPNG()
			imgName = "placeholder.png"
		}
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

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
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

func isAudioImportPayload(contentType, tags string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	tg := strings.ToLower(strings.TrimSpace(tags))
	return strings.Contains(tg, "audio-import") ||
		strings.Contains(ct, "audio-import") ||
		strings.Contains(ct, "audio-track")
}
