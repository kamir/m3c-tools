package er1

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"os"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/httpsafe"
)

// UploadPayload describes the multipart data to send to ER1.
type UploadPayload struct {
	TranscriptData     []byte // composite document content (nil = no transcript provided)
	TranscriptFilename string // e.g. "videoID_transcript.txt"
	AudioData          []byte // WAV audio data (optional — placeholder if nil)
	AudioFilename      string // e.g. "videoID_audio.wav"
	ImageData          []byte // JPEG/PNG image data (optional — placeholder if nil)
	ImageFilename      string // e.g. "videoID_thumbnail.jpg"
	Tags               string // comma-separated tags
	ContentType        string // per-observation content type (overrides cfg.ContentType if set)
	DocID              string // if set, request ER1 to overwrite this existing document
	DoTranscribe       bool   // if true, send DO_TRANSCRIBE=true — server transcribes audio
	CurrentTime        string // real capture time "2006-01-02 15:04:05"; empty → server stamps now.
	// Positions the item at its true creation time in the memory viewer instead
	// of the import time — important for multi-device capture (SPEC-0117).
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
// Upload sends a multipart upload to the ER1 server.
// Authenticates via device token (Bearer, preferred) or API key (X-API-KEY, fallback).
func Upload(cfg *Config, payload *UploadPayload) (*UploadResponse, error) {
	hasToken := os.Getenv("ER1_DEVICE_TOKEN") != ""
	if cfg.APIKey == "" && !hasToken {
		return nil, fmt.Errorf("no authentication configured — log in with 'Sign In' or set ER1_API_KEY. " +
			"Run 'm3c-tools setup' to configure")
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
	if payload.DoTranscribe {
		_ = writer.WriteField("DO_TRANSCRIBE", "true")
	}
	if payload.CurrentTime != "" {
		// Real capture time — the server positions the item here instead of "now".
		_ = writer.WriteField("current_time", payload.CurrentTime)
	}

	// Transcript (optional — omit to let server handle transcription)
	if payload.TranscriptData != nil {
		txPart, err := writer.CreateFormFile("transcript_file_ext", payload.TranscriptFilename)
		if err != nil {
			return nil, fmt.Errorf("create transcript part: %w", err)
		}
		_, _ = txPart.Write(payload.TranscriptData)
	}

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
		Timeout:       time.Duration(cfg.UploadTimeout) * time.Second,
		CheckRedirect: httpsafe.NoCredentialRedirect, // SEC F25: don't leak X-API-KEY cross-host
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
		Timeout:       5 * time.Second,
		CheckRedirect: httpsafe.NoCredentialRedirect, // SEC F25
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

// PatchMemoryCurrentTime updates an already-stored ER1 memory item's
// `current_time` (the memory-viewer sort position) via
// PATCH /memory/<ctx>/<docID>. Used by `plaud fix-times` to backfill the real
// recording time onto items that were synced before capture-time support —
// no audio re-upload, no transcription disruption. currentTime must be
// "2006-01-02 15:04:05".
func PatchMemoryCurrentTime(cfg *Config, docID, currentTime string) error {
	if docID == "" || currentTime == "" {
		return fmt.Errorf("doc_id and current_time are required")
	}
	if cfg.APIKey == "" && os.Getenv("ER1_DEVICE_TOKEN") == "" {
		return fmt.Errorf("no authentication configured")
	}
	base := strings.TrimSuffix(cfg.APIURL, "/upload_2")
	base = strings.TrimSuffix(base, "/upload")
	base = strings.TrimSuffix(base, "/")
	endpoint := fmt.Sprintf("%s/memory/%s/%s", base, cfg.ContextID, docID)

	form := url.Values{}
	form.Set("current_time", currentTime)
	req, err := http.NewRequest("PATCH", endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// The /memory PATCH route enforces CSRF for a Bearer-only (session-style)
	// request but exempts API-key clients — so send X-API-KEY (not just the
	// device-token Bearer that AuthHeaders() prefers), else every PATCH 400s
	// with "CSRF token missing". Both headers are safe; the server accepts the key.
	if cfg.APIKey != "" {
		req.Header.Set("X-API-KEY", cfg.APIKey)
	}
	if token := os.Getenv("ER1_DEVICE_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if cfg.APIKey == "" {
		// No API key — fall back to the standard headers (may hit CSRF; the
		// real fix is a server-side CSRF exemption for token auth on this route).
		for k, v := range cfg.AuthHeaders() {
			req.Header.Set(k, v)
		}
	}

	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: httpsafe.NoCredentialRedirect}
	if !cfg.VerifySSL {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("PATCH current_time HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	return nil
}

// CaptureTimeLayout is the timestamp format ER1 stores in `current_time` and
// sorts the memory viewer by ("YYYY-MM-DD HH:MM:SS").
const CaptureTimeLayout = "2006-01-02 15:04:05"

// FormatCaptureTime formats a capture time for UploadPayload.CurrentTime.
// A zero time yields "" so the caller omits the field and the server stamps now.
func FormatCaptureTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(CaptureTimeLayout)
}

func isAudioImportPayload(contentType, tags string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	tg := strings.ToLower(strings.TrimSpace(tags))
	return strings.Contains(tg, "audio-import") ||
		strings.Contains(ct, "audio-import") ||
		strings.Contains(ct, "audio-track")
}
