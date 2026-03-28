//go:build darwin

// capture.go — Unified capture pipeline data and Store/Draft actions.
//
// CaptureData holds all observation data collected across the 4-step pipeline
// (Capture → Record → Review → Tags). The Store action uploads to ER1; the
// Cancel action saves to ~/.m3c-tools/drafts/.
package menubar

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/er1"
	"github.com/kamir/m3c-tools/pkg/impression"
)

// CaptureData holds all data collected during the unified capture pipeline.
// It is progressively populated as the user moves through the Observation
// Window tabs (Record → Review → Tags).
type CaptureData struct {
	// Channel identifies the capture source (screenshot, youtube, impulse, import).
	Channel impression.ObservationType

	// Timestamp is when the capture was initiated.
	Timestamp time.Time

	// ImagePath is the path to the captured screenshot or thumbnail image.
	ImagePath string

	// ImageData is the raw image bytes (PNG/JPEG).
	ImageData []byte

	// AudioData is the recorded voice note WAV bytes (nil if skipped).
	AudioData []byte

	// TranscriptText is the whisper transcription or YouTube transcript text.
	TranscriptText string

	// ImpressionText is the user's notes/summary from the Tags tab.
	ImpressionText string

	// Tags is the comma-separated tag string from the editable Tags field.
	Tags string

	// ContentType is the ER1 content type label (from .env or channel default).
	ContentType string

	// VideoID is set for YouTube channel captures.
	VideoID string

	// Language metadata for YouTube transcripts.
	Language     string
	LanguageCode string
	IsGenerated  bool
	SnippetCount int
}

// StoreResult captures the outcome of a Store action for display/logging.
type StoreResult struct {
	Success bool   // true if uploaded, false if queued or failed
	DocID   string // ER1 document ID on success
	Message string // human-readable result summary
	Queued  bool   // true if queued for retry (ER1 unreachable)
}

// StoreToER1 uploads the capture data to the ER1 endpoint. On failure, the
// upload is queued for retry via the JSON queue. Returns a StoreResult with
// the outcome. This function never returns an error — failures are captured
// in the result and queued for retry.
func StoreToER1(data *CaptureData) *StoreResult {
	cfg := er1.LoadConfig()

	// Override content type if set on capture data (from .env per channel).
	if data.ContentType != "" {
		cfg.ContentType = data.ContentType
	}

	// Build composite document.
	doc := buildCompositeDoc(data)
	composite := doc.Build()

	// Build timestamp-based filenames.
	ts := data.Timestamp.Format("20060102_150405")
	prefix := channelPrefix(data.Channel)

	// Build tags string (user-edited tags from the Tags tab).
	tags := data.Tags
	if tags == "" {
		tags = impression.BuildTags(data.Channel)
	}

	// Construct the upload payload.
	payload := &er1.UploadPayload{
		TranscriptData:     []byte(composite),
		TranscriptFilename: fmt.Sprintf("%s_%s.txt", prefix, ts),
		AudioData:          data.AudioData,
		AudioFilename:      fmt.Sprintf("%s_%s.wav", prefix, ts),
		ImageData:          data.ImageData,
		ImageFilename:      imageFilename(data, prefix, ts),
		Tags:               tags,
	}

	log.Printf("[store] START channel=%s tags=%q endpoint=%s", data.Channel, tags, cfg.APIURL)
	start := time.Now()

	resp, err := er1.Upload(cfg, payload)
	elapsed := time.Since(start)

	if err != nil {
		log.Printf("[store] FAIL channel=%s error=%v elapsed=%s", data.Channel, err, elapsed.Round(time.Millisecond))

		// Queue for retry.
		queuePath := er1.DefaultQueuePath()
		entry := er1.EnqueueFailure(queuePath, prefix, payload, tags, err)

		queueID := "unknown"
		if entry != nil {
			queueID = entry.ID
		}

		log.Printf("[store] QUEUED id=%s path=%s", queueID, queuePath)

		return &StoreResult{
			Success: false,
			Message: fmt.Sprintf("Upload failed, queued for retry: %s", queueID),
			Queued:  true,
		}
	}

	log.Printf("[store] DONE channel=%s doc_id=%s elapsed=%s", data.Channel, resp.DocID, elapsed.Round(time.Millisecond))

	return &StoreResult{
		Success: true,
		DocID:   resp.DocID,
		Message: fmt.Sprintf("Uploaded → doc_id: %s (%s)", resp.DocID, elapsed.Round(time.Millisecond)),
	}
}

// SaveDraft persists all capture data to ~/.m3c-tools/drafts/<timestamp>/
// so it can be reviewed and submitted later. Returns the draft directory path.
func SaveDraft(data *CaptureData) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("get home dir: %w", err)
	}

	ts := data.Timestamp.Format("20060102_150405")
	draftDir := filepath.Join(home, ".m3c-tools", "drafts", ts)

	if err := os.MkdirAll(draftDir, 0700); err != nil { // FIX-17: restrictive perms for user data
		return "", fmt.Errorf("create draft dir: %w", err)
	}

	prefix := channelPrefix(data.Channel)

	// Save composite document.
	doc := buildCompositeDoc(data)
	composite := doc.Build()
	transcriptPath := filepath.Join(draftDir, fmt.Sprintf("%s_transcript.txt", prefix))
	if err := os.WriteFile(transcriptPath, []byte(composite), 0600); err != nil {
		return draftDir, fmt.Errorf("write transcript: %w", err)
	}

	// Save image if present.
	if len(data.ImageData) > 0 {
		imgName := imageFilename(data, prefix, ts)
		imgPath := filepath.Join(draftDir, imgName)
		if err := os.WriteFile(imgPath, data.ImageData, 0600); err != nil {
			return draftDir, fmt.Errorf("write image: %w", err)
		}
	}

	// Save audio if present.
	if len(data.AudioData) > 0 {
		audioPath := filepath.Join(draftDir, fmt.Sprintf("%s_audio.wav", prefix))
		if err := os.WriteFile(audioPath, data.AudioData, 0600); err != nil {
			return draftDir, fmt.Errorf("write audio: %w", err)
		}
	}

	// Save metadata (tags, channel, timestamp, notes).
	meta := DraftMetadata{
		Channel:        string(data.Channel),
		Tags:           data.Tags,
		ContentType:    data.ContentType,
		ImpressionText: data.ImpressionText,
		VideoID:        data.VideoID,
		Timestamp:      data.Timestamp.Format(time.RFC3339),
	}
	metaJSON, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return draftDir, fmt.Errorf("marshal metadata: %w", err)
	}
	metaPath := filepath.Join(draftDir, "draft.json")
	if err := os.WriteFile(metaPath, metaJSON, 0600); err != nil {
		return draftDir, fmt.Errorf("write metadata: %w", err)
	}

	log.Printf("[draft] saved to %s (channel=%s tags=%q)", draftDir, data.Channel, data.Tags)
	return draftDir, nil
}

// DraftMetadata is the JSON structure saved as draft.json in the drafts directory.
type DraftMetadata struct {
	Channel        string `json:"channel"`
	Tags           string `json:"tags"`
	ContentType    string `json:"content_type,omitempty"`
	ImpressionText string `json:"impression_text,omitempty"`
	VideoID        string `json:"video_id,omitempty"`
	Timestamp      string `json:"timestamp"`
}

// DefaultCaptureData creates a CaptureData with sensible defaults for the
// given channel type. Tags are pre-filled based on the channel.
func DefaultCaptureData(channel impression.ObservationType) *CaptureData {
	data := &CaptureData{
		Channel:   channel,
		Timestamp: time.Now(),
	}

	// Pre-fill tags and content type based on channel.
	// Each channel has its own content type — ER1_CONTENT_TYPE is only used
	// for Progress (YouTube) uploads to stay backward-compatible.
	switch channel {
	case impression.Idea:
		data.Tags = impression.BuildTags(impression.Idea)
		data.ContentType = "Screenshot-Observation"
	case impression.Progress:
		data.Tags = impression.BuildTags(impression.Progress)
		data.ContentType = envOrDefault("ER1_CONTENT_TYPE", "YouTube-Video-Impression")
	case impression.Impulse:
		data.Tags = impression.BuildTags(impression.Impulse)
		data.ContentType = "Quick-Impulse"
	case impression.Import:
		data.Tags = impression.BuildTags(impression.Import)
		data.ContentType = envOrDefault("IMPORT_CONTENT_TYPE", "Audio-Import")
	}

	return data
}

// buildCompositeDoc creates a CompositeDoc from CaptureData.
func buildCompositeDoc(data *CaptureData) *impression.CompositeDoc {
	doc := &impression.CompositeDoc{
		ObsType:        data.Channel,
		Timestamp:      data.Timestamp,
		ImpressionText: data.ImpressionText,
		TranscriptText: data.TranscriptText,
	}

	if data.Channel == impression.Progress {
		doc.VideoID = data.VideoID
		doc.VideoURL = "https://www.youtube.com/watch?v=" + data.VideoID
		doc.Language = data.Language
		doc.LanguageCode = data.LanguageCode
		doc.IsGenerated = data.IsGenerated
		doc.SnippetCount = data.SnippetCount
	}

	return doc
}

// channelPrefix returns a short filename prefix for the channel type.
func channelPrefix(ch impression.ObservationType) string {
	switch ch {
	case impression.Progress:
		return "progress"
	case impression.Idea:
		return "idea"
	case impression.Impulse:
		return "impulse"
	case impression.Import:
		return "import"
	default:
		return "observation"
	}
}

// imageFilename returns an appropriate filename for the image file.
func imageFilename(data *CaptureData, prefix, ts string) string {
	if data.ImagePath != "" {
		ext := filepath.Ext(data.ImagePath)
		if ext != "" {
			return fmt.Sprintf("%s_%s%s", prefix, ts, ext)
		}
	}
	return fmt.Sprintf("%s_%s.png", prefix, ts)
}

// envOrDefault reads an environment variable, returning fallback if empty.
func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// UpdateTagsFromUser merges user-edited tags with the capture data.
// The input is a comma-separated string from the Tags tab text field.
func (cd *CaptureData) UpdateTagsFromUser(userTags string) {
	cd.Tags = strings.TrimSpace(userTags)
}

// UpdateImpressionFromUser sets the impression/notes text from the Tags tab.
func (cd *CaptureData) UpdateImpressionFromUser(notes string) {
	cd.ImpressionText = strings.TrimSpace(notes)
}
