package pocket

import (
	"encoding/json"
	"time"
)

// Envelope is the standard Pocket Cloud API response wrapper.
type Envelope struct {
	Success    bool            `json:"success"`
	Data       json.RawMessage `json:"data"`
	Error      string          `json:"error,omitempty"`
	Pagination *Pagination     `json:"pagination,omitempty"`
}

type Pagination struct {
	Page       int  `json:"page"`
	Limit      int  `json:"limit"`
	Total      int  `json:"total"`
	TotalPages int  `json:"total_pages"`
	HasMore    bool `json:"has_more"`
}

type Transcript struct {
	Metadata map[string]any   `json:"metadata,omitempty"`
	Segments []map[string]any `json:"segments,omitempty"`
	Text     string           `json:"text,omitempty"`
}

type SummaryV2 struct {
	Markdown     string   `json:"markdown,omitempty"`
	Title        string   `json:"title,omitempty"`
	Summary      string   `json:"summary,omitempty"`
	BulletPoints []string `json:"bullet_points,omitempty"`
	Emoji        string   `json:"emoji,omitempty"`
}

type ActionItemsV2 struct {
	Actions []map[string]any `json:"actions,omitempty"`
	Version string           `json:"version,omitempty"`
}

type Summarization struct {
	ID               string `json:"id,omitempty"`
	ProcessingStatus string `json:"processingStatus,omitempty"`
	V2               struct {
		Summary     SummaryV2     `json:"summary,omitempty"`
		ActionItems ActionItemsV2 `json:"actionItems,omitempty"`
	} `json:"v2,omitempty"`
}

// APIRecording matches the live heypocketai schema (verified 2026-04-27).
// Note: legacy field names (TranscriptText, AudioURL, SpeakerCount, WordCount, Summary)
// from the prior broken Phase-2 client have been REMOVED — the API does not return them.
type APIRecording struct {
	ID             string                   `json:"id"`
	Title          string                   `json:"title"`
	Duration       float64                  `json:"duration"`
	State          string                   `json:"state"` // "pending" | "completed"
	Language       *string                  `json:"language,omitempty"`
	RecordingAt    time.Time                `json:"recording_at"`
	CreatedAt      time.Time                `json:"created_at"`
	UpdatedAt      time.Time                `json:"updated_at"`
	Tags           []string                 `json:"tags"`
	Transcript     Transcript               `json:"transcript,omitempty"`
	RawTranscript  Transcript               `json:"raw_transcript,omitempty"`
	Summarizations map[string]Summarization `json:"summarizations,omitempty"`
}

func (r *APIRecording) IsCompleted() bool { return r.State == "completed" }

// DedupKey returns the canonical "pocket://<id>" identifier used by aims-core
// pocket_sync to dedup across devices.
func (r *APIRecording) DedupKey() string { return "pocket://" + r.ID }

// SummaryMarkdown returns the first non-empty v2 summary markdown across all
// summarizations (Pocket may store multiple revisions).
func (r *APIRecording) SummaryMarkdown() string {
	for _, s := range r.Summarizations {
		if s.V2.Summary.Markdown != "" {
			return s.V2.Summary.Markdown
		}
	}
	return ""
}

// LanguageOrEmpty returns the detected language string or "" if absent.
func (r *APIRecording) LanguageOrEmpty() string {
	if r.Language == nil {
		return ""
	}
	return *r.Language
}
