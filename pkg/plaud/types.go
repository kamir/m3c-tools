// Package plaud provides an API client for the Plaud.ai voice recorder cloud.
// It fetches recordings and transcripts for the ER1 upload pipeline.
//
// The Plaud Web API is undocumented. This implementation is based on
// reverse-engineered endpoints (openplaud). All HTTP calls are isolated
// in client.go so only one file needs updating if endpoints change.
package plaud

import (
	"fmt"
	"time"
)

// Recording represents a single Plaud recording.
type Recording struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Status    string    `json:"status"` // e.g. "completed", "processing"
	Duration  int       `json:"duration"` // seconds
	CreatedAt time.Time `json:"created_at"`
	AudioURL  string    `json:"audio_url"`
}

// Transcript holds the text and speaker-diarized segments from Plaud.
type Transcript struct {
	Text     string    `json:"text"`
	Segments []Segment `json:"segments"`
	Summary  string    `json:"summary"`
}

// Segment is a speaker-diarized transcript chunk.
type Segment struct {
	Speaker   string  `json:"speaker"`
	StartTime float64 `json:"start_time"`
	EndTime   float64 `json:"end_time"`
	Text      string  `json:"text"`
}

// FormatDuration returns a human-readable duration string from seconds.
func FormatDuration(seconds int) string {
	m := seconds / 60
	s := seconds % 60
	if m > 0 {
		return fmt.Sprintf("%dm%02ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}
