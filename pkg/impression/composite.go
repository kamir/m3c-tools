// Package impression handles observation capture, composite document building,
// and tag management for the multimodal memory system.
package impression

import (
	"fmt"
	"strings"
	"time"
	"unicode"
)

// ObservationType categorizes the kind of observation.
type ObservationType string

const (
	Progress ObservationType = "progress" // YouTube video impression
	Idea     ObservationType = "idea"     // Screenshot observation
	Impulse  ObservationType = "impulse"  // Quick capture
	Import    ObservationType = "import"    // Batch audio import
	Fieldnote       ObservationType = "fieldnote"        // Plaud field recording
	PocketFieldnote ObservationType = "pocket_fieldnote" // Pocket USB recorder
	PocketGrouped   ObservationType = "pocket_grouped"   // Pocket grouped session
)

// CompositeDoc builds a composite text document for ER1 upload.
type CompositeDoc struct {
	VideoID        string
	VideoURL       string
	Language       string
	LanguageCode   string
	IsGenerated    bool
	SnippetCount   int
	TranscriptText    string
	ImpressionText    string
	ObsType           ObservationType
	Timestamp         time.Time
	RecordingTitle    string
	RecordingDuration string
}

// Build creates the composite document string.
func (d *CompositeDoc) Build() string {
	if d.Timestamp.IsZero() {
		d.Timestamp = time.Now()
	}
	ts := d.Timestamp.Format("2006-01-02 15:04:05")

	var b strings.Builder

	switch d.ObsType {
	case Progress:
		fmt.Fprintf(&b, "=== VIDEO TRANSCRIPT ===\n")
		fmt.Fprintf(&b, "Video ID: %s\n", d.VideoID)
		fmt.Fprintf(&b, "URL: %s\n", d.VideoURL)
		fmt.Fprintf(&b, "Language: %s (%s)\n", d.Language, d.LanguageCode)
		fmt.Fprintf(&b, "Generated: %v\n", d.IsGenerated)
		fmt.Fprintf(&b, "Snippets: %d\n", d.SnippetCount)
		fmt.Fprintf(&b, "Date: %s\n\n", ts)
		b.WriteString(d.TranscriptText)
		if d.ImpressionText != "" {
			fmt.Fprintf(&b, "\n=== USER IMPRESSION ===\n")
			b.WriteString(d.ImpressionText)
			b.WriteByte('\n')
		}
		fmt.Fprintf(&b, "\n=== END TRANSCRIPT ===\n")

	case Idea:
		fmt.Fprintf(&b, "=== SCREENSHOT OBSERVATION ===\n")
		fmt.Fprintf(&b, "Type: idea\n")
		fmt.Fprintf(&b, "Date: %s\n\n", ts)
		if d.ImpressionText != "" {
			b.WriteString(d.ImpressionText)
			b.WriteByte('\n')
		}
		fmt.Fprintf(&b, "\n=== END OBSERVATION ===\n")

	case Impulse:
		fmt.Fprintf(&b, "=== IMPULSE OBSERVATION ===\n")
		fmt.Fprintf(&b, "Type: impulse\n")
		fmt.Fprintf(&b, "Date: %s\n\n", ts)
		if d.ImpressionText != "" {
			b.WriteString(d.ImpressionText)
			b.WriteByte('\n')
		}
		fmt.Fprintf(&b, "\n=== END OBSERVATION ===\n")

	case Import:
		fmt.Fprintf(&b, "=== AUDIO IMPORT ===\n")
		fmt.Fprintf(&b, "Type: import\n")
		fmt.Fprintf(&b, "Date: %s\n\n", ts)
		b.WriteString(d.TranscriptText)
		fmt.Fprintf(&b, "\n=== END IMPORT ===\n")

	case Fieldnote:
		fmt.Fprintf(&b, "=== PLAUD FIELDNOTE ===\n")
		fmt.Fprintf(&b, "Recording: %s\n", d.RecordingTitle)
		fmt.Fprintf(&b, "Duration: %s\n", d.RecordingDuration)
		fmt.Fprintf(&b, "Date: %s\n\n", ts)
		b.WriteString(d.TranscriptText)
		if d.ImpressionText != "" {
			fmt.Fprintf(&b, "\n=== USER NOTES ===\n")
			b.WriteString(d.ImpressionText)
			b.WriteByte('\n')
		}
		fmt.Fprintf(&b, "\n=== END FIELDNOTE ===\n")

	case PocketFieldnote:
		fmt.Fprintf(&b, "=== POCKET FIELDNOTE ===\n")
		fmt.Fprintf(&b, "Device: Pocket Audio Tracker\n")
		fmt.Fprintf(&b, "Recording: %s\n", d.RecordingTitle)
		fmt.Fprintf(&b, "Duration: %s\n", d.RecordingDuration)
		fmt.Fprintf(&b, "Date: %s\n", ts)
		fmt.Fprintf(&b, "Source: %s\n\n", d.VideoURL) // reuse VideoURL for source file path
		if d.TranscriptText != "" {
			fmt.Fprintf(&b, "--- Transcript ---\n")
			b.WriteString(d.TranscriptText)
			b.WriteByte('\n')
		} else {
			fmt.Fprintf(&b, "[Transcription pending — audio queued for processing]\n\n")
		}
		fmt.Fprintf(&b, "\n=== END POCKET FIELDNOTE ===\n")

	case PocketGrouped:
		fmt.Fprintf(&b, "=== POCKET SESSION (GROUPED) ===\n")
		fmt.Fprintf(&b, "Device: Pocket Audio Tracker\n")
		fmt.Fprintf(&b, "Session: %s\n", d.RecordingTitle)
		fmt.Fprintf(&b, "Total Duration: %s\n", d.RecordingDuration)
		fmt.Fprintf(&b, "Segments: %d\n", d.SnippetCount) // reuse SnippetCount for segment count
		fmt.Fprintf(&b, "Date: %s\n\n", ts)
		if d.TranscriptText != "" {
			b.WriteString(d.TranscriptText)
		} else {
			fmt.Fprintf(&b, "[Transcription pending — merged audio queued for processing]\n\n")
		}
		if d.ImpressionText != "" {
			fmt.Fprintf(&b, "\n--- Raw File Manifest ---\n")
			b.WriteString(d.ImpressionText) // reuse for file listing
			b.WriteByte('\n')
		}
		fmt.Fprintf(&b, "\n=== END POCKET SESSION ===\n")
	}

	return normalizeSectionHeaderIndent(b.String())
}

// normalizeSectionHeaderIndent removes accidental leading spaces/tabs before
// section header lines (e.g. "=== SCREENSHOT OBSERVATION ===").
func normalizeSectionHeaderIndent(doc string) string {
	lines := strings.Split(doc, "\n")
	for i, line := range lines {
		trimmed := strings.TrimLeftFunc(line, unicode.IsSpace)
		if strings.HasPrefix(trimmed, "===") {
			lines[i] = trimmed
		}
	}
	return strings.Join(lines, "\n")
}
