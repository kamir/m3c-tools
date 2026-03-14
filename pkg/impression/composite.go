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
	Fieldnote ObservationType = "fieldnote" // Plaud field recording
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
