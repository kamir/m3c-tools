package e2e

import (
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/impression"
)

func TestCompositeDocProgress(t *testing.T) {
	doc := &impression.CompositeDoc{
		VideoID:        "dQw4w9WgXcQ",
		VideoURL:       "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
		Language:       "English",
		LanguageCode:   "en",
		IsGenerated:    false,
		SnippetCount:   61,
		TranscriptText: "Never gonna give you up\nNever gonna let you down\n",
		ImpressionText: "Classic 80s banger",
		ObsType:        impression.Progress,
		Timestamp:      time.Date(2026, 3, 9, 12, 0, 0, 0, time.UTC),
	}
	result := doc.Build()

	if !strings.Contains(result, "=== VIDEO TRANSCRIPT ===") {
		t.Error("Missing VIDEO TRANSCRIPT header")
	}
	if !strings.Contains(result, "dQw4w9WgXcQ") {
		t.Error("Missing video ID")
	}
	if !strings.Contains(result, "Never gonna give you up") {
		t.Error("Missing transcript text")
	}
	if !strings.Contains(result, "Classic 80s banger") {
		t.Error("Missing impression text")
	}
	if !strings.Contains(result, "=== END TRANSCRIPT ===") {
		t.Error("Missing END TRANSCRIPT")
	}
	t.Logf("Composite document: %d chars", len(result))
}

func TestCompositeDocIdea(t *testing.T) {
	doc := &impression.CompositeDoc{
		ImpressionText: "Interesting UI pattern",
		ObsType:        impression.Idea,
	}
	result := doc.Build()
	if !strings.Contains(result, "=== SCREENSHOT OBSERVATION ===") {
		t.Error("Missing SCREENSHOT OBSERVATION header")
	}
}

func TestCompositeDocImpulse(t *testing.T) {
	doc := &impression.CompositeDoc{
		ImpressionText: "Quick thought about ML",
		ObsType:        impression.Impulse,
	}
	result := doc.Build()
	if !strings.Contains(result, "=== IMPULSE OBSERVATION ===") {
		t.Error("Missing IMPULSE OBSERVATION header")
	}
}

func TestCompositeDocImport(t *testing.T) {
	doc := &impression.CompositeDoc{
		TranscriptText: "Imported audio transcription text",
		ObsType:        impression.Import,
	}
	result := doc.Build()
	if !strings.Contains(result, "=== AUDIO IMPORT ===") {
		t.Error("Missing AUDIO IMPORT header")
	}
}

func TestBuildVideoTags(t *testing.T) {
	tags := impression.BuildVideoTags("dQw4w9WgXcQ", "RickAstleyVEVO", impression.Progress)
	if !strings.Contains(tags, "youtube") {
		t.Error("Missing youtube tag")
	}
	if !strings.Contains(tags, "video_id:dQw4w9WgXcQ") {
		t.Error("Missing video_id tag")
	}
	if !strings.Contains(tags, "channel:RickAstleyVEVO") {
		t.Error("Missing channel tag")
	}
	t.Logf("Tags: %s", tags)
}

func TestBuildImportTags(t *testing.T) {
	tags := impression.BuildImportTags([]string{"braindump", "meeting"})
	if !strings.Contains(tags, "audio-import") {
		t.Error("Missing audio-import tag")
	}
	if !strings.Contains(tags, "braindump") {
		t.Error("Missing braindump tag")
	}
	t.Logf("Tags: %s", tags)
}

func TestParseTagLine(t *testing.T) {
	tags := impression.ParseTagLine("youtube, video_id:abc, progress")
	if len(tags) != 3 {
		t.Errorf("Expected 3 tags, got %d", len(tags))
	}
}
