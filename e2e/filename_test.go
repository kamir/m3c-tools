package e2e

import (
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/impression"
)

func TestParseFilenameISODate(t *testing.T) {
	info := impression.ParseFilename("2026-03-09_braindump_meeting.wav")
	if info.Timestamp.IsZero() {
		t.Fatal("Expected timestamp, got zero")
	}
	if info.Timestamp.Year() != 2026 || info.Timestamp.Month() != 3 || info.Timestamp.Day() != 9 {
		t.Errorf("Wrong date: %v", info.Timestamp)
	}
	assertContainsTag(t, info.Tags, "braindump")
	assertContainsTag(t, info.Tags, "meeting")
	if info.Extension != ".wav" {
		t.Errorf("Expected .wav extension, got %q", info.Extension)
	}
	t.Logf("Tags: %v, Timestamp: %v", info.Tags, info.Timestamp)
}

func TestParseFilenameCompactDatetime(t *testing.T) {
	info := impression.ParseFilename("20260309-143000-braindump.wav")
	if info.Timestamp.IsZero() {
		t.Fatal("Expected timestamp, got zero")
	}
	if info.Timestamp.Hour() != 14 || info.Timestamp.Minute() != 30 {
		t.Errorf("Wrong time: %v", info.Timestamp)
	}
	assertContainsTag(t, info.Tags, "braindump")
	t.Logf("Tags: %v, Timestamp: %v", info.Tags, info.Timestamp)
}

func TestParseFilenameISODatetime(t *testing.T) {
	info := impression.ParseFilename("meeting_2026-03-09T14-30-00_standup.wav")
	if info.Timestamp.IsZero() {
		t.Fatal("Expected timestamp, got zero")
	}
	if info.Timestamp.Hour() != 14 {
		t.Errorf("Expected hour 14, got %d", info.Timestamp.Hour())
	}
	assertContainsTag(t, info.Tags, "meeting")
	assertContainsTag(t, info.Tags, "standup")
	t.Logf("Tags: %v, Timestamp: %v", info.Tags, info.Timestamp)
}

func TestParseFilenameCompactDate(t *testing.T) {
	info := impression.ParseFilename("braindump_20260309.wav")
	if info.Timestamp.IsZero() {
		t.Fatal("Expected timestamp, got zero")
	}
	if info.Timestamp.Year() != 2026 {
		t.Errorf("Wrong year: %d", info.Timestamp.Year())
	}
	assertContainsTag(t, info.Tags, "braindump")
	t.Logf("Tags: %v, Timestamp: %v", info.Tags, info.Timestamp)
}

func TestParseFilenameNoTimestamp(t *testing.T) {
	info := impression.ParseFilename("braindump-meeting-notes.wav")
	if !info.Timestamp.IsZero() {
		t.Errorf("Expected zero timestamp, got %v", info.Timestamp)
	}
	assertContainsTag(t, info.Tags, "braindump")
	assertContainsTag(t, info.Tags, "meeting")
	assertContainsTag(t, info.Tags, "notes")
	t.Logf("Tags: %v", info.Tags)
}

func TestParseFilenameNoTags(t *testing.T) {
	info := impression.ParseFilename("2026-03-09.wav")
	if info.Timestamp.IsZero() {
		t.Fatal("Expected timestamp")
	}
	if len(info.Tags) != 0 {
		t.Errorf("Expected no tags, got %v", info.Tags)
	}
}

func TestParseFilenameWithPath(t *testing.T) {
	info := impression.ParseFilename("/Users/test/audio/braindump_2026-03-09.wav")
	assertContainsTag(t, info.Tags, "braindump")
	if info.Timestamp.IsZero() {
		t.Fatal("Expected timestamp from path-prefixed filename")
	}
	if info.BaseName != "braindump_2026-03-09" {
		t.Errorf("Unexpected basename: %q", info.BaseName)
	}
}

func TestParseFilenameM4A(t *testing.T) {
	info := impression.ParseFilename("standup-notes.m4a")
	if info.Extension != ".m4a" {
		t.Errorf("Expected .m4a, got %q", info.Extension)
	}
	assertContainsTag(t, info.Tags, "standup")
	assertContainsTag(t, info.Tags, "notes")
}

func TestParseFilenameTagsLowercased(t *testing.T) {
	info := impression.ParseFilename("BrainDump_Meeting.wav")
	assertContainsTag(t, info.Tags, "braindump")
	assertContainsTag(t, info.Tags, "meeting")
}

func TestParseFilenameCustomPatterns(t *testing.T) {
	// Custom pattern: match "day-NNN" as day-of-year
	// (demonstrating configurable patterns)
	patterns := []impression.FilenamePattern{
		{
			Regex:  impression.DefaultPatterns[3].Regex, // ISO date
			Layout: impression.DefaultPatterns[3].Layout,
		},
	}
	info := impression.ParseFilenameWith("braindump_2026-03-09.wav", patterns)
	if info.Timestamp.IsZero() {
		t.Fatal("Expected timestamp with custom patterns")
	}
	assertContainsTag(t, info.Tags, "braindump")
}

func TestParseFilenameCompactDatetimeUnderscore(t *testing.T) {
	info := impression.ParseFilename("20260309_143000_standup.wav")
	if info.Timestamp.IsZero() {
		t.Fatal("Expected timestamp")
	}
	if info.Timestamp.Hour() != 14 || info.Timestamp.Minute() != 30 {
		t.Errorf("Wrong time: %v", info.Timestamp)
	}
	assertContainsTag(t, info.Tags, "standup")
}

func TestParseFilenameIntegrationWithBuildImportTags(t *testing.T) {
	info := impression.ParseFilename("2026-03-09_braindump_standup.wav")
	tags := impression.BuildImportTags(info.Tags)
	parsed := impression.ParseTagLine(tags)

	// Should contain: import, audio-import, braindump, standup
	if len(parsed) < 4 {
		t.Errorf("Expected at least 4 tags, got %d: %v", len(parsed), parsed)
	}
	found := map[string]bool{}
	for _, tag := range parsed {
		found[tag] = true
	}
	for _, want := range []string{"import", "audio-import", "braindump", "standup"} {
		if !found[want] {
			t.Errorf("Missing expected tag %q in %v", want, parsed)
		}
	}
	t.Logf("Full tag string: %s", tags)
}

func TestParseFilenameTimestampUsableInCompositeDoc(t *testing.T) {
	info := impression.ParseFilename("2026-03-09T14-30-00_braindump.wav")
	doc := &impression.CompositeDoc{
		TranscriptText: "Some transcribed audio",
		ObsType:        impression.Import,
		Timestamp:      info.Timestamp,
	}
	result := doc.Build()
	if !containsStr(result, "2026-03-09 14:30:00") {
		t.Error("Composite doc should use parsed timestamp")
	}
	t.Logf("Composite with parsed timestamp: %d chars", len(result))
}

func TestParseFilenameYearBoundaryValidation(t *testing.T) {
	// Year 1999 should be rejected as out of range.
	info := impression.ParseFilename("19990101_braindump.wav")
	if !info.Timestamp.IsZero() {
		t.Errorf("Expected zero timestamp for year 1999, got %v", info.Timestamp)
	}
	assertContainsTag(t, info.Tags, "braindump")
}

func TestParseFilenameISODatetimeCompactTime(t *testing.T) {
	info := impression.ParseFilename("notes_2026-03-09T143000.wav")
	if info.Timestamp.IsZero() {
		t.Fatal("Expected timestamp for ISO date with compact time")
	}
	if info.Timestamp.Hour() != 14 || info.Timestamp.Minute() != 30 {
		t.Errorf("Wrong time: %v", info.Timestamp)
	}
	assertContainsTag(t, info.Tags, "notes")
}

func TestParseFilenameEmptyResult(t *testing.T) {
	info := impression.ParseFilename(".wav")
	if len(info.Tags) != 0 {
		t.Errorf("Expected no tags for bare extension, got %v", info.Tags)
	}
	if !info.Timestamp.IsZero() {
		t.Errorf("Expected zero timestamp, got %v", info.Timestamp)
	}
}

func TestDefaultPatternsAreValid(t *testing.T) {
	// Verify all default patterns compile and have valid layouts.
	for i, p := range impression.DefaultPatterns {
		if p.Regex == nil {
			t.Errorf("Pattern %d has nil regex", i)
		}
		// Patterns with explicit layouts should parse the reference time.
		if p.Layout != "" {
			ref := time.Date(2006, 1, 2, 15, 4, 5, 0, time.UTC).Format(p.Layout)
			_, err := time.Parse(p.Layout, ref)
			if err != nil {
				t.Errorf("Pattern %d layout %q fails roundtrip: %v", i, p.Layout, err)
			}
		}
	}
}

// --- helpers ---

func assertContainsTag(t *testing.T, tags []string, want string) {
	t.Helper()
	for _, tag := range tags {
		if tag == want {
			return
		}
	}
	t.Errorf("Tags %v missing expected tag %q", tags, want)
}

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && findSubstr(s, substr)
}

func findSubstr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
