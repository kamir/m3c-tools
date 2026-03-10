package e2e

import (
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/transcript"
)

// testTranscript creates a sample FetchedTranscript for testing.
func testTranscript() *transcript.FetchedTranscript {
	return &transcript.FetchedTranscript{
		VideoID:      "dQw4w9WgXcQ",
		Language:     "English",
		LanguageCode: "en",
		IsGenerated:  true,
		Snippets: []transcript.Snippet{
			{Text: "Never gonna give you up", Start: 0.0, Duration: 3.5},
			{Text: "Never gonna let you down", Start: 3.5, Duration: 3.2},
			{Text: "Never gonna run around and desert you", Start: 6.7, Duration: 4.1},
		},
	}
}

func TestPrettyPrintFormatterDefault(t *testing.T) {
	f := transcript.NewPrettyPrintFormatter()
	ft := testTranscript()
	output := f.FormatTranscript(ft)

	// Header should be present
	if !strings.Contains(output, "Video:") {
		t.Error("Missing Video: header field")
	}
	if !strings.Contains(output, "dQw4w9WgXcQ") {
		t.Error("Missing video ID in header")
	}
	if !strings.Contains(output, "Language:") {
		t.Error("Missing Language: header field")
	}
	if !strings.Contains(output, "English") {
		t.Error("Missing language name")
	}
	if !strings.Contains(output, "auto-generated") {
		t.Error("Missing auto-generated indicator")
	}

	// Snippets with timestamps
	if !strings.Contains(output, "│") {
		t.Error("Missing box-drawing column separator")
	}
	if !strings.Contains(output, "→") {
		t.Error("Missing timestamp arrow separator")
	}
	if !strings.Contains(output, "Never gonna give you up") {
		t.Error("Missing first snippet text")
	}
	if !strings.Contains(output, "Never gonna let you down") {
		t.Error("Missing second snippet text")
	}

	// Footer summary
	if !strings.Contains(output, "Total: 3 snippets") {
		t.Error("Missing total snippet count in footer")
	}

	// Line numbering
	if !strings.Contains(output, "1 │") {
		t.Error("Missing line number 1")
	}
	if !strings.Contains(output, "3 │") {
		t.Error("Missing line number 3")
	}

	t.Logf("Pretty output (%d chars):\n%s", len(output), output)
}

func TestPrettyPrintFormatterNoHeader(t *testing.T) {
	f := transcript.NewPrettyPrintFormatter()
	f.ShowHeader = false
	ft := testTranscript()
	output := f.FormatTranscript(ft)

	if strings.Contains(output, "Video:") {
		t.Error("Header should not be present when ShowHeader=false")
	}
	if !strings.Contains(output, "Never gonna give you up") {
		t.Error("Snippet text should still be present")
	}
	// No footer when header is off
	if strings.Contains(output, "Total:") {
		t.Error("Footer should not be present when ShowHeader=false")
	}
}

func TestPrettyPrintFormatterNoTimestamps(t *testing.T) {
	f := transcript.NewPrettyPrintFormatter()
	f.ShowTimestamps = false
	ft := testTranscript()
	output := f.FormatTranscript(ft)

	if strings.Contains(output, "→") {
		t.Error("Timestamps arrow should not be present when ShowTimestamps=false")
	}
	if !strings.Contains(output, "Never gonna give you up") {
		t.Error("Snippet text should still be present")
	}
}

func TestPrettyPrintFormatterMaxWidth(t *testing.T) {
	f := transcript.NewPrettyPrintFormatter()
	f.MaxWidth = 15
	ft := testTranscript()
	output := f.FormatTranscript(ft)

	// Third snippet "Never gonna run around and desert you" should be truncated
	if strings.Contains(output, "desert you") {
		t.Error("Long text should be truncated with MaxWidth=15")
	}
	if !strings.Contains(output, "…") {
		t.Error("Truncated text should end with ellipsis")
	}
}

func TestPrettyPrintFormatterInterface(t *testing.T) {
	// Ensure PrettyPrintFormatter satisfies the Formatter interface
	var f transcript.Formatter = *transcript.NewPrettyPrintFormatter()
	ft := testTranscript()
	output := f.FormatTranscript(ft)
	if output == "" {
		t.Error("Formatter interface output should not be empty")
	}
}

func TestPrettyPrintEmptyTranscript(t *testing.T) {
	f := transcript.NewPrettyPrintFormatter()
	ft := &transcript.FetchedTranscript{
		VideoID:      "empty123",
		Language:     "English",
		LanguageCode: "en",
		Snippets:     nil,
	}
	output := f.FormatTranscript(ft)
	if !strings.Contains(output, "empty123") {
		t.Error("Should contain video ID even for empty transcript")
	}
	if !strings.Contains(output, "Snippets: 0") {
		t.Error("Should show 0 snippets")
	}
}

func TestFormatTranscriptList(t *testing.T) {
	f := transcript.NewPrettyPrintFormatter()
	tl := &transcript.TranscriptList{
		VideoID: "abc123",
		Transcripts: []transcript.TranscriptInfo{
			{Language: "English", LanguageCode: "en", IsGenerated: true, IsTranslatable: true},
			{Language: "German", LanguageCode: "de", IsGenerated: false, IsTranslatable: false},
		},
	}
	output := f.FormatTranscriptList(tl)

	if !strings.Contains(output, "abc123") {
		t.Error("Missing video ID")
	}
	if !strings.Contains(output, "English") {
		t.Error("Missing English language")
	}
	if !strings.Contains(output, "German") {
		t.Error("Missing German language")
	}
	if !strings.Contains(output, "auto") {
		t.Error("Missing auto indicator for generated transcript")
	}
	if !strings.Contains(output, "manual") {
		t.Error("Missing manual indicator")
	}
	if !strings.Contains(output, "2 transcript(s) found") {
		t.Error("Missing transcript count")
	}
	if !strings.Contains(output, "╭") {
		t.Error("Missing box top")
	}
	if !strings.Contains(output, "╰") {
		t.Error("Missing box bottom")
	}
	t.Logf("TranscriptList output:\n%s", output)
}

func TestFormatTranscriptInfo(t *testing.T) {
	f := transcript.NewPrettyPrintFormatter()
	info := &transcript.TranscriptInfo{
		Language:     "German",
		LanguageCode: "de",
		IsGenerated:  false,
		IsTranslatable: true,
		TranslationLanguages: []transcript.TranslationLanguage{
			{Language: "English", LanguageCode: "en"},
			{Language: "French", LanguageCode: "fr"},
		},
	}
	output := f.FormatTranscriptInfo(info)

	if !strings.Contains(output, "German") {
		t.Error("Missing language name")
	}
	if !strings.Contains(output, "Manual") {
		t.Error("Missing Manual indicator")
	}
	if !strings.Contains(output, "2 languages") {
		t.Error("Missing translation count")
	}
}

func TestFormatSnippet(t *testing.T) {
	f := transcript.NewPrettyPrintFormatter()
	s := &transcript.Snippet{Text: "Hello world", Start: 65.0, Duration: 2.5}

	output := f.FormatSnippet(1, s)
	if !strings.Contains(output, "Hello world") {
		t.Error("Missing snippet text")
	}
	if !strings.Contains(output, "01:05") {
		t.Error("Missing formatted start time")
	}

	// Without timestamps
	f.ShowTimestamps = false
	output = f.FormatSnippet(1, s)
	if !strings.Contains(output, "Hello world") {
		t.Error("Missing snippet text without timestamps")
	}
	if strings.Contains(output, "→") {
		t.Error("Should not have arrow without timestamps")
	}
}

func TestFormatKeyValue(t *testing.T) {
	output := transcript.FormatKeyValue("Server", "https://example.com", 12)
	if !strings.Contains(output, "Server:") {
		t.Error("Missing key")
	}
	if !strings.Contains(output, "https://example.com") {
		t.Error("Missing value")
	}

	// Default padding
	output2 := transcript.FormatKeyValue("Key", "Val", 0)
	if !strings.Contains(output2, "Key:") {
		t.Error("Missing key with default padding")
	}
}

func TestFormatTable(t *testing.T) {
	columns := []string{"ID", "Video", "Status"}
	rows := [][]string{
		{"1", "dQw4w9WgXcQ", "uploaded"},
		{"2", "abc123xyz99", "pending"},
	}
	output := transcript.FormatTable(columns, rows)

	if !strings.Contains(output, "ID") {
		t.Error("Missing column header ID")
	}
	if !strings.Contains(output, "Video") {
		t.Error("Missing column header Video")
	}
	if !strings.Contains(output, "dQw4w9WgXcQ") {
		t.Error("Missing data row 1")
	}
	if !strings.Contains(output, "pending") {
		t.Error("Missing data row 2")
	}
	if !strings.Contains(output, "─┼─") {
		t.Error("Missing table separator")
	}

	// Empty columns
	empty := transcript.FormatTable(nil, nil)
	if empty != "" {
		t.Error("Empty columns should return empty string")
	}

	t.Logf("Table output:\n%s", output)
}

func TestFormatSection(t *testing.T) {
	output := transcript.FormatSection("ER1 Status", "Server: reachable\nKey: abc...")

	if !strings.Contains(output, "┌─ ER1 Status") {
		t.Error("Missing section header")
	}
	if !strings.Contains(output, "│ Server: reachable") {
		t.Error("Missing section content line 1")
	}
	if !strings.Contains(output, "│ Key: abc...") {
		t.Error("Missing section content line 2")
	}
	if !strings.Contains(output, "└─") {
		t.Error("Missing section footer")
	}

	t.Logf("Section output:\n%s", output)
}

func TestFormatStatusLine(t *testing.T) {
	tests := []struct {
		status   string
		expected string
	}{
		{"ok", "[OK]"},
		{"warn", "[!!]"},
		{"error", "[ERR]"},
		{"info", "[--]"},
		{"unknown", "[??]"},
	}

	for _, tc := range tests {
		output := transcript.FormatStatusLine(tc.status, "test message")
		if !strings.Contains(output, tc.expected) {
			t.Errorf("FormatStatusLine(%q): expected %q indicator, got: %s", tc.status, tc.expected, output)
		}
		if !strings.Contains(output, "test message") {
			t.Errorf("FormatStatusLine(%q): missing message text", tc.status)
		}
	}
}

func TestFormatterLoaderPretty(t *testing.T) {
	loader := transcript.NewFormatterLoader()

	// "pretty" should be registered
	f, err := loader.Get("pretty")
	if err != nil {
		t.Fatalf("Get(pretty): %v", err)
	}
	ft := testTranscript()
	output := f.FormatTranscript(ft)
	if !strings.Contains(output, "Video:") {
		t.Error("Pretty formatter from loader should include header")
	}

	// Default (empty name) should also return pretty formatter
	fDefault, err := loader.Get("")
	if err != nil {
		t.Fatalf("Get(''): %v", err)
	}
	outputDefault := fDefault.FormatTranscript(ft)
	if !strings.Contains(outputDefault, "Video:") {
		t.Error("Default formatter should be PrettyPrintFormatter with header")
	}

	// Names should include "pretty"
	names := loader.Names()
	found := false
	for _, n := range names {
		if n == "pretty" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Names() should include 'pretty', got: %v", names)
	}
}
