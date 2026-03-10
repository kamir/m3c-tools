// End-to-end tests for transcript library commands: import, list, search, export.
//
// Offline tests (no network):
//   - TestTranscriptImportFromSnippets — construct transcript from known snippets
//   - TestTranscriptListSearchByLanguage — FindTranscript language search
//   - TestTranscriptListSearchGenerated — FindGeneratedTranscript search
//   - TestTranscriptListSearchManual — FindManualTranscript search
//   - TestTranscriptSearchNotFound — search with no matching language
//   - TestTranscriptExportText — export as plain text
//   - TestTranscriptExportSRT — export as SRT subtitle
//   - TestTranscriptExportJSON — export as JSON
//   - TestTranscriptExportWebVTT — export as WebVTT subtitle
//   - TestTranscriptExportPretty — export as pretty-printed output
//   - TestTranscriptExportAllFormats — round-trip all formatters via FormatterLoader
//   - TestTranscriptExportToFile — write transcript export to temp file
//   - TestTranscriptListString — TranscriptList.String() representation
//
// Network tests:
//   - TestTranscriptCLIImport — run CLI binary to import transcript
//   - TestTranscriptCLIList — run CLI binary with --list flag
//   - TestTranscriptCLIExportSRT — run CLI binary with --format srt
//   - TestTranscriptCLIExportJSON — run CLI binary with --format json
//
// Run offline:  go test -v ./e2e/ -run "TestTranscriptImport|TestTranscriptListSearch|TestTranscriptSearch|TestTranscriptExport|TestTranscriptListString"
// Run network:  go test -v ./e2e/ -run "TestTranscriptCLI"
package e2e

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/transcript"
)

// -- Helper --

// buildTranscriptFixture returns a FetchedTranscript with realistic test data.
func buildTranscriptFixture() *transcript.FetchedTranscript {
	return &transcript.FetchedTranscript{
		VideoID:      "dQw4w9WgXcQ",
		Language:     "English",
		LanguageCode: "en",
		IsGenerated:  true,
		Snippets: []transcript.Snippet{
			{Text: "We're no strangers to love", Start: 0.0, Duration: 3.2},
			{Text: "You know the rules and so do I", Start: 3.2, Duration: 3.5},
			{Text: "A full commitment's what I'm thinking of", Start: 6.7, Duration: 4.0},
			{Text: "You wouldn't get this from any other guy", Start: 10.7, Duration: 3.8},
			{Text: "I just wanna tell you how I'm feeling", Start: 14.5, Duration: 3.0},
		},
	}
}

// buildTranscriptListFixture returns a TranscriptList with multiple languages.
func buildTranscriptListFixture() *transcript.TranscriptList {
	return &transcript.TranscriptList{
		VideoID: "dQw4w9WgXcQ",
		Transcripts: []transcript.TranscriptInfo{
			{Language: "English", LanguageCode: "en", IsGenerated: true, IsTranslatable: true},
			{Language: "German", LanguageCode: "de", IsGenerated: false, IsTranslatable: true},
			{Language: "French", LanguageCode: "fr", IsGenerated: true, IsTranslatable: false},
			{Language: "Japanese", LanguageCode: "ja", IsGenerated: false, IsTranslatable: true},
			{Language: "Spanish", LanguageCode: "es", IsGenerated: true, IsTranslatable: true},
		},
	}
}

// -- Import Tests (offline) --

// TestTranscriptImportFromSnippets verifies that a FetchedTranscript can be
// constructed from snippet data and has correct metadata.
func TestTranscriptImportFromSnippets(t *testing.T) {
	ft := buildTranscriptFixture()

	if ft.VideoID != "dQw4w9WgXcQ" {
		t.Errorf("VideoID = %q, want dQw4w9WgXcQ", ft.VideoID)
	}
	if ft.LanguageCode != "en" {
		t.Errorf("LanguageCode = %q, want en", ft.LanguageCode)
	}
	if len(ft.Snippets) != 5 {
		t.Fatalf("Snippets count = %d, want 5", len(ft.Snippets))
	}
	if ft.Snippets[0].Text != "We're no strangers to love" {
		t.Errorf("First snippet text = %q", ft.Snippets[0].Text)
	}
	if ft.Snippets[0].Start != 0.0 {
		t.Errorf("First snippet start = %f, want 0.0", ft.Snippets[0].Start)
	}
	if ft.Snippets[0].Duration != 3.2 {
		t.Errorf("First snippet duration = %f, want 3.2", ft.Snippets[0].Duration)
	}

	// Verify snippets are contiguous (next start ≈ prev start + prev duration)
	for i := 1; i < len(ft.Snippets); i++ {
		prevEnd := ft.Snippets[i-1].Start + ft.Snippets[i-1].Duration
		if ft.Snippets[i].Start < prevEnd-0.5 {
			t.Errorf("Snippet %d starts at %.1f, overlaps with previous ending at %.1f", i, ft.Snippets[i].Start, prevEnd)
		}
	}
}

// TestTranscriptImportPreservesMetadata verifies all metadata fields are preserved.
func TestTranscriptImportPreservesMetadata(t *testing.T) {
	ft := &transcript.FetchedTranscript{
		VideoID:      "abc123xyz99",
		Language:     "German",
		LanguageCode: "de",
		IsGenerated:  false,
		Snippets: []transcript.Snippet{
			{Text: "Hallo Welt", Start: 0.0, Duration: 2.0},
		},
	}

	if ft.Language != "German" {
		t.Errorf("Language = %q, want German", ft.Language)
	}
	if ft.IsGenerated {
		t.Error("IsGenerated should be false for manual transcript")
	}
	if ft.Snippets[0].Text != "Hallo Welt" {
		t.Errorf("Snippet text = %q, want 'Hallo Welt'", ft.Snippets[0].Text)
	}
}

// -- List/Search Tests (offline) --

// TestTranscriptListSearchByLanguage tests FindTranscript with various language codes.
func TestTranscriptListSearchByLanguage(t *testing.T) {
	list := buildTranscriptListFixture()

	tests := []struct {
		name     string
		langs    []string
		wantCode string
		wantErr  bool
	}{
		{"find English", []string{"en"}, "en", false},
		{"find German", []string{"de"}, "de", false},
		{"find Japanese", []string{"ja"}, "ja", false},
		{"fallback to second", []string{"zh", "fr"}, "fr", false},
		{"not found", []string{"ko", "ar"}, "", true},
		{"first match wins", []string{"de", "en"}, "de", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			info, err := list.FindTranscript(tc.langs)
			if tc.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if info.LanguageCode != tc.wantCode {
				t.Errorf("LanguageCode = %q, want %q", info.LanguageCode, tc.wantCode)
			}
		})
	}
}

// TestTranscriptListSearchGenerated tests FindGeneratedTranscript.
func TestTranscriptListSearchGenerated(t *testing.T) {
	list := buildTranscriptListFixture()

	// English is generated
	info, err := list.FindGeneratedTranscript([]string{"en"})
	if err != nil {
		t.Fatalf("FindGeneratedTranscript(en): %v", err)
	}
	if !info.IsGenerated {
		t.Error("Expected IsGenerated=true for English")
	}
	if info.LanguageCode != "en" {
		t.Errorf("LanguageCode = %q, want en", info.LanguageCode)
	}

	// German is NOT generated, should fail
	_, err = list.FindGeneratedTranscript([]string{"de"})
	if err == nil {
		t.Error("Expected error for non-generated German transcript")
	}

	// Spanish is generated
	info, err = list.FindGeneratedTranscript([]string{"es"})
	if err != nil {
		t.Fatalf("FindGeneratedTranscript(es): %v", err)
	}
	if info.LanguageCode != "es" {
		t.Errorf("LanguageCode = %q, want es", info.LanguageCode)
	}
}

// TestTranscriptListSearchManual tests FindManualTranscript.
func TestTranscriptListSearchManual(t *testing.T) {
	list := buildTranscriptListFixture()

	// German is manual
	info, err := list.FindManualTranscript([]string{"de"})
	if err != nil {
		t.Fatalf("FindManualTranscript(de): %v", err)
	}
	if info.IsGenerated {
		t.Error("Expected IsGenerated=false for manual German")
	}
	if info.LanguageCode != "de" {
		t.Errorf("LanguageCode = %q, want de", info.LanguageCode)
	}

	// English is NOT manual, should fail
	_, err = list.FindManualTranscript([]string{"en"})
	if err == nil {
		t.Error("Expected error for generated English transcript")
	}

	// Japanese is manual
	info, err = list.FindManualTranscript([]string{"ja"})
	if err != nil {
		t.Fatalf("FindManualTranscript(ja): %v", err)
	}
	if info.LanguageCode != "ja" {
		t.Errorf("LanguageCode = %q, want ja", info.LanguageCode)
	}
}

// TestTranscriptSearchNotFound verifies error types for missing transcripts.
func TestTranscriptSearchNotFound(t *testing.T) {
	list := buildTranscriptListFixture()

	_, err := list.FindTranscript([]string{"ko"})
	if err == nil {
		t.Fatal("Expected error for missing language")
	}

	// Error message should mention the requested language
	if !strings.Contains(err.Error(), "ko") {
		t.Errorf("Error should mention requested language 'ko': %v", err)
	}

	// Error message should list available languages
	if !strings.Contains(err.Error(), "English") || !strings.Contains(err.Error(), "en") {
		t.Errorf("Error should list available transcripts: %v", err)
	}
}

// -- Export Tests (offline) --

// TestTranscriptExportText tests text format export.
func TestTranscriptExportText(t *testing.T) {
	ft := buildTranscriptFixture()
	f := transcript.TextFormatter{}
	output := f.FormatTranscript(ft)

	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 5 {
		t.Errorf("Expected 5 lines, got %d", len(lines))
	}
	if lines[0] != "We're no strangers to love" {
		t.Errorf("First line = %q", lines[0])
	}
	if lines[4] != "I just wanna tell you how I'm feeling" {
		t.Errorf("Last line = %q", lines[4])
	}
	// Text format should not contain timestamps
	if strings.Contains(output, "-->") || strings.Contains(output, "00:") {
		t.Error("Text format should not contain timestamp markers")
	}
}

// TestTranscriptExportSRT tests SRT subtitle format export.
func TestTranscriptExportSRT(t *testing.T) {
	ft := buildTranscriptFixture()
	f := transcript.SRTFormatter{}
	output := f.FormatTranscript(ft)

	if !strings.Contains(output, "-->") {
		t.Error("SRT output missing --> separator")
	}
	// SRT uses comma for millisecond separator
	if !strings.Contains(output, ",") {
		t.Error("SRT should use comma for ms separator (HH:MM:SS,mmm)")
	}
	// Check sequence numbers
	if !strings.Contains(output, "1\n") {
		t.Error("SRT missing sequence number 1")
	}
	if !strings.Contains(output, "5\n") {
		t.Error("SRT missing sequence number 5")
	}
	// Check first timestamp
	if !strings.Contains(output, "00:00:00,000 --> 00:00:03,200") {
		t.Errorf("SRT first entry timestamp incorrect in:\n%s", output)
	}
	// Check content
	if !strings.Contains(output, "We're no strangers to love") {
		t.Error("SRT missing first snippet text")
	}
}

// TestTranscriptExportJSON tests JSON format export.
func TestTranscriptExportJSON(t *testing.T) {
	ft := buildTranscriptFixture()

	// Compact JSON
	f := transcript.JSONFormatter{Pretty: false}
	output := f.FormatTranscript(ft)

	if !strings.HasPrefix(output, "[") || !strings.HasSuffix(output, "]") {
		t.Error("JSON output should be wrapped in []")
	}

	// Parse it back
	var snippets []transcript.Snippet
	if err := json.Unmarshal([]byte(output), &snippets); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}
	if len(snippets) != 5 {
		t.Errorf("Expected 5 snippets in JSON, got %d", len(snippets))
	}
	if snippets[0].Text != "We're no strangers to love" {
		t.Errorf("First snippet text = %q", snippets[0].Text)
	}
	if snippets[0].Start != 0.0 {
		t.Errorf("First snippet start = %f", snippets[0].Start)
	}

	// Pretty JSON
	fPretty := transcript.JSONFormatter{Pretty: true}
	prettyOutput := fPretty.FormatTranscript(ft)
	if !strings.Contains(prettyOutput, "  ") {
		t.Error("Pretty JSON should contain indentation")
	}
	if !strings.Contains(prettyOutput, `"text"`) {
		t.Error("Pretty JSON should contain 'text' field")
	}
}

// TestTranscriptExportWebVTT tests WebVTT subtitle format export.
func TestTranscriptExportWebVTT(t *testing.T) {
	ft := buildTranscriptFixture()
	f := transcript.WebVTTFormatter{}
	output := f.FormatTranscript(ft)

	if !strings.HasPrefix(output, "WEBVTT") {
		t.Error("WebVTT must start with WEBVTT header")
	}
	if !strings.Contains(output, "-->") {
		t.Error("WebVTT output missing --> separator")
	}
	// WebVTT uses dot for millisecond separator
	if !strings.Contains(output, ".") {
		t.Error("WebVTT should use dot for ms separator (HH:MM:SS.mmm)")
	}
	if !strings.Contains(output, "00:00:00.000 --> 00:00:03.200") {
		t.Errorf("WebVTT first entry timestamp incorrect in:\n%s", output)
	}
	if !strings.Contains(output, "We're no strangers to love") {
		t.Error("WebVTT missing first snippet text")
	}
}

// TestTranscriptExportPretty tests pretty-print format export.
func TestTranscriptExportPretty(t *testing.T) {
	ft := buildTranscriptFixture()
	f := transcript.NewPrettyPrintFormatter()
	output := f.FormatTranscript(ft)

	// Header
	if !strings.Contains(output, "dQw4w9WgXcQ") {
		t.Error("Pretty output missing video ID")
	}
	if !strings.Contains(output, "English") {
		t.Error("Pretty output missing language")
	}
	// Box drawing
	if !strings.Contains(output, "│") {
		t.Error("Pretty output missing box drawing separator")
	}
	// Timestamps
	if !strings.Contains(output, "00:00") {
		t.Error("Pretty output missing timestamps")
	}
	// Footer
	if !strings.Contains(output, "Total: 5 snippets") {
		t.Error("Pretty output missing footer with snippet count")
	}
}

// TestTranscriptExportAllFormats verifies all registered formatters produce non-empty output.
func TestTranscriptExportAllFormats(t *testing.T) {
	ft := buildTranscriptFixture()
	loader := transcript.NewFormatterLoader()

	for _, name := range loader.Names() {
		t.Run(name, func(t *testing.T) {
			f, err := loader.Get(name)
			if err != nil {
				t.Fatalf("Get(%q) error: %v", name, err)
			}
			output := f.FormatTranscript(ft)
			if len(output) == 0 {
				t.Errorf("Formatter %q produced empty output", name)
			}
			// All formats should contain the snippet text
			if !strings.Contains(output, "strangers") {
				t.Errorf("Formatter %q output missing snippet text", name)
			}
		})
	}
}

// TestTranscriptExportToFile verifies transcript can be exported to a file.
func TestTranscriptExportToFile(t *testing.T) {
	ft := buildTranscriptFixture()
	tmpDir := t.TempDir()

	formats := map[string]transcript.Formatter{
		"transcript.txt":  transcript.TextFormatter{},
		"transcript.srt":  transcript.SRTFormatter{},
		"transcript.json": transcript.JSONFormatter{Pretty: true},
		"transcript.vtt":  transcript.WebVTTFormatter{},
	}

	for filename, formatter := range formats {
		t.Run(filename, func(t *testing.T) {
			output := formatter.FormatTranscript(ft)
			path := filepath.Join(tmpDir, filename)

			if err := os.WriteFile(path, []byte(output), 0644); err != nil {
				t.Fatalf("WriteFile(%s): %v", path, err)
			}

			// Verify file was written and has content
			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("Stat(%s): %v", path, err)
			}
			if info.Size() == 0 {
				t.Errorf("File %s is empty", filename)
			}

			// Read back and verify
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("ReadFile(%s): %v", path, err)
			}
			content := string(data)
			if !strings.Contains(content, "strangers") {
				t.Errorf("File %s missing expected content", filename)
			}

			t.Logf("%s: %d bytes", filename, info.Size())
		})
	}
}

// -- List String Tests (offline) --

// TestTranscriptListString tests TranscriptList.String() output.
func TestTranscriptListString(t *testing.T) {
	list := buildTranscriptListFixture()
	output := list.String()

	// Should contain each language
	for _, info := range list.Transcripts {
		if !strings.Contains(output, info.Language) {
			t.Errorf("String() missing language %q", info.Language)
		}
		if !strings.Contains(output, info.LanguageCode) {
			t.Errorf("String() missing language code %q", info.LanguageCode)
		}
	}

	// Should distinguish generated vs manual
	if !strings.Contains(output, "generated") {
		t.Error("String() missing 'generated' indicator")
	}
	if !strings.Contains(output, "manual") {
		t.Error("String() missing 'manual' indicator")
	}

	// Should mark translatable
	if !strings.Contains(output, "[translatable]") {
		t.Error("String() missing [translatable] indicator")
	}

	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 5 {
		t.Errorf("Expected 5 lines, got %d", len(lines))
	}
}

// TestTranscriptListStringEmpty tests String() with empty list.
func TestTranscriptListStringEmpty(t *testing.T) {
	list := &transcript.TranscriptList{VideoID: "empty", Transcripts: nil}
	output := list.String()
	if output != "" {
		t.Errorf("Empty list String() should be empty, got %q", output)
	}
}

// -- CLI Tests (require network + binary build) --

// TestTranscriptCLIImport builds and runs "m3c-tools transcript <video_id>"
// to verify the import command outputs transcript text.
func TestTranscriptCLIImport(t *testing.T) {
	SkipIfNoYTCalls(t)
	binary := buildTestBinary(t)

	cmd := exec.Command(binary, "transcript", testVideoID, "--lang", "en", "--format", "text")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("transcript import failed: %v\n%s", err, out)
	}

	output := string(out)
	if len(output) < 100 {
		t.Errorf("Transcript output too short: %d chars", len(output))
	}
	// Rick Astley transcript should contain recognizable lyrics
	lower := strings.ToLower(output)
	if !strings.Contains(lower, "never") && !strings.Contains(lower, "give") {
		t.Error("Transcript output missing expected content")
	}
	t.Logf("CLI import: %d chars", len(output))
}

// TestTranscriptCLIList builds and runs "m3c-tools transcript <video_id> --list"
// to verify the list command shows available transcripts.
func TestTranscriptCLIList(t *testing.T) {
	SkipIfNoYTCalls(t)
	binary := buildTestBinary(t)

	cmd := exec.Command(binary, "transcript", testVideoID, "--list")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("transcript list failed: %v\n%s", err, out)
	}

	output := string(out)
	// Should list at least English
	if !strings.Contains(output, "en") {
		t.Error("List output missing English (en)")
	}
	// Should show generated/manual indicators
	if !strings.Contains(output, "generated") && !strings.Contains(output, "manual") {
		t.Error("List output missing generated/manual indicators")
	}
	t.Logf("CLI list output:\n%s", output)
}

// TestTranscriptCLIExportSRT builds and runs with --format srt.
func TestTranscriptCLIExportSRT(t *testing.T) {
	SkipIfNoYTCalls(t)
	binary := buildTestBinary(t)

	cmd := exec.Command(binary, "transcript", testVideoID, "--lang", "en", "--format", "srt")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("transcript export srt failed: %v\n%s", err, out)
	}

	output := string(out)
	if !strings.Contains(output, "-->") {
		t.Error("SRT output missing --> separator")
	}
	if !strings.Contains(output, "1\n") {
		t.Error("SRT output missing sequence number 1")
	}
	t.Logf("CLI SRT: %d chars", len(output))
}

// TestTranscriptCLIExportJSON builds and runs with --format json.
func TestTranscriptCLIExportJSON(t *testing.T) {
	SkipIfNoYTCalls(t)
	binary := buildTestBinary(t)

	cmd := exec.Command(binary, "transcript", testVideoID, "--lang", "en", "--format", "json")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("transcript export json failed: %v\n%s", err, out)
	}

	output := string(out)
	// Should be valid JSON array
	var snippets []transcript.Snippet
	if err := json.Unmarshal([]byte(output), &snippets); err != nil {
		t.Fatalf("JSON parse error: %v\nOutput:\n%s", err, output[:min(200, len(output))])
	}
	if len(snippets) < 10 {
		t.Errorf("Expected at least 10 snippets, got %d", len(snippets))
	}
	t.Logf("CLI JSON: %d snippets", len(snippets))
}

// -- helpers --

// buildTestBinary compiles the m3c-tools binary for testing.
// It caches the result within a test run.
func buildTestBinary(t *testing.T) string {
	t.Helper()
	binary := filepath.Join("..", "build", "m3c-tools-test")
	build := exec.Command("go", "build", "-o", binary, "../cmd/m3c-tools")
	build.Dir = "."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	return binary
}
