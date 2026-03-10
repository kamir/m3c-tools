// End-to-end tests for the transcript library.
// These tests hit the real YouTube API — network required.
//
// Run: go test -v -tags e2e ./e2e/ -run TestTranscript
package e2e

import (
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/transcript"
)

const testVideoID = "dQw4w9WgXcQ" // Rick Astley — always available

func TestTranscriptList(t *testing.T) {
	api := transcript.New()
	list, err := api.List(testVideoID)
	if err != nil {
		t.Fatalf("List() error: %v", err)
	}
	if len(list.Transcripts) == 0 {
		t.Fatal("Expected at least one transcript")
	}

	// Should have English
	found := false
	for _, tr := range list.Transcripts {
		t.Logf("  %s (%s) generated=%v translatable=%v", tr.Language, tr.LanguageCode, tr.IsGenerated, tr.IsTranslatable)
		if tr.LanguageCode == "en" {
			found = true
		}
	}
	if !found {
		t.Error("Expected English transcript to be available")
	}
}

func TestTranscriptFetch(t *testing.T) {
	api := transcript.New()
	fetched, err := api.Fetch(testVideoID, []string{"en"}, false)
	if err != nil {
		t.Fatalf("Fetch() error: %v", err)
	}
	if len(fetched.Snippets) < 10 {
		t.Errorf("Expected at least 10 snippets, got %d", len(fetched.Snippets))
	}
	if fetched.LanguageCode != "en" {
		t.Errorf("Expected language code 'en', got '%s'", fetched.LanguageCode)
	}
	t.Logf("Fetched %d snippets, language: %s", len(fetched.Snippets), fetched.Language)

	// Check first snippet has content
	if fetched.Snippets[0].Text == "" {
		t.Error("First snippet has empty text")
	}
}

func TestTranscriptFetchGerman(t *testing.T) {
	api := transcript.New()
	fetched, err := api.Fetch(testVideoID, []string{"de-DE"}, false)
	if err != nil {
		t.Fatalf("Fetch(de-DE) error: %v", err)
	}
	if len(fetched.Snippets) < 10 {
		t.Errorf("Expected at least 10 snippets, got %d", len(fetched.Snippets))
	}
	t.Logf("German: %d snippets", len(fetched.Snippets))
}

func TestTranscriptFormatters(t *testing.T) {
	api := transcript.New()
	fetched, err := api.Fetch(testVideoID, []string{"en"}, false)
	if err != nil {
		t.Fatalf("Fetch() error: %v", err)
	}

	// Text
	tf := transcript.TextFormatter{}
	text := tf.FormatTranscript(fetched)
	if len(text) < 100 {
		t.Errorf("Text output too short: %d chars", len(text))
	}
	t.Logf("Text: %d chars", len(text))

	// SRT
	sf := transcript.SRTFormatter{}
	srt := sf.FormatTranscript(fetched)
	if !strings.Contains(srt, "-->") {
		t.Error("SRT output missing --> separator")
	}
	t.Logf("SRT: %d chars", len(srt))

	// JSON
	jf := transcript.JSONFormatter{Pretty: true}
	jsonOut := jf.FormatTranscript(fetched)
	if !strings.Contains(jsonOut, `"text"`) {
		t.Error("JSON output missing 'text' field")
	}
	t.Logf("JSON: %d chars", len(jsonOut))

	// WebVTT
	wf := transcript.WebVTTFormatter{}
	vtt := wf.FormatTranscript(fetched)
	if !strings.HasPrefix(vtt, "WEBVTT") {
		t.Error("WebVTT output missing WEBVTT header")
	}
	t.Logf("WebVTT: %d chars", len(vtt))
}

// -- Unit tests for filter flags (offline, no network) --

func TestTranscriptFilterExcludeGenerated(t *testing.T) {
	list := &transcript.TranscriptList{
		VideoID: "test123",
		Transcripts: []transcript.TranscriptInfo{
			{Language: "English", LanguageCode: "en", IsGenerated: true},
			{Language: "German", LanguageCode: "de", IsGenerated: false},
			{Language: "French", LanguageCode: "fr", IsGenerated: true},
			{Language: "Spanish", LanguageCode: "es", IsGenerated: false},
		},
	}

	filtered := list.FilterExcludeGenerated()

	if len(filtered.Transcripts) != 2 {
		t.Fatalf("Expected 2 transcripts after excluding generated, got %d", len(filtered.Transcripts))
	}
	for _, tr := range filtered.Transcripts {
		if tr.IsGenerated {
			t.Errorf("FilterExcludeGenerated kept generated transcript: %s", tr.LanguageCode)
		}
	}
	if filtered.Transcripts[0].LanguageCode != "de" {
		t.Errorf("Expected first transcript to be 'de', got %q", filtered.Transcripts[0].LanguageCode)
	}
	if filtered.Transcripts[1].LanguageCode != "es" {
		t.Errorf("Expected second transcript to be 'es', got %q", filtered.Transcripts[1].LanguageCode)
	}
	if filtered.VideoID != "test123" {
		t.Errorf("Expected VideoID preserved, got %q", filtered.VideoID)
	}
	// Original list should be unchanged
	if len(list.Transcripts) != 4 {
		t.Errorf("Original list was mutated: expected 4, got %d", len(list.Transcripts))
	}
}

func TestTranscriptFilterExcludeManuallyCreated(t *testing.T) {
	list := &transcript.TranscriptList{
		VideoID: "test456",
		Transcripts: []transcript.TranscriptInfo{
			{Language: "English", LanguageCode: "en", IsGenerated: true},
			{Language: "German", LanguageCode: "de", IsGenerated: false},
			{Language: "French", LanguageCode: "fr", IsGenerated: true},
			{Language: "Spanish", LanguageCode: "es", IsGenerated: false},
		},
	}

	filtered := list.FilterExcludeManuallyCreated()

	if len(filtered.Transcripts) != 2 {
		t.Fatalf("Expected 2 transcripts after excluding manually created, got %d", len(filtered.Transcripts))
	}
	for _, tr := range filtered.Transcripts {
		if !tr.IsGenerated {
			t.Errorf("FilterExcludeManuallyCreated kept manual transcript: %s", tr.LanguageCode)
		}
	}
	if filtered.Transcripts[0].LanguageCode != "en" {
		t.Errorf("Expected first transcript to be 'en', got %q", filtered.Transcripts[0].LanguageCode)
	}
	if filtered.Transcripts[1].LanguageCode != "fr" {
		t.Errorf("Expected second transcript to be 'fr', got %q", filtered.Transcripts[1].LanguageCode)
	}
	if filtered.VideoID != "test456" {
		t.Errorf("Expected VideoID preserved, got %q", filtered.VideoID)
	}
}

func TestTranscriptFilterBothExcludes(t *testing.T) {
	list := &transcript.TranscriptList{
		VideoID: "test789",
		Transcripts: []transcript.TranscriptInfo{
			{Language: "English", LanguageCode: "en", IsGenerated: true},
			{Language: "German", LanguageCode: "de", IsGenerated: false},
		},
	}

	// Applying both filters should result in empty list
	filtered := list.FilterExcludeGenerated().FilterExcludeManuallyCreated()
	if len(filtered.Transcripts) != 0 {
		t.Errorf("Expected 0 transcripts after both excludes, got %d", len(filtered.Transcripts))
	}
}

func TestTranscriptFilterEmptyList(t *testing.T) {
	list := &transcript.TranscriptList{
		VideoID:     "empty",
		Transcripts: nil,
	}

	filtered := list.FilterExcludeGenerated()
	if filtered.Transcripts != nil {
		t.Errorf("Expected nil transcripts for empty list, got %v", filtered.Transcripts)
	}

	filtered = list.FilterExcludeManuallyCreated()
	if filtered.Transcripts != nil {
		t.Errorf("Expected nil transcripts for empty list, got %v", filtered.Transcripts)
	}
}

func TestTranscriptFilterAllSameType(t *testing.T) {
	// All generated — exclude generated should yield empty
	allGen := &transcript.TranscriptList{
		VideoID: "allgen",
		Transcripts: []transcript.TranscriptInfo{
			{Language: "English", LanguageCode: "en", IsGenerated: true},
			{Language: "French", LanguageCode: "fr", IsGenerated: true},
		},
	}
	filtered := allGen.FilterExcludeGenerated()
	if len(filtered.Transcripts) != 0 {
		t.Errorf("Expected 0 after excluding all generated, got %d", len(filtered.Transcripts))
	}
	// Exclude manually created should keep all
	filtered = allGen.FilterExcludeManuallyCreated()
	if len(filtered.Transcripts) != 2 {
		t.Errorf("Expected 2 after excluding manual from all-generated, got %d", len(filtered.Transcripts))
	}
}

func TestTranscriptInvalidVideoID(t *testing.T) {
	api := transcript.New()
	_, err := api.List("invalid")
	if err == nil {
		t.Error("Expected error for invalid video ID")
	}
	t.Logf("Got expected error: %v", err)
}

func TestTranscriptFetchNMSHcSq8nMs(t *testing.T) {
	api := transcript.New()
	fetched, err := api.Fetch("NMSHcSq8nMs", []string{"en"}, false)
	if err != nil {
		t.Fatalf("Fetch() error: %v", err)
	}
	if len(fetched.Snippets) < 100 {
		t.Errorf("Expected many snippets, got %d", len(fetched.Snippets))
	}
	t.Logf("NMSHcSq8nMs: %d snippets, %s", len(fetched.Snippets), fetched.Language)
}
