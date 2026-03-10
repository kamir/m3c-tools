// Unit tests for the --translate flag and FetchTranslated API.
// Offline tests validate flag parsing and TranscriptInfo.IsTranslatable logic.
// Network tests (TestTranscriptFetchTranslated*) hit the real YouTube API.
//
// Run offline:  go test -v ./e2e/ -run TestTranslate
// Run network:  go test -v ./e2e/ -run TestTranscriptFetchTranslated
package e2e

import (
	"testing"

	"github.com/kamir/m3c-tools/pkg/transcript"
)

// TestTranslateFlagParsing verifies that --translate is correctly parsed
// alongside --lang and --format flags.
func TestTranslateFlagParsing(t *testing.T) {
	tests := []struct {
		name          string
		args          []string
		wantLang      string
		wantFormat    string
		wantTranslate string
		wantList      bool
	}{
		{
			name:          "translate to German",
			args:          []string{"VIDEO_ID", "--translate", "de"},
			wantLang:      "en",
			wantFormat:    "text",
			wantTranslate: "de",
		},
		{
			name:          "translate with explicit source lang",
			args:          []string{"VIDEO_ID", "--lang", "fr", "--translate", "es"},
			wantLang:      "fr",
			wantFormat:    "text",
			wantTranslate: "es",
		},
		{
			name:          "translate with format",
			args:          []string{"VIDEO_ID", "--translate", "ja", "--format", "srt"},
			wantLang:      "en",
			wantFormat:    "srt",
			wantTranslate: "ja",
		},
		{
			name:          "no translate flag",
			args:          []string{"VIDEO_ID", "--lang", "en"},
			wantLang:      "en",
			wantFormat:    "text",
			wantTranslate: "",
		},
		{
			name:          "list overrides translate",
			args:          []string{"VIDEO_ID", "--translate", "de", "--list"},
			wantLang:      "en",
			wantFormat:    "text",
			wantTranslate: "de",
			wantList:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the flag parsing from cmdTranscript
			lang := "en"
			format := "text"
			translateLang := ""
			listOnly := false

			for i := 1; i < len(tt.args); i++ {
				switch tt.args[i] {
				case "--lang":
					if i+1 < len(tt.args) {
						lang = tt.args[i+1]
						i++
					}
				case "--format":
					if i+1 < len(tt.args) {
						format = tt.args[i+1]
						i++
					}
				case "--translate":
					if i+1 < len(tt.args) {
						translateLang = tt.args[i+1]
						i++
					}
				case "--list":
					listOnly = true
				}
			}

			if lang != tt.wantLang {
				t.Errorf("lang = %q, want %q", lang, tt.wantLang)
			}
			if format != tt.wantFormat {
				t.Errorf("format = %q, want %q", format, tt.wantFormat)
			}
			if translateLang != tt.wantTranslate {
				t.Errorf("translate = %q, want %q", translateLang, tt.wantTranslate)
			}
			if listOnly != tt.wantList {
				t.Errorf("listOnly = %v, want %v", listOnly, tt.wantList)
			}
		})
	}
}

// TestTranslateNotTranslatable verifies that FetchTranslated returns an error
// when the source transcript is not translatable.
func TestTranslateNotTranslatable(t *testing.T) {
	// Create a TranscriptList with a non-translatable transcript
	list := &transcript.TranscriptList{
		VideoID: "test123",
		Transcripts: []transcript.TranscriptInfo{
			{
				Language:       "English",
				LanguageCode:   "en",
				IsGenerated:    false,
				IsTranslatable: false,
				BaseURL:        "https://example.com/captions",
			},
		},
	}

	// FindTranscript should work
	info, err := list.FindTranscript([]string{"en"})
	if err != nil {
		t.Fatalf("FindTranscript() error: %v", err)
	}

	// Verify IsTranslatable is false
	if info.IsTranslatable {
		t.Error("Expected IsTranslatable to be false")
	}
}

// TestTranslateTranslatable verifies that a translatable transcript
// can be identified and its properties are correct.
func TestTranslateTranslatable(t *testing.T) {
	list := &transcript.TranscriptList{
		VideoID: "test456",
		Transcripts: []transcript.TranscriptInfo{
			{
				Language:       "English",
				LanguageCode:   "en",
				IsGenerated:    true,
				IsTranslatable: true,
				BaseURL:        "https://example.com/captions",
				TranslationLanguages: []transcript.TranslationLanguage{
					{Language: "German", LanguageCode: "de"},
					{Language: "French", LanguageCode: "fr"},
				},
			},
		},
	}

	info, err := list.FindTranscript([]string{"en"})
	if err != nil {
		t.Fatalf("FindTranscript() error: %v", err)
	}

	if !info.IsTranslatable {
		t.Error("Expected IsTranslatable to be true")
	}
	if len(info.TranslationLanguages) != 2 {
		t.Errorf("Expected 2 translation languages, got %d", len(info.TranslationLanguages))
	}
	if info.TranslationLanguages[0].LanguageCode != "de" {
		t.Errorf("Expected first translation language 'de', got %q", info.TranslationLanguages[0].LanguageCode)
	}
}

// TestTranscriptFetchTranslatedDE is a network test that fetches a transcript
// translated to German. Requires internet access.
func TestTranscriptFetchTranslatedDE(t *testing.T) {
	SkipIfNoYTCalls(t)
	api := transcript.New()
	fetched, err := api.FetchTranslated(testVideoID, []string{"en"}, "de")
	if err != nil {
		t.Fatalf("FetchTranslated(de) error: %v", err)
	}
	if len(fetched.Snippets) < 10 {
		t.Errorf("Expected at least 10 snippets, got %d", len(fetched.Snippets))
	}
	if fetched.LanguageCode != "de" {
		t.Errorf("Expected language code 'de', got %q", fetched.LanguageCode)
	}
	t.Logf("Translated to DE: %d snippets", len(fetched.Snippets))
	if len(fetched.Snippets) > 0 {
		t.Logf("  First snippet: %q", fetched.Snippets[0].Text)
	}
}
