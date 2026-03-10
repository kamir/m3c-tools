package e2e

import (
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/transcript"
)

func TestLanguageFlagMap(t *testing.T) {
	// Verify the map is populated with common languages
	required := []string{"en", "de", "fr", "es", "ja", "ko", "zh", "ru", "ar", "hi", "pt"}
	for _, code := range required {
		if _, ok := transcript.LanguageFlag[code]; !ok {
			t.Errorf("LanguageFlag missing required language code %q", code)
		}
	}
	t.Logf("LanguageFlag has %d entries", len(transcript.LanguageFlag))
}

func TestFlagForLanguageExact(t *testing.T) {
	tests := []struct {
		code string
		want string
	}{
		{"en", "🇬🇧"},
		{"en-US", "🇺🇸"},
		{"de", "🇩🇪"},
		{"ja", "🇯🇵"},
		{"zh-TW", "🇹🇼"},
		{"pt-BR", "🇧🇷"},
	}
	for _, tt := range tests {
		got := transcript.FlagForLanguage(tt.code)
		if got != tt.want {
			t.Errorf("FlagForLanguage(%q) = %q, want %q", tt.code, got, tt.want)
		}
	}
}

func TestFlagForLanguageFallback(t *testing.T) {
	// Unknown regional variant should fall back to base language
	flag := transcript.FlagForLanguage("fr-BE")
	if flag != "🇫🇷" {
		t.Errorf("FlagForLanguage(\"fr-BE\") = %q, want 🇫🇷 (French base)", flag)
	}
}

func TestFlagForLanguageUnknown(t *testing.T) {
	// Completely unknown code should return white flag
	flag := transcript.FlagForLanguage("xx")
	if flag != "🏳️" {
		t.Errorf("FlagForLanguage(\"xx\") = %q, want 🏳️ (white flag)", flag)
	}
}

func TestLanguageLabel(t *testing.T) {
	label := transcript.LanguageLabel("English", "en")
	if !strings.Contains(label, "🇬🇧") {
		t.Error("LanguageLabel missing flag emoji")
	}
	if !strings.Contains(label, "English") {
		t.Error("LanguageLabel missing language name")
	}
	if !strings.Contains(label, "(en)") {
		t.Error("LanguageLabel missing language code")
	}
	t.Logf("Label: %s", label)
}

func TestLanguageLabelRegional(t *testing.T) {
	label := transcript.LanguageLabel("Portuguese (Brazil)", "pt-BR")
	if !strings.Contains(label, "🇧🇷") {
		t.Error("LanguageLabel missing Brazilian flag")
	}
	t.Logf("Label: %s", label)
}

func TestLanguageFlagValues(t *testing.T) {
	// Every flag value should be non-empty
	for code, flag := range transcript.LanguageFlag {
		if len(flag) == 0 {
			t.Errorf("LanguageFlag[%q] is empty", code)
		}
	}
}
