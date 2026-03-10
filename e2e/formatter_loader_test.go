// Unit tests for FormatterLoader and PrettyPrintFormatter.
// No network or hardware required.
//
// Run: go test -v -count=1 ./e2e/ -run TestFormatterLoader
package e2e

import (
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/transcript"
)

// sample returns a minimal FetchedTranscript for formatter tests.
func sampleTranscript() *transcript.FetchedTranscript {
	return &transcript.FetchedTranscript{
		VideoID:      "test123",
		Language:     "English",
		LanguageCode: "en",
		Snippets: []transcript.Snippet{
			{Text: "Hello world", Start: 0.0, Duration: 2.5},
			{Text: "Second line", Start: 2.5, Duration: 3.0},
			{Text: "After an hour", Start: 3661.0, Duration: 1.0},
		},
	}
}

func TestFormatterLoaderBuiltins(t *testing.T) {
	fl := transcript.NewFormatterLoader()
	names := fl.Names()
	expected := []string{"json", "json-pretty", "pretty", "srt", "text", "webvtt"}
	if len(names) != len(expected) {
		t.Fatalf("expected %d formatters, got %d: %v", len(expected), len(names), names)
	}
	for i, name := range expected {
		if names[i] != name {
			t.Errorf("names[%d] = %q, want %q", i, names[i], name)
		}
	}
}

func TestFormatterLoaderGet(t *testing.T) {
	fl := transcript.NewFormatterLoader()
	ft := sampleTranscript()

	tests := []struct {
		name    string
		check   func(string) bool
		desc    string
	}{
		{"text", func(s string) bool { return strings.Contains(s, "Hello world") && !strings.Contains(s, "[") }, "text has content without brackets"},
		{"json", func(s string) bool { return strings.HasPrefix(s, "[{") }, "json starts with [{"},
		{"json-pretty", func(s string) bool { return strings.Contains(s, "  ") && strings.Contains(s, `"text"`) }, "json-pretty is indented"},
		{"srt", func(s string) bool { return strings.Contains(s, "-->") }, "srt has --> separator"},
		{"webvtt", func(s string) bool { return strings.HasPrefix(s, "WEBVTT") }, "webvtt has header"},
		{"pretty", func(s string) bool { return strings.Contains(s, "00:00") && strings.Contains(s, "│") && strings.Contains(s, "Hello world") }, "pretty has timestamp and box-drawing separator"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, err := fl.Get(tc.name)
			if err != nil {
				t.Fatalf("Get(%q) error: %v", tc.name, err)
			}
			out := f.FormatTranscript(ft)
			if !tc.check(out) {
				t.Errorf("%s failed: %s\nOutput:\n%s", tc.name, tc.desc, out)
			}
		})
	}
}

func TestFormatterLoaderDefault(t *testing.T) {
	fl := transcript.NewFormatterLoader()
	f, err := fl.Get("")
	if err != nil {
		t.Fatalf("Get(\"\") should return default, got error: %v", err)
	}
	out := f.FormatTranscript(sampleTranscript())
	if !strings.Contains(out, "00:00") || !strings.Contains(out, "│") {
		t.Errorf("default formatter should be PrettyPrint with timestamps, got: %s", out)
	}
}

func TestFormatterLoaderUnknown(t *testing.T) {
	fl := transcript.NewFormatterLoader()
	_, err := fl.Get("nonexistent")
	if err == nil {
		t.Error("Get(\"nonexistent\") should return error")
	}
	if !strings.Contains(err.Error(), "unknown formatter") {
		t.Errorf("error should mention 'unknown formatter', got: %v", err)
	}
}

func TestFormatterLoaderRegisterCustom(t *testing.T) {
	fl := transcript.NewFormatterLoader()
	fl.Register("custom", transcript.TextFormatter{})
	f, err := fl.Get("custom")
	if err != nil {
		t.Fatalf("Get(\"custom\") error: %v", err)
	}
	out := f.FormatTranscript(sampleTranscript())
	if !strings.Contains(out, "Hello world") {
		t.Errorf("custom formatter output missing expected text: %s", out)
	}
}

func TestPrettyPrintFormatterHourTimestamp(t *testing.T) {
	ft := sampleTranscript()
	f := *transcript.NewPrettyPrintFormatter()
	out := f.FormatTranscript(ft)
	// Third snippet is at 3661s = 1:01:01
	if !strings.Contains(out, "1:01:01") {
		t.Errorf("expected 1:01:01 for hour+ timestamp, got:\n%s", out)
	}
}
