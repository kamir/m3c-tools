package pocket

import (
	"encoding/json"
	"testing"
)

// SPEC-0176 §3.4: pin the schema helpers in pkg/pocket/types.go.

func TestAPIRecording_IsCompleted(t *testing.T) {
	cases := []struct {
		state string
		want  bool
	}{
		{"completed", true},
		{"pending", false},
		{"", false},
		{"COMPLETED", false}, // case-sensitive — Pocket uses lowercase
		{"failed", false},
	}
	for _, tc := range cases {
		r := APIRecording{State: tc.state}
		if got := r.IsCompleted(); got != tc.want {
			t.Errorf("State=%q IsCompleted() = %v, want %v", tc.state, got, tc.want)
		}
	}
}

func TestAPIRecording_DedupKey(t *testing.T) {
	r := APIRecording{ID: "9bbc770f-f269-4054-a1d2-4d7770fb4089"}
	if got := r.DedupKey(); got != "pocket://9bbc770f-f269-4054-a1d2-4d7770fb4089" {
		t.Errorf("DedupKey = %q, want 'pocket://9bbc770f-...'", got)
	}
	empty := APIRecording{}
	if got := empty.DedupKey(); got != "pocket://" {
		t.Errorf("empty DedupKey = %q, want 'pocket://'", got)
	}
}

func TestAPIRecording_LanguageOrEmpty(t *testing.T) {
	de := "de"
	cases := []struct {
		lang *string
		want string
	}{
		{nil, ""},
		{&de, "de"},
	}
	for _, tc := range cases {
		r := APIRecording{Language: tc.lang}
		if got := r.LanguageOrEmpty(); got != tc.want {
			t.Errorf("Language=%v LanguageOrEmpty = %q, want %q", tc.lang, got, tc.want)
		}
	}
}

func TestAPIRecording_SummaryMarkdown(t *testing.T) {
	t.Run("empty when no summarizations", func(t *testing.T) {
		r := APIRecording{}
		if got := r.SummaryMarkdown(); got != "" {
			t.Errorf("empty recording SummaryMarkdown = %q, want empty", got)
		}
	})

	t.Run("returns the first non-empty markdown", func(t *testing.T) {
		s1 := Summarization{}
		s2 := Summarization{}
		s2.V2.Summary.Markdown = "## the good summary"
		r := APIRecording{
			Summarizations: map[string]Summarization{"u1": s1, "u2": s2},
		}
		got := r.SummaryMarkdown()
		if got != "## the good summary" {
			t.Errorf("SummaryMarkdown = %q, want '## the good summary'", got)
		}
	})

	t.Run("empty when all summarizations are blank", func(t *testing.T) {
		r := APIRecording{
			Summarizations: map[string]Summarization{
				"u1": {}, "u2": {},
			},
		}
		if got := r.SummaryMarkdown(); got != "" {
			t.Errorf("SummaryMarkdown = %q, want empty", got)
		}
	})
}

func TestAPIRecording_JSONRoundTrip(t *testing.T) {
	// Real-shape JSON from the api-probe — verifies our types decode cleanly.
	raw := `{
		"id": "ac4e7b92-40ca-46c0-bafe-e70111c3dbd0",
		"title": "Cuffscale Smoke Test und Blueprints",
		"duration": 301,
		"state": "completed",
		"language": "en",
		"recording_at": "2026-04-17T06:14:25Z",
		"created_at":   "2026-04-17T12:40:52Z",
		"updated_at":   "2026-04-17T12:41:45Z",
		"tags": [],
		"transcript": {
			"metadata": {"language": "en"},
			"segments": [{"start": 0, "end": 5, "text": "hello"}],
			"text": "hello world"
		},
		"summarizations": {
			"u1": {
				"id": "u1",
				"processingStatus": "completed",
				"v2": {
					"summary": {"markdown": "# done", "title": "x", "summary": "y"},
					"actionItems": {"actions": [], "version": "3"}
				}
			}
		}
	}`
	var r APIRecording
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if r.ID != "ac4e7b92-40ca-46c0-bafe-e70111c3dbd0" {
		t.Errorf("ID = %q", r.ID)
	}
	if !r.IsCompleted() {
		t.Error("IsCompleted() should be true")
	}
	if r.LanguageOrEmpty() != "en" {
		t.Errorf("LanguageOrEmpty = %q", r.LanguageOrEmpty())
	}
	if r.Transcript.Text != "hello world" {
		t.Errorf("Transcript.Text = %q", r.Transcript.Text)
	}
	if r.SummaryMarkdown() != "# done" {
		t.Errorf("SummaryMarkdown = %q", r.SummaryMarkdown())
	}
	if r.DedupKey() != "pocket://ac4e7b92-40ca-46c0-bafe-e70111c3dbd0" {
		t.Errorf("DedupKey = %q", r.DedupKey())
	}
}

func TestEnvelope_DecodesPagination(t *testing.T) {
	raw := `{"success":true,"data":[],"pagination":{"page":1,"limit":20,"total":26,"total_pages":2,"has_more":true}}`
	var env Envelope
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !env.Success {
		t.Error("Success should be true")
	}
	if env.Pagination == nil {
		t.Fatal("Pagination should not be nil")
	}
	if env.Pagination.Total != 26 || !env.Pagination.HasMore {
		t.Errorf("pagination shape wrong: %+v", env.Pagination)
	}
}
