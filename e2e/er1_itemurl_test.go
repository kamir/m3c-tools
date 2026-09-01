// Offline test for er1.Config.MemoryItemURL — the recording→ER1 item URL used
// by `plaud list` / `plaud check` and the Plaud sync panel's click-to-open.
package e2e

import (
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/er1"
)

func TestMemoryItemURL(t *testing.T) {
	tests := []struct {
		name    string
		apiURL  string
		ctx     string
		docID   string
		want    string
	}{
		{"upload_2 suffix stripped", "https://onboarding.guide/upload_2", "107677460544181387647___mft", "hzrCsrM0BGAThZ6lGd6y",
			"https://onboarding.guide/memory/107677460544181387647___mft/hzrCsrM0BGAThZ6lGd6y"},
		{"upload suffix stripped", "https://onboarding.guide/upload", "ctx", "d1",
			"https://onboarding.guide/memory/ctx/d1"},
		{"trailing slash stripped", "https://127.0.0.1:8081/", "ctx", "d1",
			"https://127.0.0.1:8081/memory/ctx/d1"},
		{"empty doc_id yields empty url", "https://onboarding.guide/upload_2", "ctx", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &er1.Config{APIURL: tt.apiURL, ContextID: tt.ctx}
			if got := cfg.MemoryItemURL(tt.docID); got != tt.want {
				t.Errorf("MemoryItemURL(%q) = %q; want %q", tt.docID, got, tt.want)
			}
		})
	}
}

func TestFormatCaptureTime(t *testing.T) {
	if got := er1.FormatCaptureTime(time.Time{}); got != "" {
		t.Errorf("zero time should format to empty, got %q", got)
	}
	ts := time.Date(2026, 5, 19, 14, 3, 49, 0, time.UTC)
	if got, want := er1.FormatCaptureTime(ts), "2026-05-19 14:03:49"; got != want {
		t.Errorf("FormatCaptureTime = %q; want %q", got, want)
	}
}
