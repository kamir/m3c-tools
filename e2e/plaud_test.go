package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/impression"
	"github.com/kamir/m3c-tools/pkg/plaud"
)

func TestFieldnoteCompositeDoc(t *testing.T) {
	doc := &impression.CompositeDoc{
		ObsType:           impression.Fieldnote,
		RecordingTitle:    "Customer visit Acme Corp",
		RecordingDuration: "12m30s",
		TranscriptText:    "Hello, this is a field recording from the customer visit.",
	}
	result := doc.Build()

	checks := []string{
		"=== PLAUD FIELDNOTE ===",
		"Recording: Customer visit Acme Corp",
		"Duration: 12m30s",
		"Hello, this is a field recording",
		"=== END FIELDNOTE ===",
	}
	for _, want := range checks {
		if !strings.Contains(result, want) {
			t.Errorf("Build() missing %q in output:\n%s", want, result)
		}
	}
}

func TestFieldnoteCompositeDocWithNotes(t *testing.T) {
	doc := &impression.CompositeDoc{
		ObsType:           impression.Fieldnote,
		RecordingTitle:    "Sales call",
		RecordingDuration: "5m00s",
		TranscriptText:    "Transcript text here.",
		ImpressionText:    "Follow up on pricing.",
	}
	result := doc.Build()

	checks := []string{
		"=== PLAUD FIELDNOTE ===",
		"Recording: Sales call",
		"=== USER NOTES ===",
		"Follow up on pricing.",
		"=== END FIELDNOTE ===",
	}
	for _, want := range checks {
		if !strings.Contains(result, want) {
			t.Errorf("Build() missing %q in output:\n%s", want, result)
		}
	}
}

func TestFieldnoteTags(t *testing.T) {
	tags := impression.BuildTags(impression.Fieldnote)
	parts := impression.ParseTagLine(tags)

	if len(parts) != 2 {
		t.Fatalf("expected 2 tags, got %d: %v", len(parts), parts)
	}
	if parts[0] != "plaud" {
		t.Errorf("tag[0] = %q, want %q", parts[0], "plaud")
	}
	if parts[1] != "fieldnote" {
		t.Errorf("tag[1] = %q, want %q", parts[1], "fieldnote")
	}
}

func TestBuildFieldnoteTags(t *testing.T) {
	tags := impression.BuildFieldnoteTags("My Recording", "extra-tag")
	parts := impression.ParseTagLine(tags)

	expected := []string{"plaud", "fieldnote", "recording:My Recording", "extra-tag"}
	if len(parts) != len(expected) {
		t.Fatalf("expected %d tags, got %d: %v", len(expected), len(parts), parts)
	}
	for i, want := range expected {
		if parts[i] != want {
			t.Errorf("tag[%d] = %q, want %q", i, parts[i], want)
		}
	}
}

func TestPlaudConfigDefaults(t *testing.T) {
	// Ensure no env vars override defaults.
	os.Unsetenv("PLAUD_API_URL")
	os.Unsetenv("PLAUD_TOKEN_FILE")
	os.Unsetenv("PLAUD_CONTENT_TYPE")

	cfg := plaud.LoadConfig()

	if cfg.APIURL != "https://api.plaud.ai" {
		t.Errorf("APIURL = %q, want default", cfg.APIURL)
	}
	if !strings.Contains(cfg.TokenPath, "plaud-session.json") {
		t.Errorf("TokenPath = %q, want to contain plaud-session.json", cfg.TokenPath)
	}
	if cfg.ContentType != "Plaud-Fieldnote" {
		t.Errorf("ContentType = %q, want Plaud-Fieldnote", cfg.ContentType)
	}
}

func TestPlaudTokenRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "test-token.json")

	// Save.
	session := &plaud.TokenSession{Token: "test-bearer-token-123"}
	if err := plaud.SaveToken(tokenPath, session); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	// Verify file permissions.
	info, err := os.Stat(tokenPath)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("file perm = %o, want 0600", perm)
	}

	// Load.
	loaded, err := plaud.LoadToken(tokenPath)
	if err != nil {
		t.Fatalf("LoadToken: %v", err)
	}
	if loaded.Token != "test-bearer-token-123" {
		t.Errorf("Token = %q, want test-bearer-token-123", loaded.Token)
	}
	if loaded.SavedAt.IsZero() {
		t.Error("SavedAt should not be zero")
	}
}

func TestPlaudFormatDuration(t *testing.T) {
	tests := []struct {
		seconds int
		want    string
	}{
		{0, "0s"},
		{30, "30s"},
		{60, "1m00s"},
		{90, "1m30s"},
		{3661, "61m01s"},
	}
	for _, tc := range tests {
		got := plaud.FormatDuration(tc.seconds)
		if got != tc.want {
			t.Errorf("FormatDuration(%d) = %q, want %q", tc.seconds, got, tc.want)
		}
	}
}
