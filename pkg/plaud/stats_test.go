package plaud

import (
	"fmt"
	"strings"
	"testing"
)

func TestNewSyncStats(t *testing.T) {
	stats := NewSyncStats()
	if stats == nil {
		t.Fatal("NewSyncStats returned nil")
	}
	if stats.UploadErrors == nil {
		t.Error("UploadErrors map not initialized")
	}
	if stats.LocalTotal != 0 || stats.UploadedNew != 0 || stats.UploadFailed != 0 {
		t.Error("expected all counters to be zero")
	}
}

func TestRecordUploadError(t *testing.T) {
	stats := NewSyncStats()
	stats.RecordUploadError(fmt.Errorf("connection refused"))
	stats.RecordUploadError(fmt.Errorf("request timeout"))
	stats.RecordUploadError(fmt.Errorf("connection refused again"))

	if stats.UploadFailed != 3 {
		t.Errorf("UploadFailed = %d, want 3", stats.UploadFailed)
	}
	if stats.UploadErrors["connection"] != 2 {
		t.Errorf("connection errors = %d, want 2", stats.UploadErrors["connection"])
	}
	if stats.UploadErrors["timeout"] != 1 {
		t.Errorf("timeout errors = %d, want 1", stats.UploadErrors["timeout"])
	}
}

func TestTotalProcessed(t *testing.T) {
	stats := NewSyncStats()
	stats.UploadedNew = 5
	stats.UploadFailed = 2
	stats.SavedLocally = 1

	if got := stats.TotalProcessed(); got != 8 {
		t.Errorf("TotalProcessed() = %d, want 8", got)
	}
}

func TestTotalSkipped(t *testing.T) {
	stats := NewSyncStats()
	stats.LocalExisting = 90
	stats.AlreadyInER1 = 3

	if got := stats.TotalSkipped(); got != 93 {
		t.Errorf("TotalSkipped() = %d, want 93", got)
	}
}

func TestFormatSummary(t *testing.T) {
	stats := NewSyncStats()
	stats.LocalTotal = 99
	stats.LocalExisting = 92
	stats.LocalNew = 7
	stats.AlreadyInER1 = 0
	stats.UploadedNew = 7
	stats.UploadFailed = 0

	summary := stats.FormatSummary()

	// Check key lines are present.
	if !strings.Contains(summary, "Total recordings:") {
		t.Error("summary missing 'Total recordings'")
	}
	if !strings.Contains(summary, "99") {
		t.Error("summary missing total count 99")
	}
	if !strings.Contains(summary, "Already local:") {
		t.Error("summary missing 'Already local'")
	}
	if !strings.Contains(summary, "92") {
		t.Error("summary missing local existing count 92")
	}
	if !strings.Contains(summary, "Uploaded (new):") {
		t.Error("summary missing 'Uploaded (new)'")
	}
	if !strings.Contains(summary, "Upload failed:") {
		t.Error("summary missing 'Upload failed'")
	}
	// AlreadyInER1 is 0, so that line should NOT appear.
	if strings.Contains(summary, "Already in ER1:") {
		t.Error("summary should not show 'Already in ER1' when count is 0")
	}
}

func TestFormatSummaryWithER1Dedup(t *testing.T) {
	stats := NewSyncStats()
	stats.LocalTotal = 50
	stats.LocalExisting = 40
	stats.LocalNew = 10
	stats.AlreadyInER1 = 5
	stats.UploadedNew = 4
	stats.UploadFailed = 1
	stats.RecordUploadError(fmt.Errorf("HTTP 401 Unauthorized"))

	summary := stats.FormatSummary()

	if !strings.Contains(summary, "Already in ER1:") {
		t.Error("summary should show 'Already in ER1' when count > 0")
	}
	if !strings.Contains(summary, "auth: 1") {
		t.Error("summary should show error category breakdown")
	}
}

func TestFormatNotification_AllSynced(t *testing.T) {
	stats := NewSyncStats()
	stats.LocalTotal = 50
	stats.LocalExisting = 50

	got := stats.FormatNotification()
	if !strings.Contains(got, "already synced") {
		t.Errorf("notification = %q, want 'already synced' message", got)
	}
}

func TestFormatNotification_NewUploads(t *testing.T) {
	stats := NewSyncStats()
	stats.LocalTotal = 50
	stats.UploadedNew = 5

	got := stats.FormatNotification()
	if !strings.Contains(got, "5 new") {
		t.Errorf("notification = %q, want '5 new' in message", got)
	}
}

func TestFormatNotification_WithFailures(t *testing.T) {
	stats := NewSyncStats()
	stats.LocalTotal = 50
	stats.UploadedNew = 3
	stats.UploadFailed = 2

	got := stats.FormatNotification()
	if !strings.Contains(got, "3 new") || !strings.Contains(got, "2 failed") {
		t.Errorf("notification = %q, want both 'new' and 'failed' counts", got)
	}
}

func TestCategorizeError(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{fmt.Errorf("CSRF session expired"), "csrf"},
		{fmt.Errorf("HTTP 401 Unauthorized"), "auth"},
		{fmt.Errorf("HTTP 403 Forbidden"), "forbidden"},
		{fmt.Errorf("request timeout"), "timeout"},
		{fmt.Errorf("connection refused"), "connection"},
		{fmt.Errorf("ER1_API_KEY is not set"), "missing-key"},
		{fmt.Errorf("HTTP 413 payload too large"), "too-large"},
		{fmt.Errorf("some random error"), "other"},
		{nil, "unknown"},
	}

	for _, tc := range tests {
		got := categorizeError(tc.err)
		if got != tc.want {
			t.Errorf("categorizeError(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}
