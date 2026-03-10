package e2e

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/tracking"
)

func TestRetryQueueInsertAndQuery(t *testing.T) {
	db, err := tracking.OpenRetryQueueDB(filepath.Join(t.TempDir(), "retry.db"))
	if err != nil {
		t.Fatalf("OpenRetryQueueDB: %v", err)
	}
	defer db.Close()

	// Insert an entry.
	entry, err := db.Insert("upload-001", "/tmp/transcript.txt", "/tmp/audio.wav", "/tmp/image.png", "youtube,music", 5)
	if err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if entry.EntryID != "upload-001" {
		t.Errorf("EntryID = %q, want upload-001", entry.EntryID)
	}
	if entry.Status != tracking.RetryStatusPending {
		t.Errorf("Status = %q, want pending", entry.Status)
	}
	if entry.Attempts != 0 {
		t.Errorf("Attempts = %d, want 0", entry.Attempts)
	}
	if entry.MaxAttempts != 5 {
		t.Errorf("MaxAttempts = %d, want 5", entry.MaxAttempts)
	}
	if entry.TranscriptPath != "/tmp/transcript.txt" {
		t.Errorf("TranscriptPath = %q, want /tmp/transcript.txt", entry.TranscriptPath)
	}

	// Query pending — should return the entry (next_retry_at is now).
	pending, err := db.QueryPending(10)
	if err != nil {
		t.Fatalf("QueryPending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("Expected 1 pending entry, got %d", len(pending))
	}
	if pending[0].EntryID != "upload-001" {
		t.Errorf("Pending EntryID = %q, want upload-001", pending[0].EntryID)
	}

	// Query by entry_id.
	got, err := db.GetByEntryID("upload-001")
	if err != nil {
		t.Fatalf("GetByEntryID: %v", err)
	}
	if got == nil {
		t.Fatal("GetByEntryID returned nil")
	}
	if got.Tags != "youtube,music" {
		t.Errorf("Tags = %q, want youtube,music", got.Tags)
	}

	// Query non-existent.
	missing, err := db.GetByEntryID("nonexistent")
	if err != nil {
		t.Fatalf("GetByEntryID for missing: %v", err)
	}
	if missing != nil {
		t.Error("Expected nil for non-existent entry_id")
	}
}

func TestRetryQueueUpdateAttempt(t *testing.T) {
	db, err := tracking.OpenRetryQueueDB(
		filepath.Join(t.TempDir(), "retry.db"),
		tracking.WithBaseDelay(1*time.Second),
		tracking.WithMaxDelay(30*time.Second),
		tracking.WithBackoffScale(2.0),
	)
	if err != nil {
		t.Fatalf("OpenRetryQueueDB: %v", err)
	}
	defer db.Close()

	_, err = db.Insert("upload-002", "/tmp/t.txt", "", "", "test", 3)
	if err != nil {
		t.Fatalf("Insert: %v", err)
	}

	// First retry attempt.
	entry, err := db.UpdateAttempt("upload-002", errors.New("connection refused"))
	if err != nil {
		t.Fatalf("UpdateAttempt 1: %v", err)
	}
	if entry.Attempts != 1 {
		t.Errorf("Attempts = %d, want 1", entry.Attempts)
	}
	if entry.Status != tracking.RetryStatusRetrying {
		t.Errorf("Status = %q, want retrying", entry.Status)
	}
	if entry.LastError != "connection refused" {
		t.Errorf("LastError = %q, want 'connection refused'", entry.LastError)
	}
	// next_retry_at should be in the future.
	if !entry.NextRetryAt.After(entry.UpdatedAt.Add(-1 * time.Second)) {
		t.Error("NextRetryAt should be after UpdatedAt")
	}

	// Second retry attempt.
	entry, err = db.UpdateAttempt("upload-002", errors.New("timeout"))
	if err != nil {
		t.Fatalf("UpdateAttempt 2: %v", err)
	}
	if entry.Attempts != 2 {
		t.Errorf("Attempts = %d, want 2", entry.Attempts)
	}
	if entry.Status != tracking.RetryStatusRetrying {
		t.Errorf("Status = %q, want retrying", entry.Status)
	}

	// Third attempt — should exceed max_attempts (3) and become failed.
	entry, err = db.UpdateAttempt("upload-002", errors.New("still broken"))
	if err != nil {
		t.Fatalf("UpdateAttempt 3: %v", err)
	}
	if entry.Attempts != 3 {
		t.Errorf("Attempts = %d, want 3", entry.Attempts)
	}
	if entry.Status != tracking.RetryStatusFailed {
		t.Errorf("Status = %q, want failed", entry.Status)
	}

	// Should no longer appear in pending.
	pending, err := db.QueryPending(10)
	if err != nil {
		t.Fatalf("QueryPending: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("Expected 0 pending entries after max attempts, got %d", len(pending))
	}
}

func TestRetryQueueMarkComplete(t *testing.T) {
	db, err := tracking.OpenRetryQueueDB(filepath.Join(t.TempDir(), "retry.db"))
	if err != nil {
		t.Fatalf("OpenRetryQueueDB: %v", err)
	}
	defer db.Close()

	db.Insert("upload-003", "/tmp/t.txt", "", "", "", 0)

	err = db.MarkComplete("upload-003")
	if err != nil {
		t.Fatalf("MarkComplete: %v", err)
	}

	entry, err := db.GetByEntryID("upload-003")
	if err != nil {
		t.Fatal(err)
	}
	if entry.Status != tracking.RetryStatusCompleted {
		t.Errorf("Status = %q, want completed", entry.Status)
	}

	// Should not appear in pending.
	pending, err := db.QueryPending(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Errorf("Expected 0 pending after completion, got %d", len(pending))
	}

	// Mark non-existent should error.
	err = db.MarkComplete("nonexistent")
	if err == nil {
		t.Error("Expected error for non-existent entry_id")
	}
}

func TestRetryQueueBackoffCalculation(t *testing.T) {
	db, err := tracking.OpenRetryQueueDB(
		filepath.Join(t.TempDir(), "retry.db"),
		tracking.WithBaseDelay(10*time.Second),
		tracking.WithMaxDelay(5*time.Minute),
		tracking.WithBackoffScale(2.0),
	)
	if err != nil {
		t.Fatalf("OpenRetryQueueDB: %v", err)
	}
	defer db.Close()

	tests := []struct {
		attempt  int
		expected time.Duration
	}{
		{0, 10 * time.Second},  // 10 * 2^0 = 10s
		{1, 20 * time.Second},  // 10 * 2^1 = 20s
		{2, 40 * time.Second},  // 10 * 2^2 = 40s
		{3, 80 * time.Second},  // 10 * 2^3 = 80s
		{4, 160 * time.Second}, // 10 * 2^4 = 160s
		{5, 5 * time.Minute},   // 10 * 2^5 = 320s, capped at 300s
		{10, 5 * time.Minute},  // capped at max
		{-1, 10 * time.Second}, // negative treated as 0
	}

	for _, tt := range tests {
		got := db.CalculateBackoff(tt.attempt)
		if got != tt.expected {
			t.Errorf("CalculateBackoff(%d) = %v, want %v", tt.attempt, got, tt.expected)
		}
	}
}

func TestRetryQueueCountByStatus(t *testing.T) {
	db, err := tracking.OpenRetryQueueDB(filepath.Join(t.TempDir(), "retry.db"))
	if err != nil {
		t.Fatalf("OpenRetryQueueDB: %v", err)
	}
	defer db.Close()

	db.Insert("e1", "/tmp/t1.txt", "", "", "", 10)
	db.Insert("e2", "/tmp/t2.txt", "", "", "", 10)
	db.Insert("e3", "/tmp/t3.txt", "", "", "", 10)
	db.MarkComplete("e2")

	pending, err := db.CountByStatus(tracking.RetryStatusPending)
	if err != nil {
		t.Fatal(err)
	}
	if pending != 2 {
		t.Errorf("pending count = %d, want 2", pending)
	}

	completed, err := db.CountByStatus(tracking.RetryStatusCompleted)
	if err != nil {
		t.Fatal(err)
	}
	if completed != 1 {
		t.Errorf("completed count = %d, want 1", completed)
	}
}

func TestRetryQueueRemoveCompleted(t *testing.T) {
	db, err := tracking.OpenRetryQueueDB(filepath.Join(t.TempDir(), "retry.db"))
	if err != nil {
		t.Fatalf("OpenRetryQueueDB: %v", err)
	}
	defer db.Close()

	db.Insert("e1", "/tmp/t1.txt", "", "", "", 10)
	db.Insert("e2", "/tmp/t2.txt", "", "", "", 10)
	db.MarkComplete("e1")
	db.MarkComplete("e2")
	db.Insert("e3", "/tmp/t3.txt", "", "", "", 10) // still pending

	removed, err := db.RemoveCompleted()
	if err != nil {
		t.Fatalf("RemoveCompleted: %v", err)
	}
	if removed != 2 {
		t.Errorf("removed = %d, want 2", removed)
	}

	all, err := db.ListAll(100)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Errorf("Expected 1 remaining entry, got %d", len(all))
	}
	if all[0].EntryID != "e3" {
		t.Errorf("Remaining entry = %q, want e3", all[0].EntryID)
	}
}

func TestRetryQueueDuplicateEntryID(t *testing.T) {
	db, err := tracking.OpenRetryQueueDB(filepath.Join(t.TempDir(), "retry.db"))
	if err != nil {
		t.Fatalf("OpenRetryQueueDB: %v", err)
	}
	defer db.Close()

	_, err = db.Insert("dup-001", "/tmp/t.txt", "", "", "", 10)
	if err != nil {
		t.Fatalf("First insert: %v", err)
	}

	// Duplicate entry_id should fail due to UNIQUE constraint.
	_, err = db.Insert("dup-001", "/tmp/t2.txt", "", "", "", 10)
	if err == nil {
		t.Error("Expected error for duplicate entry_id")
	}
}

func TestRetryQueueListAll(t *testing.T) {
	db, err := tracking.OpenRetryQueueDB(filepath.Join(t.TempDir(), "retry.db"))
	if err != nil {
		t.Fatalf("OpenRetryQueueDB: %v", err)
	}
	defer db.Close()

	db.Insert("a1", "/tmp/t1.txt", "/tmp/a1.wav", "/tmp/i1.png", "tag1", 10)
	db.Insert("a2", "/tmp/t2.txt", "", "", "tag2", 10)

	all, err := db.ListAll(100)
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("Expected 2 entries, got %d", len(all))
	}
}
