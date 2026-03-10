package e2e

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/er1"
)

// TestRetryRunnerProcessOnce tests that ProcessOnce dispatches entries,
// removes successes, increments retry counts on failure, and drops
// entries exceeding MaxRetries.
func TestRetryRunnerProcessOnce(t *testing.T) {
	tmpPath := t.TempDir() + "/retry-test-queue.json"
	q := er1.NewQueue(tmpPath)

	// Seed 3 entries
	q.Add(er1.QueueEntry{ID: "ok-1", Tags: "test"})
	q.Add(er1.QueueEntry{ID: "fail-1", Tags: "test"})
	q.Add(er1.QueueEntry{ID: "ok-2", Tags: "test"})

	// Upload function: "ok-*" succeeds, "fail-*" fails
	uploadFn := func(entry er1.QueueEntry) error {
		if entry.ID == "fail-1" {
			return fmt.Errorf("simulated upload error")
		}
		return nil
	}

	runner := er1.NewRetryRunner(q, uploadFn, 5)

	ctx := context.Background()
	successes, failures, dropped := runner.ProcessOnce(ctx)

	if successes != 2 {
		t.Errorf("Expected 2 successes, got %d", successes)
	}
	if failures != 1 {
		t.Errorf("Expected 1 failure, got %d", failures)
	}
	if dropped != 0 {
		t.Errorf("Expected 0 dropped, got %d", dropped)
	}

	// Queue should now contain only the failed entry
	if q.Len() != 1 {
		t.Fatalf("Expected 1 entry in queue, got %d", q.Len())
	}
	entries := q.Entries()
	if entries[0].ID != "fail-1" {
		t.Errorf("Expected fail-1 to remain, got %s", entries[0].ID)
	}
	if entries[0].RetryCount != 1 {
		t.Errorf("Expected retry count 1, got %d", entries[0].RetryCount)
	}
	if entries[0].LastError != "simulated upload error" {
		t.Errorf("Expected error message, got %q", entries[0].LastError)
	}
	t.Logf("ProcessOnce: %d successes, %d failures, %d dropped", successes, failures, dropped)
}

// TestRetryRunnerDropExceedMaxRetries verifies that entries exceeding
// MaxRetries are dropped from the queue.
func TestRetryRunnerDropExceedMaxRetries(t *testing.T) {
	tmpPath := t.TempDir() + "/retry-drop-queue.json"
	q := er1.NewQueue(tmpPath)

	// Add entry with retry count already at the limit
	q.Add(er1.QueueEntry{ID: "expired-1", Tags: "test", RetryCount: 3})

	alwaysFail := func(entry er1.QueueEntry) error {
		return fmt.Errorf("should not be called")
	}

	var droppedID string
	runner := er1.NewRetryRunner(q, alwaysFail, 3)
	runner.OnRetry = func(entry er1.QueueEntry, err error, removed bool) {
		if removed && err != nil {
			droppedID = entry.ID
		}
	}

	ctx := context.Background()
	_, _, dropped := runner.ProcessOnce(ctx)

	if dropped != 1 {
		t.Errorf("Expected 1 dropped, got %d", dropped)
	}
	if droppedID != "expired-1" {
		t.Errorf("Expected dropped ID expired-1, got %q", droppedID)
	}
	if q.Len() != 0 {
		t.Errorf("Expected empty queue after drop, got %d", q.Len())
	}
	t.Log("Entries exceeding MaxRetries are correctly dropped")
}

// TestRetryRunnerBackoff verifies that exponential backoff delays are calculated correctly.
func TestRetryRunnerBackoff(t *testing.T) {
	backoff := er1.DefaultBackoff(5*time.Second, 5*time.Minute)

	tests := []struct {
		attempt  int
		expected time.Duration
	}{
		{0, 5 * time.Second},
		{1, 10 * time.Second},
		{2, 20 * time.Second},
		{3, 40 * time.Second},
		{4, 80 * time.Second},
		{5, 160 * time.Second},
		{6, 5 * time.Minute}, // capped
		{10, 5 * time.Minute},
	}

	for _, tc := range tests {
		got := backoff(tc.attempt)
		if got != tc.expected {
			t.Errorf("Backoff(%d): expected %v, got %v", tc.attempt, tc.expected, got)
		}
	}
	t.Log("Exponential backoff with cap works correctly")
}

// TestRetryRunnerRunLoop verifies the Run loop processes entries and
// stops on context cancellation.
func TestRetryRunnerRunLoop(t *testing.T) {
	tmpPath := t.TempDir() + "/retry-loop-queue.json"
	q := er1.NewQueue(tmpPath)
	q.Add(er1.QueueEntry{ID: "loop-1", Tags: "test"})

	var processed int32
	uploadFn := func(entry er1.QueueEntry) error {
		atomic.AddInt32(&processed, 1)
		return nil // always succeed
	}

	runner := er1.NewRetryRunner(q, uploadFn, 5)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	err := runner.Run(ctx, 100*time.Millisecond)
	if err != nil && err != context.DeadlineExceeded {
		t.Fatalf("Unexpected error: %v", err)
	}

	count := atomic.LoadInt32(&processed)
	if count < 1 {
		t.Errorf("Expected at least 1 processing, got %d", count)
	}
	if q.Len() != 0 {
		t.Errorf("Expected empty queue after success, got %d", q.Len())
	}
	t.Logf("Run loop processed %d entries before context cancellation", count)
}

// TestRetryRunnerBackoffSkip verifies that entries with recent LastRetry
// are skipped based on backoff timing.
func TestRetryRunnerBackoffSkip(t *testing.T) {
	tmpPath := t.TempDir() + "/retry-backoff-queue.json"
	q := er1.NewQueue(tmpPath)

	// Add entry that was just retried — should be skipped due to backoff
	q.Add(er1.QueueEntry{ID: "recent-1", Tags: "test"})
	// Simulate a recent retry by updating
	q.UpdateRetry("recent-1", fmt.Errorf("previous error"))

	var called int32
	uploadFn := func(entry er1.QueueEntry) error {
		atomic.AddInt32(&called, 1)
		return nil
	}

	runner := er1.NewRetryRunner(q, uploadFn, 5)
	// Use a large base backoff so the entry won't be ready
	runner.Backoff = er1.DefaultBackoff(1*time.Hour, 24*time.Hour)

	ctx := context.Background()
	successes, failures, dropped := runner.ProcessOnce(ctx)

	if successes != 0 || failures != 0 || dropped != 0 {
		t.Errorf("Expected 0/0/0, got %d/%d/%d — entry should have been skipped", successes, failures, dropped)
	}
	if atomic.LoadInt32(&called) != 0 {
		t.Error("Upload function should not have been called for a skipped entry")
	}
	if q.Len() != 1 {
		t.Errorf("Entry should still be in queue, got %d", q.Len())
	}
	t.Log("Backoff correctly skips recently-retried entries")
}
