package e2e

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/er1"
)

// TestBackgroundRetryStartsAndProcesses verifies that StartBackgroundRetryWithRunner
// launches a background goroutine that processes queued entries automatically.
func TestBackgroundRetryStartsAndProcesses(t *testing.T) {
	tmpPath := t.TempDir() + "/bg-retry-queue.json"
	q := er1.NewQueue(tmpPath)

	// Seed 2 entries
	q.Add(er1.QueueEntry{ID: "bg-ok-1", Tags: "test"})
	q.Add(er1.QueueEntry{ID: "bg-ok-2", Tags: "test"})

	var processed int32
	uploadFn := func(entry er1.QueueEntry) error {
		atomic.AddInt32(&processed, 1)
		return nil
	}

	runner := er1.NewRetryRunner(q, uploadFn, 5)
	bg := er1.StartBackgroundRetryWithRunner(runner, 50*time.Millisecond)

	// Verify it's running
	if !bg.Running() {
		t.Fatal("Expected background retry to be running")
	}

	// Wait for processing to complete
	time.Sleep(300 * time.Millisecond)

	count := atomic.LoadInt32(&processed)
	if count < 2 {
		t.Errorf("Expected at least 2 processed entries, got %d", count)
	}

	// Queue should be drained
	if q.Len() != 0 {
		t.Errorf("Expected empty queue, got %d entries", q.Len())
	}

	// Stop gracefully
	bg.Stop(2 * time.Second)
	if bg.Running() {
		t.Error("Expected background retry to be stopped")
	}
	t.Logf("Background retry processed %d entries", count)
}

// TestBackgroundRetryStopsGracefully verifies that Stop() shuts down the goroutine.
func TestBackgroundRetryStopsGracefully(t *testing.T) {
	tmpPath := t.TempDir() + "/bg-stop-queue.json"
	q := er1.NewQueue(tmpPath)

	uploadFn := func(entry er1.QueueEntry) error {
		return nil
	}

	runner := er1.NewRetryRunner(q, uploadFn, 5)
	bg := er1.StartBackgroundRetryWithRunner(runner, 100*time.Millisecond)

	if !bg.Running() {
		t.Fatal("Expected background retry to be running")
	}

	bg.Stop(2 * time.Second)

	if bg.Running() {
		t.Error("Expected background retry to be stopped after Stop()")
	}

	// Done channel should be closed
	select {
	case <-bg.Done():
		// expected
	default:
		t.Error("Done channel should be closed after Stop()")
	}
	t.Log("Background retry stopped gracefully")
}

// TestBackgroundRetryHandlesFailures verifies that the background goroutine
// handles upload failures by keeping entries in the queue for later retry.
func TestBackgroundRetryHandlesFailures(t *testing.T) {
	tmpPath := t.TempDir() + "/bg-fail-queue.json"
	q := er1.NewQueue(tmpPath)

	q.Add(er1.QueueEntry{ID: "bg-fail-1", Tags: "test"})

	var attempts int32
	uploadFn := func(entry er1.QueueEntry) error {
		atomic.AddInt32(&attempts, 1)
		return fmt.Errorf("simulated failure")
	}

	// Use high max retries so the entry won't be dropped during the test
	runner := er1.NewRetryRunner(q, uploadFn, 100)
	// Use very short backoff for testing
	runner.Backoff = er1.DefaultBackoff(1*time.Millisecond, 10*time.Millisecond)

	bg := er1.StartBackgroundRetryWithRunner(runner, 50*time.Millisecond)

	// Let it attempt a few retries
	time.Sleep(300 * time.Millisecond)
	bg.Stop(2 * time.Second)

	count := atomic.LoadInt32(&attempts)
	if count < 1 {
		t.Errorf("Expected at least 1 retry attempt, got %d", count)
	}

	// Entry should still be in queue (not yet exceeded max retries of 100)
	if q.Len() != 1 {
		t.Errorf("Expected 1 entry still in queue, got %d", q.Len())
	}

	if q.Len() > 0 {
		entries := q.Entries()
		if entries[0].RetryCount < 1 {
			t.Errorf("Expected retry count >= 1, got %d", entries[0].RetryCount)
		}
		t.Logf("Background retry made %d attempts, entry has %d retries", count, entries[0].RetryCount)
	}
}

// TestBackgroundRetryEmptyQueue verifies the goroutine runs fine with no entries.
func TestBackgroundRetryEmptyQueue(t *testing.T) {
	tmpPath := t.TempDir() + "/bg-empty-queue.json"
	q := er1.NewQueue(tmpPath)

	var called int32
	uploadFn := func(entry er1.QueueEntry) error {
		atomic.AddInt32(&called, 1)
		return nil
	}

	runner := er1.NewRetryRunner(q, uploadFn, 5)
	bg := er1.StartBackgroundRetryWithRunner(runner, 50*time.Millisecond)

	time.Sleep(200 * time.Millisecond)
	bg.Stop(2 * time.Second)

	if atomic.LoadInt32(&called) != 0 {
		t.Error("Upload function should not be called with empty queue")
	}

	if bg.Running() {
		t.Error("Expected stopped after Stop()")
	}
	t.Log("Background retry with empty queue runs and stops cleanly")
}

// TestBackgroundRetryLogging verifies OnLog callback is invoked.
func TestBackgroundRetryLogging(t *testing.T) {
	tmpPath := t.TempDir() + "/bg-log-queue.json"
	q := er1.NewQueue(tmpPath)
	q.Add(er1.QueueEntry{ID: "bg-log-1", Tags: "test"})

	uploadFn := func(entry er1.QueueEntry) error {
		return nil
	}

	runner := er1.NewRetryRunner(q, uploadFn, 5)
	bg := er1.StartBackgroundRetryWithRunner(runner, 50*time.Millisecond)

	var logCount int32
	bg.OnLog = func(msg string) {
		atomic.AddInt32(&logCount, 1)
	}

	// The OnLog on the BackgroundRetry is separate from the runner's OnRetry.
	// The runner's OnRetry is set in StartBackgroundRetry (not StartBackgroundRetryWithRunner).
	// For StartBackgroundRetryWithRunner, the runner's OnRetry is nil unless set explicitly.
	runner.OnRetry = func(entry er1.QueueEntry, err error, removed bool) {
		if bg.OnLog != nil {
			if err == nil {
				bg.OnLog(fmt.Sprintf("[bg-retry] SUCCESS: %s", entry.ID))
			}
		}
	}

	time.Sleep(200 * time.Millisecond)
	bg.Stop(2 * time.Second)

	if atomic.LoadInt32(&logCount) < 1 {
		t.Error("Expected at least 1 log message")
	}
	t.Logf("Background retry logged %d messages", atomic.LoadInt32(&logCount))
}
