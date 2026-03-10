package er1

import (
	"context"
	"fmt"
	"math"
	"time"
)

// RetryFunc is the function signature for attempting an upload retry.
// It receives the queue entry and returns nil on success or an error on failure.
type RetryFunc func(entry QueueEntry) error

// BackoffFunc computes the delay before the next retry given the attempt number (0-based).
type BackoffFunc func(attempt int) time.Duration

// DefaultBackoff returns an exponential backoff: base * 2^attempt, capped at maxDelay.
// For example with base=5s, max=5m: 5s, 10s, 20s, 40s, 80s, 160s, 300s, 300s, ...
func DefaultBackoff(base, maxDelay time.Duration) BackoffFunc {
	return func(attempt int) time.Duration {
		d := time.Duration(float64(base) * math.Pow(2, float64(attempt)))
		if d > maxDelay {
			d = maxDelay
		}
		return d
	}
}

// RetryRunner manages the retry loop for queued ER1 uploads.
type RetryRunner struct {
	Queue      *Queue
	UploadFunc RetryFunc
	Backoff    BackoffFunc
	MaxRetries int

	// OnRetry is called after each retry attempt (success or failure).
	// Optional — used for testing/logging.
	OnRetry func(entry QueueEntry, err error, removed bool)

	// sleepFunc can be overridden in tests to avoid real sleeps.
	sleepFunc func(ctx context.Context, d time.Duration) error
}

// NewRetryRunner creates a RetryRunner with sensible defaults.
func NewRetryRunner(q *Queue, uploadFn RetryFunc, maxRetries int) *RetryRunner {
	return &RetryRunner{
		Queue:      q,
		UploadFunc: uploadFn,
		Backoff:    DefaultBackoff(5*time.Second, 5*time.Minute),
		MaxRetries: maxRetries,
		sleepFunc:  contextSleep,
	}
}

// contextSleep sleeps for duration d or until ctx is cancelled.
func contextSleep(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

// ProcessOnce iterates through all queue entries once, attempting each upload.
// Entries are processed in FIFO order (oldest first).
// Successful uploads are removed from the queue.
// Failed uploads have their retry count incremented.
// Entries exceeding MaxRetries are removed (dropped).
// Returns the number of successful uploads and errors encountered.
func (r *RetryRunner) ProcessOnce(ctx context.Context) (successes int, failures int, dropped int) {
	entries := r.Queue.Entries() // FIFO order — oldest first

	for _, entry := range entries {
		// Check context before processing
		if ctx.Err() != nil {
			return
		}

		// Skip entries that haven't waited long enough (backoff)
		if !entry.LastRetry.IsZero() {
			backoffDelay := r.Backoff(entry.RetryCount - 1)
			nextRetry := entry.LastRetry.Add(backoffDelay)
			if time.Now().Before(nextRetry) {
				continue // not yet time to retry
			}
		}

		// Check if entry exceeded max retries
		if r.MaxRetries > 0 && entry.RetryCount >= r.MaxRetries {
			r.Queue.Remove(entry.ID)
			dropped++
			if r.OnRetry != nil {
				r.OnRetry(entry, fmt.Errorf("max retries (%d) exceeded", r.MaxRetries), true)
			}
			continue
		}

		// Attempt upload
		err := r.UploadFunc(entry)
		if err == nil {
			// Success — remove from queue
			r.Queue.Remove(entry.ID)
			successes++
			if r.OnRetry != nil {
				r.OnRetry(entry, nil, true)
			}
		} else {
			// Failure — update retry count
			r.Queue.UpdateRetry(entry.ID, err)
			failures++
			if r.OnRetry != nil {
				r.OnRetry(entry, err, false)
			}
		}
	}
	return
}

// Run starts the retry loop, processing the queue at regular intervals.
// It blocks until the context is cancelled. The interval between processing
// cycles is controlled by the cycleInterval parameter.
// On context cancellation, the current cycle finishes gracefully and Run returns.
func (r *RetryRunner) Run(ctx context.Context, cycleInterval time.Duration) error {
	for {
		// Process one cycle
		r.ProcessOnce(ctx)

		// Wait for the next cycle or cancellation
		if err := r.sleepFunc(ctx, cycleInterval); err != nil {
			return err // context cancelled
		}
	}
}
