package er1

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// BackgroundRetry manages a background goroutine that processes the retry queue.
// It is started automatically during upload commands to drain any pending retries.
type BackgroundRetry struct {
	runner *RetryRunner
	cancel context.CancelFunc
	wg     sync.WaitGroup
	done   chan struct{}

	// OnLog is called for each log message from the background goroutine.
	// If nil, messages are discarded.
	OnLog func(msg string)
}

// StartBackgroundRetry launches a background goroutine that processes the
// retry queue at the given interval. It returns immediately. Call Stop() to
// gracefully shut down the goroutine.
//
// The background goroutine processes existing queue entries using the provided
// upload function and config. It runs until Stop() is called or the parent
// context is cancelled.
func StartBackgroundRetry(queuePath string, cfg *Config, interval time.Duration, maxRetries int) *BackgroundRetry {
	q := NewQueue(queuePath)

	uploadFn := func(entry QueueEntry) error {
		payload := &UploadPayload{
			TranscriptFilename: entry.TranscriptPath,
			AudioFilename:      entry.AudioPath,
			ImageFilename:      entry.ImagePath,
			Tags:               entry.Tags,
		}
		// For background retries, we use placeholder data since the original
		// payload data is not persisted in the queue (only filenames).
		payload.TranscriptData = []byte(fmt.Sprintf("Retry upload for %s", entry.ID))
		payload.AudioData = nil  // will use placeholder
		payload.ImageData = nil  // will use placeholder
		_, err := Upload(cfg, payload)
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	bg := &BackgroundRetry{
		runner: NewRetryRunner(q, uploadFn, maxRetries),
		cancel: cancel,
		done:   make(chan struct{}),
	}

	bg.runner.Backoff = DefaultBackoff(interval, 5*time.Minute)

	bg.runner.OnRetry = func(entry QueueEntry, err error, removed bool) {
		if bg.OnLog == nil {
			return
		}
		if err == nil {
			bg.OnLog(fmt.Sprintf("[bg-retry] SUCCESS: %s", entry.ID))
		} else if removed {
			bg.OnLog(fmt.Sprintf("[bg-retry] DROPPED: %s — max retries exceeded", entry.ID))
		} else {
			bg.OnLog(fmt.Sprintf("[bg-retry] FAILED: %s — attempt %d: %v", entry.ID, entry.RetryCount+1, err))
		}
	}

	bg.wg.Add(1)
	go func() {
		defer bg.wg.Done()
		defer close(bg.done)
		bg.runner.Run(ctx, interval)
	}()

	return bg
}

// StartBackgroundRetryWithRunner launches a background retry using a custom
// RetryRunner. This is useful for testing with mock upload functions.
func StartBackgroundRetryWithRunner(runner *RetryRunner, interval time.Duration) *BackgroundRetry {
	ctx, cancel := context.WithCancel(context.Background())
	bg := &BackgroundRetry{
		runner: runner,
		cancel: cancel,
		done:   make(chan struct{}),
	}

	bg.wg.Add(1)
	go func() {
		defer bg.wg.Done()
		defer close(bg.done)
		bg.runner.Run(ctx, interval)
	}()

	return bg
}

// Stop gracefully shuts down the background retry goroutine.
// It cancels the context and waits for the goroutine to finish,
// with a timeout to avoid blocking indefinitely.
func (bg *BackgroundRetry) Stop(timeout time.Duration) {
	bg.cancel()
	select {
	case <-bg.done:
		// goroutine finished cleanly
	case <-time.After(timeout):
		// timed out waiting — goroutine will be cancelled by context
	}
}

// Done returns a channel that is closed when the background goroutine finishes.
func (bg *BackgroundRetry) Done() <-chan struct{} {
	return bg.done
}

// Running returns true if the background goroutine is still active.
func (bg *BackgroundRetry) Running() bool {
	select {
	case <-bg.done:
		return false
	default:
		return true
	}
}
