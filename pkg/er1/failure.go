package er1

import (
	"fmt"
	"time"
)

// FailureResult captures the outcome of handling a failed upload:
// the queue entry that was persisted and the MEMORY folder where
// payload files were saved for offline retry.
type FailureResult struct {
	Entry  *QueueEntry
	Memory *MemoryFolder
}

// HandleUploadFailure is called when an ER1 upload fails.
// It performs two actions:
//  1. Enqueues the failed upload to queue.json for later retry
//  2. Creates a MEMORY folder and saves the payload files locally
//
// MEMORY folders are created ONLY on upload failure (not on every upload).
// The queuePath and memoryRoot can be empty to use defaults.
func HandleUploadFailure(queuePath string, memoryRoot string, videoID string, payload *UploadPayload, tags string, uploadErr error) (*FailureResult, error) {
	// Step 1: Enqueue to queue.json
	entry := EnqueueFailure(queuePath, videoID, payload, tags, uploadErr)

	// Step 2: Create MEMORY folder and save payload
	mf, err := CreateMemoryFolder(memoryRoot, time.Now())
	if err != nil {
		return &FailureResult{Entry: entry}, fmt.Errorf("create memory folder: %w", err)
	}

	if err := mf.SavePayload(payload); err != nil {
		return &FailureResult{Entry: entry, Memory: mf}, fmt.Errorf("save payload to memory: %w", err)
	}

	return &FailureResult{Entry: entry, Memory: mf}, nil
}
