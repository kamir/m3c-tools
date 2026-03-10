package er1

import (
	"fmt"
	"path/filepath"
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
//  1. Persists payload files in a MEMORY folder
//  2. Enqueues a retry entry pointing at those persisted artifacts
//
// MEMORY folders are created ONLY on upload failure (not on every upload).
// The queuePath and memoryRoot can be empty to use defaults.
func HandleUploadFailure(queuePath string, memoryRoot string, videoID string, payload *UploadPayload, tags string, uploadErr error) (*FailureResult, error) {
	_ = memoryRoot // persistence path is derived by EnqueueFailure + DefaultMemoryPath for now

	// EnqueueFailure now persists payload files and stores absolute artifact paths.
	entry := EnqueueFailure(queuePath, videoID, payload, tags, uploadErr)
	if entry == nil {
		return nil, fmt.Errorf("enqueue failure returned nil entry")
	}

	memPath := entry.MemoryPath
	if memPath == "" && entry.TranscriptPath != "" {
		memPath = filepath.Dir(entry.TranscriptPath)
	}
	if memPath == "" {
		memPath = filepath.Join(DefaultMemoryPath(), MemoryID(time.Now()))
	}
	mf := &MemoryFolder{Path: memPath, MemoryID: filepath.Base(memPath)}

	return &FailureResult{Entry: entry, Memory: mf}, nil
}
