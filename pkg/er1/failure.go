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
//  1. Enqueues the failed upload to queue.json for later retry
//  2. Creates a MEMORY folder and saves the payload files locally
//
// MEMORY folders are created ONLY on upload failure (not on every upload).
// The queuePath and memoryRoot can be empty to use defaults.
func HandleUploadFailure(queuePath string, memoryRoot string, videoID string, payload *UploadPayload, tags string, uploadErr error) (*FailureResult, error) {
	mf, err := CreateMemoryFolder(memoryRoot, time.Now())
	if err != nil {
		entry := EnqueueFailure(queuePath, videoID, payload, tags, uploadErr)
		return &FailureResult{Entry: entry}, fmt.Errorf("create memory folder: %w", err)
	}
	if err := mf.SavePayload(payload); err != nil {
		entry := EnqueueFailure(queuePath, videoID, payload, tags, uploadErr)
		return &FailureResult{Entry: entry, Memory: mf}, fmt.Errorf("save payload to memory: %w", err)
	}

	stored := *payload
	stored.TranscriptFilename = memoryFile(mf.Path, payload.TranscriptFilename)
	if payload.AudioData != nil {
		stored.AudioFilename = memoryFile(mf.Path, payload.AudioFilename)
	} else {
		stored.AudioFilename = ""
	}
	if payload.ImageData != nil {
		stored.ImageFilename = memoryFile(mf.Path, payload.ImageFilename)
	} else {
		stored.ImageFilename = ""
	}
	entry := EnqueueFailure(queuePath, videoID, &stored, tags, uploadErr)
	return &FailureResult{Entry: entry, Memory: mf}, nil
}

func memoryFile(dir, name string) string {
	if name == "" {
		return ""
	}
	return filepath.Join(dir, filepath.Base(name))
}
