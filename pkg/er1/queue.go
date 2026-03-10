package er1

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DefaultQueuePath returns the default path for the retry queue file (~/.m3c-tools/queue.json).
// It creates the ~/.m3c-tools/ directory if it doesn't exist.
func DefaultQueuePath() string {
	dir := filepath.Join(os.Getenv("HOME"), ".m3c-tools")
	os.MkdirAll(dir, 0700)
	return filepath.Join(dir, "queue.json")
}

// QueueEntry represents a single pending upload in the retry queue.
type QueueEntry struct {
	ID             string    `json:"id"`
	TranscriptPath string    `json:"transcript_path"`
	AudioPath      string    `json:"audio_path,omitempty"`
	ImagePath      string    `json:"image_path,omitempty"`
	Tags           string    `json:"tags"`
	ContentType    string    `json:"content_type,omitempty"`
	MemoryPath     string    `json:"memory_path,omitempty"`
	QueuedAt       time.Time `json:"queued_at"`
	LastRetry      time.Time `json:"last_retry,omitempty"`
	RetryCount     int       `json:"retry_count"`
	LastError      string    `json:"last_error,omitempty"`
}

// Queue is a persistent JSON-backed upload queue.
type Queue struct {
	mu      sync.Mutex
	entries []QueueEntry
	path    string
}

// NewQueue creates or loads a queue from a JSON file.
func NewQueue(path string) *Queue {
	q := &Queue{path: path}
	q.load()
	return q
}

// Add adds an entry to the queue and persists it.
func (q *Queue) Add(entry QueueEntry) {
	q.mu.Lock()
	defer q.mu.Unlock()
	entry.QueuedAt = time.Now()
	q.entries = append(q.entries, entry)
	q.save()
}

// Entries returns a copy of all queue entries.
func (q *Queue) Entries() []QueueEntry {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]QueueEntry, len(q.entries))
	copy(out, q.entries)
	return out
}

// Len returns the number of entries.
func (q *Queue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.entries)
}

// Remove removes an entry by ID and persists.
func (q *Queue) Remove(id string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for i, e := range q.entries {
		if e.ID == id {
			q.entries = append(q.entries[:i], q.entries[i+1:]...)
			q.save()
			return
		}
	}
}

// UpdateRetry updates retry metadata for an entry.
func (q *Queue) UpdateRetry(id string, err error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for i, e := range q.entries {
		if e.ID == id {
			q.entries[i].RetryCount = e.RetryCount + 1
			q.entries[i].LastRetry = time.Now()
			if err != nil {
				q.entries[i].LastError = err.Error()
			}
			q.save()
			return
		}
	}
}

// Clear removes all entries.
func (q *Queue) Clear() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.entries = nil
	q.save()
}

// EnqueueFailure creates a QueueEntry from a failed upload and persists
// it to the queue file at the given path. If queuePath is empty, the
// default path (~/.m3c-tools/queue.json) is used. Returns the created entry.
func EnqueueFailure(queuePath string, videoID string, payload *UploadPayload, tags string, uploadErr error) *QueueEntry {
	if queuePath == "" {
		queuePath = DefaultQueuePath()
	}
	if payload == nil {
		return nil
	}

	// Ensure parent directory exists
	dir := filepath.Dir(queuePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "enqueue failure: create dir %s: %v\n", dir, err)
		return nil
	}

	// Persist payload files first so retries can re-upload the original artifacts.
	mf, memErr := CreateMemoryFolder(DefaultMemoryPath(), time.Now())
	if memErr != nil {
		fmt.Fprintf(os.Stderr, "enqueue failure: create memory folder: %v\n", memErr)
		return nil
	}
	if err := mf.SavePayload(payload); err != nil {
		fmt.Fprintf(os.Stderr, "enqueue failure: save payload in memory folder: %v\n", err)
		return nil
	}

	entry := QueueEntry{
		ID:             fmt.Sprintf("%s-%d", videoID, time.Now().UnixNano()),
		TranscriptPath: filepath.Join(mf.Path, payload.TranscriptFilename),
		AudioPath:      queuedFilePath(mf.Path, payload.AudioFilename, payload.AudioData),
		ImagePath:      queuedFilePath(mf.Path, payload.ImageFilename, payload.ImageData),
		Tags:           tags,
		ContentType:    payload.ContentType,
		MemoryPath:     mf.Path,
	}
	if uploadErr != nil {
		entry.LastError = uploadErr.Error()
	}

	q := NewQueue(queuePath)
	q.Add(entry)

	// Return a copy with QueuedAt set
	entries := q.Entries()
	for _, e := range entries {
		if e.ID == entry.ID {
			return &e
		}
	}
	return &entry
}

func (q *Queue) load() {
	data, err := os.ReadFile(q.path)
	if err != nil {
		return // file doesn't exist yet
	}
	if err := json.Unmarshal(data, &q.entries); err != nil {
		return
	}
}

func (q *Queue) save() {
	data, err := json.MarshalIndent(q.entries, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "queue save error: %v\n", err)
		return
	}
	// Ensure parent directory exists
	dir := filepath.Dir(q.path)
	if dir != "" && dir != "." {
		os.MkdirAll(dir, 0700)
	}
	os.WriteFile(q.path, data, 0600)
}

func queuedFilePath(memoryPath, filename string, data []byte) string {
	if filename == "" {
		return ""
	}
	if len(data) == 0 {
		return ""
	}
	return filepath.Join(memoryPath, filename)
}
