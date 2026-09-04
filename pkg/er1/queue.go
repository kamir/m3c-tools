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
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	dir := filepath.Join(home, ".m3c-tools")
	if err := os.MkdirAll(dir, 0700); err != nil {
		// Non-fatal: return the path anyway so the caller's subsequent save()
		// surfaces the real write error, but don't swallow the signal.
		fmt.Fprintf(os.Stderr, "queue: could not create %s: %v\n", dir, err)
	}
	return filepath.Join(dir, "queue.json")
}

// QueueEntry represents a single pending upload in the retry queue.
type QueueEntry struct {
	ID             string    `json:"id"`
	TranscriptPath string    `json:"transcript_path"`
	AudioPath      string    `json:"audio_path,omitempty"`
	ImagePath      string    `json:"image_path,omitempty"`
	Tags           string    `json:"tags"`
	CurrentTime    string    `json:"current_time,omitempty"` // real capture time; preserved across retries
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

// Add adds an entry to the queue and persists it. It returns an error if the
// queue could not be persisted, so an enqueue failure is not silently dropped.
func (q *Queue) Add(entry QueueEntry) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	entry.QueuedAt = time.Now()
	q.entries = append(q.entries, entry)
	return q.save()
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

// Remove removes an entry by ID and persists. Returns the persistence error, if
// any (nil when the id was not present: nothing changed).
func (q *Queue) Remove(id string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	for i, e := range q.entries {
		if e.ID == id {
			q.entries = append(q.entries[:i], q.entries[i+1:]...)
			return q.save()
		}
	}
	return nil
}

// UpdateRetry updates retry metadata for an entry. Returns the persistence
// error, if any (nil when the id was not present).
func (q *Queue) UpdateRetry(id string, err error) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	for i, e := range q.entries {
		if e.ID == id {
			q.entries[i].RetryCount = e.RetryCount + 1
			q.entries[i].LastRetry = time.Now()
			if err != nil {
				q.entries[i].LastError = err.Error()
			}
			return q.save()
		}
	}
	return nil
}

// Clear removes all entries. Returns the persistence error, if any.
func (q *Queue) Clear() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.entries = nil
	return q.save()
}

// EnqueueFailure creates a QueueEntry from a failed upload and persists
// it to the queue file at the given path. If queuePath is empty, the
// default path (~/.m3c-tools/queue.json) is used. Returns the created entry.
func EnqueueFailure(queuePath string, videoID string, payload *UploadPayload, tags string, uploadErr error) *QueueEntry {
	if queuePath == "" {
		queuePath = DefaultQueuePath()
	}

	// Ensure parent directory exists
	dir := filepath.Dir(queuePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "enqueue failure: create dir %s: %v\n", dir, err)
		return nil
	}

	entry := QueueEntry{
		ID:             fmt.Sprintf("%s-%d", videoID, time.Now().UnixNano()),
		TranscriptPath: payload.TranscriptFilename,
		AudioPath:      payload.AudioFilename,
		ImagePath:      payload.ImageFilename,
		Tags:           tags,
		CurrentTime:    payload.CurrentTime, // preserve real capture time across retries
	}
	if uploadErr != nil {
		entry.LastError = uploadErr.Error()
	}

	q := NewQueue(queuePath)
	if err := q.Add(entry); err != nil {
		fmt.Fprintf(os.Stderr, "enqueue failure: persist entry %s: %v\n", entry.ID, err)
		return nil
	}

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

// save persists the queue to disk. It returns an error so callers can surface a
// failed persist instead of silently dropping a retry-queue mutation. The error
// is also logged to stderr (queue mutations are best-effort at most call sites).
func (q *Queue) save() error {
	data, err := json.MarshalIndent(q.entries, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "queue save error: %v\n", err)
		return err
	}
	// Ensure parent directory exists
	dir := filepath.Dir(q.path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			fmt.Fprintf(os.Stderr, "queue save error: create %s: %v\n", dir, err)
			return err
		}
	}
	if err := os.WriteFile(q.path, data, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "queue save error: write %s: %v\n", q.path, err)
		return err
	}
	return nil
}
