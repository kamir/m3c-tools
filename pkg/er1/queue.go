package er1

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
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
	if err := ensureQueueDirectory(dir); err != nil {
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
	CurrentTime    string    `json:"current_time,omitempty"`
	QueuedAt       time.Time `json:"queued_at"`
	LastRetry      time.Time `json:"last_retry,omitempty"`
	RetryCount     int       `json:"retry_count"`
	LastError      string    `json:"last_error,omitempty"`
	// PayloadPath names an immutable, checksummed snapshot stored outside queue metadata.
	PayloadPath   string `json:"payload_path,omitempty"`
	PayloadSHA256 string `json:"payload_sha256,omitempty"`
	APIURL        string `json:"api_url,omitempty"`
	ContextID     string `json:"context_id,omitempty"`
	ContentType   string `json:"content_type,omitempty"`
}

// Queue is a persistent JSON-backed upload queue. Mutations reload the file
// under an operating-system lock and atomically replace the durable snapshot.
type Queue struct {
	mu      sync.Mutex
	path    string
	lastErr error
}

// NewQueue creates a queue handle. Reads and mutations load the latest disk state.
func NewQueue(path string) *Queue { return &Queue{path: path} }

func (q *Queue) transaction(change func(*[]QueueEntry) error) (entries []QueueEntry, err error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	defer func() { q.lastErr = err }()
	if err = ensureQueueDirectory(filepath.Dir(q.path)); err != nil {
		return nil, err
	}
	lock, err := lockQueueFile(q.path+".lock", false)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	data, err := os.ReadFile(q.path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read queue: %w", err)
	}
	if err == nil {
		if err = json.Unmarshal(data, &entries); err != nil {
			return nil, fmt.Errorf("decode queue %s: %w", q.path, err)
		}
	}
	if change != nil {
		if err = change(&entries); err != nil {
			return nil, err
		}
		if err = q.save(entries); err != nil {
			return nil, err
		}
	}
	return entries, nil
}

// ReadEntries returns the latest queue state or its read/decode error.
func (q *Queue) ReadEntries() ([]QueueEntry, error) { return q.transaction(nil) }

// Err returns the error from the most recent operation, including Entries and Len.
func (q *Queue) Err() error { q.mu.Lock(); defer q.mu.Unlock(); return q.lastErr }

// Add adds an entry durably without overwriting concurrent queue changes.
func (q *Queue) Add(entry QueueEntry) error {
	_, err := q.transaction(func(entries *[]QueueEntry) error {
		for _, existing := range *entries {
			if existing.ID == entry.ID {
				return fmt.Errorf("duplicate queue id %q", entry.ID)
			}
		}
		entry.QueuedAt = time.Now()
		*entries = append(*entries, entry)
		return nil
	})
	return err
}

// Entries returns the latest entries. Read errors are logged and available via Err.
// Call ReadEntries when the caller can propagate an error.
func (q *Queue) Entries() []QueueEntry {
	entries, err := q.ReadEntries()
	if err != nil {
		fmt.Fprintf(os.Stderr, "queue: %v\n", err)
	}
	return entries
}

// Len returns the latest entry count. A read failure returns zero and sets Err.
func (q *Queue) Len() int { return len(q.Entries()) }

// Remove removes an entry by ID and persists the latest queue state.
func (q *Queue) Remove(id string) error {
	_, err := q.transaction(func(entries *[]QueueEntry) error {
		for i, e := range *entries {
			if e.ID == id {
				*entries = append((*entries)[:i], (*entries)[i+1:]...)
				break
			}
		}
		return nil
	})
	return err
}

// UpdateRetry persists retry metadata without replacing concurrent additions.
func (q *Queue) UpdateRetry(id string, retryErr error) error {
	_, err := q.transaction(func(entries *[]QueueEntry) error {
		for i, e := range *entries {
			if e.ID == id {
				(*entries)[i].RetryCount++
				(*entries)[i].LastRetry = time.Now()
				if retryErr != nil {
					(*entries)[i].LastError = retryErr.Error()
				}
				break
			}
		}
		return nil
	})
	return err
}

// Clear removes all entries. An unreadable queue is never overwritten.
func (q *Queue) Clear() error {
	var removed []QueueEntry
	_, err := q.transaction(func(entries *[]QueueEntry) error { removed = *entries; *entries = nil; return nil })
	if err != nil {
		return err
	}
	var cleanupErrors []error
	for _, entry := range removed {
		if err := removeQueuePayload(q.path, entry); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("clear payload: %w", err))
		}
	}
	return errors.Join(cleanupErrors...)
}

// EnqueueFailure durably snapshots all payload bytes and upload parameters.
// The optional config binds the entry to its original endpoint and context,
// without storing authentication. Nil means persistence failed, with an error logged.
func EnqueueFailure(queuePath, videoID string, payload *UploadPayload, tags string, uploadErr error, configs ...*Config) *QueueEntry {
	if queuePath == "" {
		queuePath = DefaultQueuePath()
	}
	if payload == nil {
		fmt.Fprintln(os.Stderr, "enqueue failure: nil payload")
		return nil
	}
	snapshot := *payload
	snapshot.Tags = tags
	entry := QueueEntry{
		ID:             fmt.Sprintf("%s-%d", videoID, time.Now().UnixNano()),
		TranscriptPath: payload.TranscriptFilename, AudioPath: payload.AudioFilename, ImagePath: payload.ImageFilename,
		Tags: tags, CurrentTime: payload.CurrentTime,
	}
	if len(configs) > 0 && configs[0] != nil {
		cfg := configs[0]
		endpoint, err := url.Parse(cfg.APIURL)
		if err != nil || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
			fmt.Fprintln(os.Stderr, "enqueue failure: endpoint must not contain credentials, query, or fragment")
			return nil
		}
		entry.APIURL, entry.ContextID, entry.ContentType = cfg.APIURL, cfg.ContextID, cfg.ContentType
	}
	if uploadErr != nil {
		entry.LastError = uploadErr.Error()
	}
	// Reject an unreadable queue before creating a new sensitive snapshot.
	if _, err := NewQueue(queuePath).ReadEntries(); err != nil {
		fmt.Fprintf(os.Stderr, "enqueue failure: read queue: %v\n", err)
		return nil
	}
	payloadPath, digest, err := persistQueuePayload(queuePath, &snapshot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "enqueue failure: persist payload: %v\n", err)
		return nil
	}
	entry.PayloadPath, entry.PayloadSHA256 = payloadPath, digest
	if err := NewQueue(queuePath).Add(entry); err != nil {
		fmt.Fprintf(os.Stderr, "enqueue failure: persist entry %s: %v\n", entry.ID, err)
		// A failed directory sync may follow a successful rename. Only remove the
		// new snapshot when a readable queue proves that it is not referenced.
		if entries, readErr := NewQueue(queuePath).ReadEntries(); readErr == nil {
			referenced := false
			for _, saved := range entries {
				if saved.PayloadPath == entry.PayloadPath {
					referenced = true
					break
				}
			}
			if !referenced {
				cleanupQueuePayload(queuePath, entry)
			}
		}
		return nil
	}
	// Return the persisted snapshot, detached from caller-owned byte slices.
	entries, err := NewQueue(queuePath).ReadEntries()
	if err != nil {
		fmt.Fprintf(os.Stderr, "enqueue failure: confirm persist: %v\n", err)
		return nil
	}
	for _, saved := range entries {
		if saved.ID == entry.ID {
			return &saved
		}
	}
	return &entry
}

// PayloadFromQueueEntry restores the persisted snapshot. Legacy entries remain
// readable, but every named original file must exist; missing data is an error.
func PayloadFromQueueEntry(entry QueueEntry) (*UploadPayload, error) {
	if entry.PayloadPath != "" {
		if !filepath.IsAbs(entry.PayloadPath) || entry.PayloadSHA256 == "" {
			return nil, fmt.Errorf("queue entry %s has invalid payload metadata", entry.ID)
		}
		data, err := os.ReadFile(entry.PayloadPath)
		if err != nil {
			return nil, fmt.Errorf("read queue payload: %w", err)
		}
		hash := sha256.Sum256(data)
		if hex.EncodeToString(hash[:]) != entry.PayloadSHA256 {
			return nil, fmt.Errorf("queue entry %s payload checksum mismatch", entry.ID)
		}
		var payload UploadPayload
		if err := json.Unmarshal(data, &payload); err != nil {
			return nil, fmt.Errorf("decode queue payload: %w", err)
		}
		return &payload, nil
	}

	payload := &UploadPayload{TranscriptFilename: entry.TranscriptPath, AudioFilename: entry.AudioPath, ImageFilename: entry.ImagePath, Tags: entry.Tags, CurrentTime: entry.CurrentTime}
	for _, part := range []struct {
		path string
		data *[]byte
	}{
		{entry.TranscriptPath, &payload.TranscriptData}, {entry.AudioPath, &payload.AudioData}, {entry.ImagePath, &payload.ImageData},
	} {
		if part.path == "" {
			continue
		}
		data, err := os.ReadFile(part.path)
		if err != nil {
			return nil, fmt.Errorf("restore queue entry %s, original %s: %w", entry.ID, part.path, err)
		}
		*part.data = data
	}
	if payload.TranscriptData == nil && payload.AudioData == nil && payload.ImageData == nil {
		return nil, fmt.Errorf("queue entry %s has no original payload", entry.ID)
	}
	return payload, nil
}

// RetryUpload restores an entry and refuses to redirect it to a changed target.
// Legacy entries require explicit review and requeueing to bind a destination.
func RetryUpload(cfg *Config, entry QueueEntry) (*UploadResponse, error) {
	if entry.APIURL == "" {
		return nil, fmt.Errorf("legacy queue entry %s has no bound destination; review and requeue the originals", entry.ID)
	}
	if entry.APIURL != "" && (entry.APIURL != cfg.APIURL || entry.ContextID != cfg.ContextID) {
		return nil, fmt.Errorf("queue entry %s target differs from current endpoint or context", entry.ID)
	}
	payload, err := PayloadFromQueueEntry(entry)
	if err != nil {
		return nil, err
	}
	retryConfig := *cfg
	if entry.APIURL != "" {
		retryConfig.ContentType = entry.ContentType
	}
	return Upload(&retryConfig, payload)
}

func (q *Queue) save(entries []QueueEntry) error {
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(q.path), ".queue-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		return errors.Join(err, tmp.Close())
	}
	if err := tmp.Sync(); err != nil {
		return errors.Join(err, tmp.Close())
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := renameQueueFile(tmp.Name(), q.path); err != nil {
		return err
	}
	return syncQueueDirectory(filepath.Dir(q.path))
}

// persistQueuePayload commits the immutable snapshot before publishing its metadata.
// An interrupted enqueue may leave an unreferenced snapshot, never a partial upload.
func persistQueuePayload(queuePath string, payload *UploadPayload) (string, string, error) {
	dir, err := filepath.Abs(queuePath + ".payloads")
	if err != nil {
		return "", "", err
	}
	if err := ensureQueueDirectory(dir); err != nil {
		return "", "", err
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", "", err
	}
	tmp, err := os.CreateTemp(dir, ".pending-*")
	if err != nil {
		return "", "", err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		return "", "", errors.Join(err, tmp.Close())
	}
	if err := tmp.Sync(); err != nil {
		return "", "", errors.Join(err, tmp.Close())
	}
	if err := tmp.Close(); err != nil {
		return "", "", err
	}
	path := tmp.Name() + ".json"
	if err := renameQueueFile(tmp.Name(), path); err != nil {
		return "", "", err
	}
	if err := syncQueueDirectory(dir); err != nil {
		return "", "", err
	}
	// Persist the directory entry for a newly created payload directory too.
	if err := syncQueueDirectory(filepath.Dir(dir)); err != nil {
		return "", "", err
	}
	hash := sha256.Sum256(data)
	return path, hex.EncodeToString(hash[:]), nil
}

// ErrUploadPending means the payload is durably queued while another uploader owns retries.
var ErrUploadPending = errors.New("upload saved locally for retry")

var errQueueBusy = errors.New("upload queue already owned")

// UploadDurable persists the original payload before attempting a network upload.
// It holds retry ownership until the confirmed upload is removed from the queue.
// On failure, a non-nil entry identifies the durable retry; a nil entry means no
// network request was attempted. Delivery remains at least once: a process crash
// after server acceptance and before local removal may cause a repeated upload.
func UploadDurable(cfg *Config, payload *UploadPayload, queuePath, label string) (*UploadResponse, *QueueEntry, error) {
	if cfg == nil || payload == nil {
		return nil, nil, fmt.Errorf("upload config and payload are required")
	}
	if queuePath == "" {
		queuePath = DefaultQueuePath()
	}
	if err := ensureQueueDirectory(filepath.Dir(queuePath)); err != nil {
		return nil, nil, fmt.Errorf("prepare upload queue: %w", err)
	}
	// Try ownership without waiting for any network activity. Even when busy,
	// the capture is immediately persisted and returned as pending.
	lock, lockErr := lockQueueFile(queuePath+".retry.lock", true)
	if lockErr == nil {
		defer lock.Close()
	}
	entry := EnqueueFailure(queuePath, label, payload, payload.Tags, nil, cfg)
	if entry == nil {
		return nil, nil, fmt.Errorf("persist upload before sending: queue unavailable")
	}
	if errors.Is(lockErr, errQueueBusy) {
		return nil, entry, ErrUploadPending
	}
	if lockErr != nil {
		return nil, entry, fmt.Errorf("upload saved locally; acquire retry ownership: %w", lockErr)
	}
	response, err := RetryUpload(cfg, *entry)
	if err != nil {
		if updateErr := NewQueue(queuePath).UpdateRetry(entry.ID, err); updateErr != nil {
			return nil, entry, fmt.Errorf("upload failed (%v); persist retry state: %w", err, updateErr)
		}
		return nil, entry, err
	}
	if err := NewQueue(queuePath).Remove(entry.ID); err != nil {
		return response, entry, fmt.Errorf("upload accepted but queue removal failed: %w", err)
	}
	cleanupQueuePayload(queuePath, *entry)
	return response, nil, nil
}

// cleanupQueuePayload removes only managed snapshots after confirmed delivery.
func cleanupQueuePayload(queuePath string, entry QueueEntry) {
	if err := removeQueuePayload(queuePath, entry); err != nil {
		fmt.Fprintf(os.Stderr, "queue: cleanup delivered payload: %v\n", err)
	}
}

func removeQueuePayload(queuePath string, entry QueueEntry) error {
	if entry.PayloadPath == "" {
		return nil
	}
	dir, err := filepath.Abs(queuePath + ".payloads")
	if err != nil {
		return err
	}
	if filepath.Dir(entry.PayloadPath) != dir {
		return fmt.Errorf("refuse cleanup outside managed payload directory")
	}
	if err := os.Remove(entry.PayloadPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncQueueDirectory(dir)
}

// ensureQueueDirectory also commits newly created parent directory entries.
func ensureQueueDirectory(path string) error {
	var missing []string
	for dir := filepath.Clean(path); ; dir = filepath.Dir(dir) {
		_, err := os.Stat(dir)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		missing = append(missing, dir)
		if filepath.Dir(dir) == dir {
			return fmt.Errorf("no existing ancestor for queue directory")
		}
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	for _, dir := range missing {
		if err := syncQueueDirectory(filepath.Dir(dir)); err != nil {
			return err
		}
	}
	return nil
}
