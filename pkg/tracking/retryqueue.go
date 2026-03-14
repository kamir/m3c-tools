// Package tracking provides SQLite-backed retry queue for ER1 uploads.
// The er1_retry_queue table tracks failed uploads with exponential backoff
// scheduling, enabling automatic retry with configurable delay progression.
package tracking

import (
	"database/sql"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/kamir/m3c-tools/internal/dbdriver"
)

const createRetryQueueTableSQL = `
CREATE TABLE IF NOT EXISTS er1_retry_queue (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id        TEXT NOT NULL UNIQUE,
    transcript_path TEXT NOT NULL,
    audio_path      TEXT,
    image_path      TEXT,
    tags            TEXT,
    status          TEXT NOT NULL DEFAULT 'pending',
    attempts        INTEGER NOT NULL DEFAULT 0,
    max_attempts    INTEGER NOT NULL DEFAULT 10,
    last_error      TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    next_retry_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_retry_queue_status ON er1_retry_queue(status);
CREATE INDEX IF NOT EXISTS idx_retry_queue_next_retry ON er1_retry_queue(next_retry_at);`

// RetryStatus constants for the retry queue.
const (
	RetryStatusPending   = "pending"
	RetryStatusRetrying  = "retrying"
	RetryStatusCompleted = "completed"
	RetryStatusFailed    = "failed" // permanently failed (max attempts exceeded)
)

// Default backoff parameters.
const (
	DefaultBaseDelay    = 30 * time.Second
	DefaultMaxDelay     = 1 * time.Hour
	DefaultMaxAttempts  = 10
	DefaultBackoffScale = 2.0
)

// RetryEntry represents a row in the er1_retry_queue table.
type RetryEntry struct {
	ID             int64
	EntryID        string
	TranscriptPath string
	AudioPath      string
	ImagePath      string
	Tags           string
	Status         string
	Attempts       int
	MaxAttempts    int
	LastError      string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	NextRetryAt    time.Time
}

// RetryQueueDB manages the er1_retry_queue SQLite table.
type RetryQueueDB struct {
	db           *sql.DB
	baseDelay    time.Duration
	maxDelay     time.Duration
	backoffScale float64
}

// RetryQueueOption configures the retry queue behavior.
type RetryQueueOption func(*RetryQueueDB)

// WithBaseDelay sets the base delay for exponential backoff.
func WithBaseDelay(d time.Duration) RetryQueueOption {
	return func(q *RetryQueueDB) { q.baseDelay = d }
}

// WithMaxDelay sets the maximum delay cap for exponential backoff.
func WithMaxDelay(d time.Duration) RetryQueueOption {
	return func(q *RetryQueueDB) { q.maxDelay = d }
}

// WithBackoffScale sets the exponential backoff multiplier.
func WithBackoffScale(s float64) RetryQueueOption {
	return func(q *RetryQueueDB) { q.backoffScale = s }
}

// OpenRetryQueueDB opens (or creates) the SQLite database at the given path
// and ensures the er1_retry_queue table exists.
func OpenRetryQueueDB(dbPath string, opts ...RetryQueueOption) (*RetryQueueDB, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	db, err := sql.Open(dbdriver.DriverName(), dbPath+"?_journal_mode=WAL")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	if _, err := db.Exec(createRetryQueueTableSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create er1_retry_queue table: %w", err)
	}

	q := &RetryQueueDB{
		db:           db,
		baseDelay:    DefaultBaseDelay,
		maxDelay:     DefaultMaxDelay,
		backoffScale: DefaultBackoffScale,
	}
	for _, opt := range opts {
		opt(q)
	}

	return q, nil
}

// Close closes the underlying database connection.
func (q *RetryQueueDB) Close() error {
	return q.db.Close()
}

// CalculateBackoff returns the delay before the next retry for the given attempt
// number (0-indexed). The formula is: min(baseDelay * scale^attempt, maxDelay).
func (q *RetryQueueDB) CalculateBackoff(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	delay := float64(q.baseDelay) * math.Pow(q.backoffScale, float64(attempt))
	if delay > float64(q.maxDelay) {
		delay = float64(q.maxDelay)
	}
	return time.Duration(delay)
}

// Insert adds a new entry to the retry queue with status "pending" and
// next_retry_at set to now (immediately eligible for retry).
func (q *RetryQueueDB) Insert(entryID, transcriptPath, audioPath, imagePath, tags string, maxAttempts int) (*RetryEntry, error) {
	if maxAttempts <= 0 {
		maxAttempts = DefaultMaxAttempts
	}
	now := time.Now().UTC().Format(time.RFC3339)

	res, err := q.db.Exec(`
		INSERT INTO er1_retry_queue (entry_id, transcript_path, audio_path, image_path, tags, status, attempts, max_attempts, created_at, updated_at, next_retry_at)
		VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)
	`, entryID, transcriptPath, audioPath, imagePath, tags, RetryStatusPending, maxAttempts, now, now, now)
	if err != nil {
		return nil, fmt.Errorf("insert retry entry: %w", err)
	}

	id, _ := res.LastInsertId()
	ts, _ := time.Parse(time.RFC3339, now)
	return &RetryEntry{
		ID:             id,
		EntryID:        entryID,
		TranscriptPath: transcriptPath,
		AudioPath:      audioPath,
		ImagePath:      imagePath,
		Tags:           tags,
		Status:         RetryStatusPending,
		Attempts:       0,
		MaxAttempts:    maxAttempts,
		CreatedAt:      ts,
		UpdatedAt:      ts,
		NextRetryAt:    ts,
	}, nil
}

// QueryPending returns entries that are eligible for retry: status is "pending"
// or "retrying", and next_retry_at <= now. Results are ordered by next_retry_at ASC
// (oldest first) with an optional limit.
func (q *RetryQueueDB) QueryPending(limit int) ([]RetryEntry, error) {
	if limit <= 0 {
		limit = 50
	}
	now := time.Now().UTC().Format(time.RFC3339)

	rows, err := q.db.Query(`
		SELECT id, entry_id, transcript_path, audio_path, image_path, tags,
		       status, attempts, max_attempts, last_error, created_at, updated_at, next_retry_at
		FROM er1_retry_queue
		WHERE status IN (?, ?) AND next_retry_at <= ?
		ORDER BY next_retry_at ASC
		LIMIT ?
	`, RetryStatusPending, RetryStatusRetrying, now, limit)
	if err != nil {
		return nil, fmt.Errorf("query pending: %w", err)
	}
	defer rows.Close()

	return scanRetryRows(rows)
}

// UpdateAttempt increments the attempt counter, records the error, and
// schedules the next retry using exponential backoff. If max_attempts is
// exceeded, the status is set to "failed" (permanent failure).
func (q *RetryQueueDB) UpdateAttempt(entryID string, retryErr error) (*RetryEntry, error) {
	// First fetch current state.
	entry, err := q.GetByEntryID(entryID)
	if err != nil {
		return nil, fmt.Errorf("get entry for update: %w", err)
	}
	if entry == nil {
		return nil, fmt.Errorf("entry not found: %s", entryID)
	}

	newAttempts := entry.Attempts + 1
	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)

	var errMsg string
	if retryErr != nil {
		errMsg = retryErr.Error()
	}

	var newStatus string
	var nextRetryAt time.Time

	if newAttempts >= entry.MaxAttempts {
		// Permanently failed — exceeded max attempts.
		newStatus = RetryStatusFailed
		nextRetryAt = now // won't be retried
	} else {
		// Schedule next retry with exponential backoff.
		newStatus = RetryStatusRetrying
		backoff := q.CalculateBackoff(newAttempts - 1)
		nextRetryAt = now.Add(backoff)
	}

	nextRetryStr := nextRetryAt.Format(time.RFC3339)

	_, err = q.db.Exec(`
		UPDATE er1_retry_queue
		SET attempts = ?, status = ?, last_error = ?, updated_at = ?, next_retry_at = ?
		WHERE entry_id = ?
	`, newAttempts, newStatus, errMsg, nowStr, nextRetryStr, entryID)
	if err != nil {
		return nil, fmt.Errorf("update attempt: %w", err)
	}

	entry.Attempts = newAttempts
	entry.Status = newStatus
	entry.LastError = errMsg
	entry.UpdatedAt = now
	entry.NextRetryAt = nextRetryAt
	return entry, nil
}

// MarkComplete sets the status to "completed" for a given entry_id.
func (q *RetryQueueDB) MarkComplete(entryID string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	result, err := q.db.Exec(`
		UPDATE er1_retry_queue SET status = ?, updated_at = ? WHERE entry_id = ?
	`, RetryStatusCompleted, now, entryID)
	if err != nil {
		return fmt.Errorf("mark complete: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("entry not found: %s", entryID)
	}
	return nil
}

// GetByEntryID returns a single retry entry by its entry_id, or nil if not found.
func (q *RetryQueueDB) GetByEntryID(entryID string) (*RetryEntry, error) {
	row := q.db.QueryRow(`
		SELECT id, entry_id, transcript_path, audio_path, image_path, tags,
		       status, attempts, max_attempts, last_error, created_at, updated_at, next_retry_at
		FROM er1_retry_queue WHERE entry_id = ?
	`, entryID)
	return scanRetryRow(row)
}

// SetStatus sets the status of a retry entry by entry_id.
func (q *RetryQueueDB) SetStatus(entryID, status string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	result, err := q.db.Exec(`
		UPDATE er1_retry_queue SET status = ?, updated_at = ? WHERE entry_id = ?
	`, status, now, entryID)
	if err != nil {
		return fmt.Errorf("set status: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("entry not found: %s", entryID)
	}
	return nil
}

// CountByStatus returns the number of retry entries with the given status.
func (q *RetryQueueDB) CountByStatus(status string) (int, error) {
	var count int
	err := q.db.QueryRow(`SELECT COUNT(*) FROM er1_retry_queue WHERE status = ?`, status).Scan(&count)
	return count, err
}

// ListAll returns all retry entries ordered by created_at descending.
func (q *RetryQueueDB) ListAll(limit int) ([]RetryEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := q.db.Query(`
		SELECT id, entry_id, transcript_path, audio_path, image_path, tags,
		       status, attempts, max_attempts, last_error, created_at, updated_at, next_retry_at
		FROM er1_retry_queue
		ORDER BY created_at DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanRetryRows(rows)
}

// RemoveCompleted deletes all entries with status "completed". Returns the
// number of rows deleted.
func (q *RetryQueueDB) RemoveCompleted() (int64, error) {
	result, err := q.db.Exec(`DELETE FROM er1_retry_queue WHERE status = ?`, RetryStatusCompleted)
	if err != nil {
		return 0, fmt.Errorf("remove completed: %w", err)
	}
	return result.RowsAffected()
}

func scanRetryRow(row *sql.Row) (*RetryEntry, error) {
	var r RetryEntry
	var audioPath, imagePath, lastError sql.NullString
	var createdAt, updatedAt, nextRetryAt string

	err := row.Scan(&r.ID, &r.EntryID, &r.TranscriptPath, &audioPath, &imagePath,
		&r.Tags, &r.Status, &r.Attempts, &r.MaxAttempts, &lastError,
		&createdAt, &updatedAt, &nextRetryAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if audioPath.Valid {
		r.AudioPath = audioPath.String
	}
	if imagePath.Valid {
		r.ImagePath = imagePath.String
	}
	if lastError.Valid {
		r.LastError = lastError.String
	}
	r.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	r.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	r.NextRetryAt, _ = time.Parse(time.RFC3339, nextRetryAt)
	return &r, nil
}

func scanRetryRows(rows *sql.Rows) ([]RetryEntry, error) {
	var entries []RetryEntry
	for rows.Next() {
		var r RetryEntry
		var audioPath, imagePath, lastError sql.NullString
		var createdAt, updatedAt, nextRetryAt string

		if err := rows.Scan(&r.ID, &r.EntryID, &r.TranscriptPath, &audioPath, &imagePath,
			&r.Tags, &r.Status, &r.Attempts, &r.MaxAttempts, &lastError,
			&createdAt, &updatedAt, &nextRetryAt); err != nil {
			return nil, err
		}

		if audioPath.Valid {
			r.AudioPath = audioPath.String
		}
		if imagePath.Valid {
			r.ImagePath = imagePath.String
		}
		if lastError.Valid {
			r.LastError = lastError.String
		}
		r.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		r.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
		r.NextRetryAt, _ = time.Parse(time.RFC3339, nextRetryAt)
		entries = append(entries, r)
	}
	return entries, rows.Err()
}
