// Package store owns the engine's local SQLite state.
//
// Scope (SPEC-0167 §Service Components, `internal/store`):
//   - processes       — process registry + snapshot for idempotency/dedup
//   - sse_subscribers — connected SSE clients and their cursors
//   - budget_counters — D4 per-day-per-user USD spend tracking
//
// NOT a source of truth for T/R/I/A — all cognitive data lives in
// Kafka + ER1. This store is engine-local operational state only.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/kamir/m3c-tools/internal/dbdriver"
	"github.com/kamir/m3c-tools/internal/thinking/schema"
)

// ProcessState mirrors the API enum.
type ProcessState string

const (
	StatePending   ProcessState = "pending"
	StateRunning   ProcessState = "running"
	StateCompleted ProcessState = "completed"
	StateFailed    ProcessState = "failed"
	StateCancelled ProcessState = "cancelled"
)

// ProcessRow is the persistent projection of an in-flight process.
type ProcessRow struct {
	ProcessID    string
	State        ProcessState
	CurrentStep  string
	StepIndex    int // last step known to have completed; -1 means "none yet"
	IterationIdx int // loop-mode iteration counter (D6 — Week 3 loop cap)
	ArtifactIDs  []string
	SpecJSON     []byte
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// Store is a small facade over the SQLite tables. Concurrency-safe
// because SQLite serializes writes; reads use a separate pool.
type Store struct {
	db *sql.DB
}

// Open initializes (and migrates) a store at path. Path can be
// ":memory:" for tests. Uses the project's dbdriver package so cgo
// and nocgo builds both work.
//
// When path is the bare ":memory:" sentinel we pin MaxOpenConns=1
// because SQLite allocates a *fresh* anonymous database per connection
// in that mode; a pool would hand consumers an empty DB missing the
// migration schema.
func Open(path string) (*Store, error) {
	db, err := sql.Open(dbdriver.DriverName(), path)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	if path == ":memory:" {
		db.SetMaxOpenConns(1)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the DB handle.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS processes (
			process_id    TEXT PRIMARY KEY,
			state         TEXT NOT NULL,
			current_step  TEXT NOT NULL DEFAULT '',
			step_index    INTEGER NOT NULL DEFAULT -1,
			iteration_idx INTEGER NOT NULL DEFAULT 0,
			artifact_ids  TEXT NOT NULL DEFAULT '[]',
			spec_json     BLOB NOT NULL,
			created_at    TIMESTAMP NOT NULL,
			updated_at    TIMESTAMP NOT NULL
		)`,
		// Week 3 — feedback loop rate limiting (10/hour per user).
		// Keyed by hour bucket (UTC RFC3339 truncated to hour) so the
		// table stays small and we can reset counters by age.
		`CREATE TABLE IF NOT EXISTS feedback_counters (
			hour_utc      TEXT PRIMARY KEY,
			count         INTEGER NOT NULL DEFAULT 0,
			updated_at    TIMESTAMP NOT NULL
		)`,
		// Generic keyed hourly rate limiter table used by the
		// autoreflect consumer (internal/thinking/ratelimit). Shape
		// is the feedback_counters table plus a "key" column so a
		// single table can host many named limiters.
		`CREATE TABLE IF NOT EXISTS hourly_rate_counters (
			key           TEXT NOT NULL,
			hour_utc      TEXT NOT NULL,
			count         INTEGER NOT NULL DEFAULT 0,
			updated_at    TIMESTAMP NOT NULL,
			PRIMARY KEY (key, hour_utc)
		)`,
		// Auto-reflect dedup ledger. See
		// internal/thinking/autoreflect for semantics.
		`CREATE TABLE IF NOT EXISTS autoreflect_fires (
			hash             TEXT PRIMARY KEY,
			window_start_ms  INTEGER NOT NULL,
			window_end_ms    INTEGER NOT NULL,
			process_id       TEXT NOT NULL,
			fired_at_ms      INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_autoreflect_fires_fired_at ON autoreflect_fires(fired_at_ms)`,
		`CREATE TABLE IF NOT EXISTS sse_subscribers (
			subscriber_id TEXT PRIMARY KEY,
			process_id    TEXT NOT NULL,
			cursor        INTEGER NOT NULL DEFAULT 0,
			connected_at  TIMESTAMP NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS budget_counters (
			day_utc       TEXT PRIMARY KEY,
			tokens_total  INTEGER NOT NULL DEFAULT 0,
			cost_usd      REAL    NOT NULL DEFAULT 0.0,
			updated_at    TIMESTAMP NOT NULL
		)`,
		// D1 — ETag-mirrored prompt cache. Survives engine restarts.
		`CREATE TABLE IF NOT EXISTS prompt_cache (
			prompt_id    TEXT PRIMARY KEY,
			version      INTEGER NOT NULL DEFAULT 0,
			body         TEXT NOT NULL DEFAULT '',
			model        TEXT NOT NULL DEFAULT '',
			etag         TEXT NOT NULL DEFAULT '',
			fetched_at   TIMESTAMP NOT NULL
		)`,
		// Consumer-side read cache mirror. Lets /v1/{thoughts,reflections,
		// insights,artifacts} serve data after a cold start without
		// re-consuming the full Kafka log. "layer" ∈ {T, R, I, A}.
		`CREATE TABLE IF NOT EXISTS msg_cache (
			id           TEXT NOT NULL,
			layer        TEXT NOT NULL,
			payload      BLOB NOT NULL,
			timestamp    TIMESTAMP NOT NULL,
			parent_ids   TEXT NOT NULL DEFAULT '[]',
			PRIMARY KEY (layer, id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_msg_cache_layer_ts ON msg_cache(layer, timestamp DESC)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("store: migrate: %w", err)
		}
	}
	return nil
}

// InsertProcess creates a row in `processes` for an accepted spec.
func (s *Store) InsertProcess(spec schema.ProcessSpec) error {
	b, err := json.Marshal(spec)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	_, err = s.db.Exec(
		`INSERT INTO processes(process_id, state, current_step, step_index, iteration_idx, artifact_ids, spec_json, created_at, updated_at)
		 VALUES (?, ?, '', -1, 0, '[]', ?, ?, ?)`,
		spec.ProcessID, string(StatePending), b, now, now,
	)
	return err
}

// UpdateState transitions state and optionally current_step.
func (s *Store) UpdateState(processID string, state ProcessState, currentStep string) error {
	_, err := s.db.Exec(
		`UPDATE processes SET state=?, current_step=?, updated_at=? WHERE process_id=?`,
		string(state), currentStep, time.Now().UTC(), processID,
	)
	return err
}

// AppendArtifact appends an artifact_id to the process row.
func (s *Store) AppendArtifact(processID, artifactID string) error {
	row := s.db.QueryRow(`SELECT artifact_ids FROM processes WHERE process_id=?`, processID)
	var blob string
	if err := row.Scan(&blob); err != nil {
		return err
	}
	var ids []string
	if err := json.Unmarshal([]byte(blob), &ids); err != nil {
		ids = nil
	}
	ids = append(ids, artifactID)
	nb, _ := json.Marshal(ids)
	_, err := s.db.Exec(
		`UPDATE processes SET artifact_ids=?, updated_at=? WHERE process_id=?`,
		string(nb), time.Now().UTC(), processID,
	)
	return err
}

// GetProcess returns the current row for a process.
func (s *Store) GetProcess(processID string) (ProcessRow, error) {
	row := s.db.QueryRow(
		`SELECT process_id, state, current_step, step_index, iteration_idx, artifact_ids, spec_json, created_at, updated_at
		 FROM processes WHERE process_id=?`, processID,
	)
	var r ProcessRow
	var state, blob string
	if err := row.Scan(&r.ProcessID, &state, &r.CurrentStep, &r.StepIndex, &r.IterationIdx, &blob, &r.SpecJSON, &r.CreatedAt, &r.UpdatedAt); err != nil {
		return ProcessRow{}, err
	}
	r.State = ProcessState(state)
	_ = json.Unmarshal([]byte(blob), &r.ArtifactIDs)
	return r, nil
}

// AdvanceStepIndex atomically bumps the highest-completed step index
// only when newIdx is strictly greater than the stored value. Returns
// the effective index after the update (which may equal the existing
// value if newIdx did not advance).
//
// Used by the semi_linear orchestrator to guard against out-of-order
// StepCompleted events racing each other. Returns an error only on DB
// failure.
func (s *Store) AdvanceStepIndex(processID string, newIdx int) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	var cur int
	if err := tx.QueryRow(`SELECT step_index FROM processes WHERE process_id=?`, processID).Scan(&cur); err != nil {
		return 0, err
	}
	if newIdx <= cur {
		// Nothing to do; still commit the read-only tx for cleanliness.
		_ = tx.Commit()
		return cur, nil
	}
	if _, err := tx.Exec(
		`UPDATE processes SET step_index=?, updated_at=? WHERE process_id=?`,
		newIdx, time.Now().UTC(), processID,
	); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return newIdx, nil
}

// IncrementIteration bumps loop-mode iteration counter and returns the
// new value. Used by the orchestrator's loop mode to enforce
// max_iterations (Week 3, SPEC-0167 §ProcessSpec.mode=loop).
func (s *Store) IncrementIteration(processID string) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	var cur int
	if err := tx.QueryRow(`SELECT iteration_idx FROM processes WHERE process_id=?`, processID).Scan(&cur); err != nil {
		return 0, err
	}
	cur++
	if _, err := tx.Exec(
		`UPDATE processes SET iteration_idx=?, updated_at=? WHERE process_id=?`,
		cur, time.Now().UTC(), processID,
	); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return cur, nil
}

// IncrementFeedbackCounter atomically increments the feedback
// rate-limit counter for the current UTC hour bucket. Returns the
// post-increment value so the caller can compare against the cap
// (SPEC-0167 §Stream 3a — 10/hour).
func (s *Store) IncrementFeedbackCounter() (int, error) {
	hour := time.Now().UTC().Format("2006-01-02T15")
	now := time.Now().UTC()
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(
		`INSERT INTO feedback_counters(hour_utc, count, updated_at)
		 VALUES(?, 1, ?)
		 ON CONFLICT(hour_utc) DO UPDATE SET
		   count = count + 1,
		   updated_at = excluded.updated_at`,
		hour, now,
	); err != nil {
		return 0, err
	}
	var count int
	if err := tx.QueryRow(`SELECT count FROM feedback_counters WHERE hour_utc=?`, hour).Scan(&count); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return count, nil
}

// GetFeedbackCounter returns the current count for the UTC hour bucket.
func (s *Store) GetFeedbackCounter() (int, error) {
	hour := time.Now().UTC().Format("2006-01-02T15")
	row := s.db.QueryRow(`SELECT count FROM feedback_counters WHERE hour_utc=?`, hour)
	var count int
	if err := row.Scan(&count); err != nil {
		if err == sql.ErrNoRows {
			return 0, nil
		}
		return 0, err
	}
	return count, nil
}

// AddBudgetSpend increments today's counters atomically.
func (s *Store) AddBudgetSpend(tokens int, costUSD float64) error {
	day := time.Now().UTC().Format("2006-01-02")
	now := time.Now().UTC()
	_, err := s.db.Exec(
		`INSERT INTO budget_counters(day_utc, tokens_total, cost_usd, updated_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(day_utc) DO UPDATE SET
		   tokens_total = tokens_total + excluded.tokens_total,
		   cost_usd     = cost_usd     + excluded.cost_usd,
		   updated_at   = excluded.updated_at`,
		day, tokens, costUSD, now,
	)
	return err
}

// GetBudgetSpend returns tokens and USD spent today (UTC day bucket).
func (s *Store) GetBudgetSpend() (tokens int, costUSD float64, err error) {
	day := time.Now().UTC().Format("2006-01-02")
	row := s.db.QueryRow(`SELECT tokens_total, cost_usd FROM budget_counters WHERE day_utc=?`, day)
	if err := row.Scan(&tokens, &costUSD); err != nil {
		if err == sql.ErrNoRows {
			return 0, 0.0, nil
		}
		return 0, 0, err
	}
	return tokens, costUSD, nil
}

// PromptCacheRow mirrors one row of the prompt_cache table.
type PromptCacheRow struct {
	ID        string
	Version   int
	Body      string
	Model     string
	ETag      string
	FetchedAt time.Time
}

// UpsertPromptCache writes one prompt entry (insert-or-update).
func (s *Store) UpsertPromptCache(row PromptCacheRow) error {
	_, err := s.db.Exec(
		`INSERT INTO prompt_cache(prompt_id, version, body, model, etag, fetched_at)
		 VALUES(?, ?, ?, ?, ?, ?)
		 ON CONFLICT(prompt_id) DO UPDATE SET
		   version=excluded.version,
		   body=excluded.body,
		   model=excluded.model,
		   etag=excluded.etag,
		   fetched_at=excluded.fetched_at`,
		row.ID, row.Version, row.Body, row.Model, row.ETag, row.FetchedAt,
	)
	return err
}

// LoadPromptCache returns all cached prompt rows (used to warm the
// in-memory registry cache on startup).
func (s *Store) LoadPromptCache() ([]PromptCacheRow, error) {
	rows, err := s.db.Query(
		`SELECT prompt_id, version, body, model, etag, fetched_at FROM prompt_cache`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PromptCacheRow
	for rows.Next() {
		var r PromptCacheRow
		if err := rows.Scan(&r.ID, &r.Version, &r.Body, &r.Model, &r.ETag, &r.FetchedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// MsgCacheRow is one mirrored message (T/R/I/A).
type MsgCacheRow struct {
	ID        string
	Layer     string // "T" | "R" | "I" | "A"
	Payload   []byte // raw JSON
	Timestamp time.Time
	ParentIDs []string // denormalized for fast filter queries (e.g. R.thought_ids, I.input_ids)
}

// UpsertMsgCache inserts or updates a mirrored message.
func (s *Store) UpsertMsgCache(row MsgCacheRow) error {
	parents, _ := json.Marshal(row.ParentIDs)
	if parents == nil {
		parents = []byte("[]")
	}
	_, err := s.db.Exec(
		`INSERT INTO msg_cache(id, layer, payload, timestamp, parent_ids)
		 VALUES(?, ?, ?, ?, ?)
		 ON CONFLICT(layer, id) DO UPDATE SET
		   payload=excluded.payload,
		   timestamp=excluded.timestamp,
		   parent_ids=excluded.parent_ids`,
		row.ID, row.Layer, row.Payload, row.Timestamp, string(parents),
	)
	return err
}

// ListMsgCache returns messages for one layer, newest first, optionally
// filtered by minTimestamp and parent id (e.g. thought_id to get Rs).
// limit 0 means "no limit"; we cap implicitly at 1000 to prevent
// runaway queries.
func (s *Store) ListMsgCache(layer string, since time.Time, parentID string, limit int) ([]MsgCacheRow, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	q := `SELECT id, layer, payload, timestamp, parent_ids FROM msg_cache WHERE layer=?`
	args := []interface{}{layer}
	if !since.IsZero() {
		q += ` AND timestamp >= ?`
		args = append(args, since)
	}
	if parentID != "" {
		// parent_ids is a JSON array; LIKE is cheap + good enough here.
		q += ` AND parent_ids LIKE ?`
		args = append(args, "%\""+parentID+"\"%")
	}
	q += ` ORDER BY timestamp DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MsgCacheRow
	for rows.Next() {
		var r MsgCacheRow
		var parents string
		if err := rows.Scan(&r.ID, &r.Layer, &r.Payload, &r.Timestamp, &parents); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(parents), &r.ParentIDs)
		out = append(out, r)
	}
	return out, rows.Err()
}

// ----- Generic hourly rate limiter (internal/thinking/ratelimit) -----

// IncrementHourlyCounter atomically bumps the counter for (key,
// current UTC hour) and returns the post-increment value. Used by
// the generic ratelimit package so multiple features can share one
// SQLite table without trampling feedback_counters.
func (s *Store) IncrementHourlyCounter(key string) (int, error) {
	hour := time.Now().UTC().Format("2006-01-02T15")
	now := time.Now().UTC()
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(
		`INSERT INTO hourly_rate_counters(key, hour_utc, count, updated_at)
		 VALUES(?, ?, 1, ?)
		 ON CONFLICT(key, hour_utc) DO UPDATE SET
		   count = count + 1,
		   updated_at = excluded.updated_at`,
		key, hour, now,
	); err != nil {
		return 0, err
	}
	var count int
	if err := tx.QueryRow(
		`SELECT count FROM hourly_rate_counters WHERE key=? AND hour_utc=?`, key, hour,
	).Scan(&count); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return count, nil
}

// ----- Auto-reflect dedup ledger -----

// AutoReflectFireRow mirrors one row of autoreflect_fires.
type AutoReflectFireRow struct {
	Hash          string
	WindowStartMs int64
	WindowEndMs   int64
	ProcessID     string
	FiredAtMs     int64
}

// RecordAutoReflectFire upserts a dedup ledger entry.
func (s *Store) RecordAutoReflectFire(row AutoReflectFireRow) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO autoreflect_fires(hash, window_start_ms, window_end_ms, process_id, fired_at_ms)
		 VALUES(?, ?, ?, ?, ?)`,
		row.Hash, row.WindowStartMs, row.WindowEndMs, row.ProcessID, row.FiredAtMs,
	)
	return err
}

// RecentAutoReflectFire returns the fired_at_ms of the most recent
// row with the given hash whose fired_at_ms is ≥ sinceMs. The
// boolean is false iff no such row exists.
func (s *Store) RecentAutoReflectFire(hash string, sinceMs int64) (int64, bool, error) {
	row := s.db.QueryRow(
		`SELECT fired_at_ms FROM autoreflect_fires WHERE hash=? AND fired_at_ms >= ?`,
		hash, sinceMs,
	)
	var firedAt int64
	if err := row.Scan(&firedAt); err != nil {
		if err == sql.ErrNoRows {
			return 0, false, nil
		}
		return 0, false, err
	}
	return firedAt, true, nil
}

// CleanAutoReflectFires deletes rows older than cutoffMs. Returns the
// number of rows removed.
func (s *Store) CleanAutoReflectFires(cutoffMs int64) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM autoreflect_fires WHERE fired_at_ms < ?`, cutoffMs)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}
