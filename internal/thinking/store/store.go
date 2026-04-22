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
	ProcessID   string
	State       ProcessState
	CurrentStep string
	ArtifactIDs []string
	SpecJSON    []byte
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Store is a small facade over the SQLite tables. Concurrency-safe
// because SQLite serializes writes; reads use a separate pool.
type Store struct {
	db *sql.DB
}

// Open initializes (and migrates) a store at path. Path can be
// ":memory:" for tests. Uses the project's dbdriver package so cgo
// and nocgo builds both work.
func Open(path string) (*Store, error) {
	db, err := sql.Open(dbdriver.DriverName(), path)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
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
			artifact_ids  TEXT NOT NULL DEFAULT '[]',
			spec_json     BLOB NOT NULL,
			created_at    TIMESTAMP NOT NULL,
			updated_at    TIMESTAMP NOT NULL
		)`,
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
		`INSERT INTO processes(process_id, state, current_step, artifact_ids, spec_json, created_at, updated_at)
		 VALUES (?, ?, '', '[]', ?, ?, ?)`,
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
		`SELECT process_id, state, current_step, artifact_ids, spec_json, created_at, updated_at
		 FROM processes WHERE process_id=?`, processID,
	)
	var r ProcessRow
	var state, blob string
	if err := row.Scan(&r.ProcessID, &state, &r.CurrentStep, &blob, &r.SpecJSON, &r.CreatedAt, &r.UpdatedAt); err != nil {
		return ProcessRow{}, err
	}
	r.State = ProcessState(state)
	_ = json.Unmarshal([]byte(blob), &r.ArtifactIDs)
	return r, nil
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
