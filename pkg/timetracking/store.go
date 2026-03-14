// Package timetracking provides local time tracking for PLM project contexts.
// It stores activation/deactivation events in a SQLite database and manages
// per-project auto-expiry timers. Events are synced to ER1 asynchronously.
package timetracking

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kamir/m3c-tools/internal/dbdriver"
)

// DefaultDBPath returns the default path for the time tracking database.
func DefaultDBPath() string {
	if v := os.Getenv("M3C_TIMETRACKING_DB"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".m3c-tools", "timetracking.db")
	}
	return filepath.Join(home, ".m3c-tools", "timetracking.db")
}

// Store provides thread-safe access to the local time tracking SQLite database.
type Store struct {
	mu sync.Mutex
	db *sql.DB
}

// OpenStore opens or creates the time tracking database at the given path.
func OpenStore(dbPath string) (*Store, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}

	db, err := sql.Open(dbdriver.DriverName(), dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS projects (
			project_id TEXT PRIMARY KEY,
			name       TEXT NOT NULL,
			client     TEXT,
			status     TEXT,
			updated_at TEXT,
			cached_at  TEXT NOT NULL
		);
	`)
	if err != nil {
		return err
	}

	// Add tags column (safe to call multiple times — ignore "duplicate column" error).
	s.db.Exec("ALTER TABLE projects ADD COLUMN tags TEXT DEFAULT ''")

	_, err = s.db.Exec(`
		CREATE TABLE IF NOT EXISTS events (
			event_id     TEXT PRIMARY KEY,
			project_id   TEXT NOT NULL,
			project_name TEXT NOT NULL,
			event_type   TEXT NOT NULL CHECK(event_type IN ('activate', 'deactivate')),
			timestamp    TEXT NOT NULL,
			trigger_type TEXT NOT NULL,
			duration_sec INTEGER,
			content_ref  TEXT,
			synced       INTEGER NOT NULL DEFAULT 0,
			FOREIGN KEY (project_id) REFERENCES projects(project_id)
		);

		CREATE TABLE IF NOT EXISTS active_contexts (
			project_id   TEXT PRIMARY KEY,
			project_name TEXT NOT NULL,
			activated_at TEXT NOT NULL,
			expires_at   TEXT NOT NULL
		);

		CREATE INDEX IF NOT EXISTS idx_events_project_ts ON events(project_id, timestamp);
		CREATE INDEX IF NOT EXISTS idx_events_synced ON events(synced) WHERE synced = 0;

		CREATE TABLE IF NOT EXISTS observations (
			obs_id    TEXT PRIMARY KEY,
			timestamp TEXT NOT NULL,
			tags      TEXT NOT NULL,
			doc_id    TEXT NOT NULL,
			obs_type  TEXT NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_observations_ts ON observations(timestamp);
	`)
	return err
}

// CachedProject represents a project cached from the PLM API.
type CachedProject struct {
	ProjectID string
	Name      string
	Client    string
	Status    string
	Tags      string // comma-separated tags from PLM
	UpdatedAt time.Time
	CachedAt  time.Time
}

// Event represents a context switch event (activation or deactivation).
type Event struct {
	EventID     string
	ProjectID   string
	ProjectName string
	EventType   string // "activate" or "deactivate"
	Timestamp   time.Time
	Trigger     string // "user", "auto_expiry", "app_quit", "crash_recovery"
	DurationSec *int
	ContentRef  string
	Synced      bool
}

// ActiveContext represents a currently active project context.
type ActiveContext struct {
	ProjectID   string
	ProjectName string
	ActivatedAt time.Time
	ExpiresAt   time.Time
}

// UpsertProjects replaces the cached project list.
func (s *Store) UpsertProjects(projects []CachedProject) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.Exec("DELETE FROM projects")
	if err != nil {
		return err
	}

	stmt, err := tx.Prepare(`INSERT INTO projects (project_id, name, client, status, updated_at, cached_at, tags)
		VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	now := time.Now().UTC().Format(time.RFC3339)
	for _, p := range projects {
		_, err = stmt.Exec(p.ProjectID, p.Name, p.Client, p.Status,
			p.UpdatedAt.UTC().Format(time.RFC3339), now, p.Tags)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListProjects returns cached projects sorted by updated_at descending.
func (s *Store) ListProjects() ([]CachedProject, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query(`SELECT project_id, name, client, status, updated_at, cached_at, COALESCE(tags, '')
		FROM projects ORDER BY updated_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []CachedProject
	for rows.Next() {
		var p CachedProject
		var updatedAt, cachedAt string
		if err := rows.Scan(&p.ProjectID, &p.Name, &p.Client, &p.Status, &updatedAt, &cachedAt, &p.Tags); err != nil {
			return nil, err
		}
		p.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
		p.CachedAt, _ = time.Parse(time.RFC3339, cachedAt)
		result = append(result, p)
	}
	return result, rows.Err()
}

// ProjectsCacheAge returns how old the cached project list is, or -1 if empty.
func (s *Store) ProjectsCacheAge() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()

	var cachedAt string
	err := s.db.QueryRow("SELECT cached_at FROM projects LIMIT 1").Scan(&cachedAt)
	if err != nil {
		return -1
	}
	t, err := time.Parse(time.RFC3339, cachedAt)
	if err != nil {
		return -1
	}
	return time.Since(t)
}

// InsertEvent records a context switch event.
func (s *Store) InsertEvent(e Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var durSec *int
	if e.DurationSec != nil {
		durSec = e.DurationSec
	}

	_, err := s.db.Exec(`INSERT INTO events (event_id, project_id, project_name, event_type, timestamp, trigger_type, duration_sec, content_ref, synced)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.EventID, e.ProjectID, e.ProjectName, e.EventType,
		e.Timestamp.UTC().Format(time.RFC3339), e.Trigger,
		durSec, e.ContentRef, boolToInt(e.Synced))
	return err
}

// ListEvents returns events for a project in a time range, ordered by timestamp.
func (s *Store) ListEvents(projectID string, from, to time.Time) ([]Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query(`SELECT event_id, project_id, project_name, event_type, timestamp, trigger_type, duration_sec, content_ref, synced
		FROM events WHERE project_id = ? AND timestamp >= ? AND timestamp <= ?
		ORDER BY timestamp ASC`,
		projectID, from.UTC().Format(time.RFC3339), to.UTC().Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

// ListAllEvents returns all events in a time range across all projects.
func (s *Store) ListAllEvents(from, to time.Time) ([]Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query(`SELECT event_id, project_id, project_name, event_type, timestamp, trigger_type, duration_sec, content_ref, synced
		FROM events WHERE timestamp >= ? AND timestamp <= ?
		ORDER BY timestamp ASC`,
		from.UTC().Format(time.RFC3339), to.UTC().Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

// UnsyncedEvents returns events not yet synced to ER1.
func (s *Store) UnsyncedEvents() ([]Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query(`SELECT event_id, project_id, project_name, event_type, timestamp, trigger_type, duration_sec, content_ref, synced
		FROM events WHERE synced = 0 ORDER BY timestamp ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

// MarkSynced marks an event as synced to ER1.
func (s *Store) MarkSynced(eventID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec("UPDATE events SET synced = 1 WHERE event_id = ?", eventID)
	return err
}

// SetActiveContext records a project as currently active.
func (s *Store) SetActiveContext(ctx ActiveContext) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`INSERT OR REPLACE INTO active_contexts (project_id, project_name, activated_at, expires_at)
		VALUES (?, ?, ?, ?)`,
		ctx.ProjectID, ctx.ProjectName,
		ctx.ActivatedAt.UTC().Format(time.RFC3339),
		ctx.ExpiresAt.UTC().Format(time.RFC3339))
	return err
}

// RemoveActiveContext removes a project from active contexts.
func (s *Store) RemoveActiveContext(projectID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec("DELETE FROM active_contexts WHERE project_id = ?", projectID)
	return err
}

// ListActiveContexts returns all currently active project contexts.
func (s *Store) ListActiveContexts() ([]ActiveContext, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query(`SELECT project_id, project_name, activated_at, expires_at FROM active_contexts`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []ActiveContext
	for rows.Next() {
		var c ActiveContext
		var activatedAt, expiresAt string
		if err := rows.Scan(&c.ProjectID, &c.ProjectName, &activatedAt, &expiresAt); err != nil {
			return nil, err
		}
		c.ActivatedAt, _ = time.Parse(time.RFC3339, activatedAt)
		c.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAt)
		result = append(result, c)
	}
	return result, rows.Err()
}

// PruneOldEvents deletes events older than the given retention period.
func (s *Store) PruneOldEvents(retention time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-retention).UTC().Format(time.RFC3339)
	res, err := s.db.Exec("DELETE FROM events WHERE timestamp < ? AND synced = 1", cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Observation records an uploaded observation for reverse tracking replay.
type Observation struct {
	ObsID     string
	Timestamp time.Time
	Tags      string
	DocID     string
	ObsType   string // "progress", "idea", "impulse", "import"
}

// RecordObservation inserts an observation into the local log.
func (s *Store) RecordObservation(obs Observation) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`INSERT OR IGNORE INTO observations (obs_id, timestamp, tags, doc_id, obs_type)
		VALUES (?, ?, ?, ?, ?)`,
		obs.ObsID, obs.Timestamp.UTC().Format(time.RFC3339), obs.Tags, obs.DocID, obs.ObsType)
	return err
}

// ListObservations returns observations in a time range, ordered by timestamp.
func (s *Store) ListObservations(from, to time.Time) ([]Observation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query(`SELECT obs_id, timestamp, tags, doc_id, obs_type
		FROM observations WHERE timestamp >= ? AND timestamp <= ?
		ORDER BY timestamp ASC`,
		from.UTC().Format(time.RFC3339), to.UTC().Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []Observation
	for rows.Next() {
		var o Observation
		var ts string
		if err := rows.Scan(&o.ObsID, &ts, &o.Tags, &o.DocID, &o.ObsType); err != nil {
			return nil, err
		}
		o.Timestamp, _ = time.Parse(time.RFC3339, ts)
		result = append(result, o)
	}
	return result, rows.Err()
}

// SessionSummary holds aggregated time for one project over a period.
type SessionSummary struct {
	ProjectID    string
	ProjectName  string
	TotalSeconds int
	SessionCount int
	LastActive   time.Time
}

// Summarize computes per-project time totals from events in the given range.
func (s *Store) Summarize(from, to time.Time) ([]SessionSummary, error) {
	events, err := s.ListAllEvents(from, to)
	if err != nil {
		return nil, err
	}

	// Track open activations per project.
	type openSession struct {
		activatedAt time.Time
	}
	open := make(map[string]*openSession)
	summaries := make(map[string]*SessionSummary)

	for _, e := range events {
		if _, ok := summaries[e.ProjectID]; !ok {
			summaries[e.ProjectID] = &SessionSummary{
				ProjectID:   e.ProjectID,
				ProjectName: e.ProjectName,
			}
		}
		sm := summaries[e.ProjectID]

		switch e.EventType {
		case "activate":
			open[e.ProjectID] = &openSession{activatedAt: e.Timestamp}
		case "deactivate":
			dur := 0
			if e.DurationSec != nil {
				dur = *e.DurationSec
			} else if o, ok := open[e.ProjectID]; ok {
				dur = int(e.Timestamp.Sub(o.activatedAt).Seconds())
			}
			sm.TotalSeconds += dur
			sm.SessionCount++
			if e.Timestamp.After(sm.LastActive) {
				sm.LastActive = e.Timestamp
			}
			delete(open, e.ProjectID)
		}
	}

	// Count still-open sessions (ongoing at "to" time).
	now := time.Now().UTC()
	if to.After(now) {
		to = now
	}
	for pid, o := range open {
		sm := summaries[pid]
		dur := int(to.Sub(o.activatedAt).Seconds())
		sm.TotalSeconds += dur
		sm.SessionCount++
		if to.After(sm.LastActive) {
			sm.LastActive = to
		}
	}

	var result []SessionSummary
	for _, sm := range summaries {
		result = append(result, *sm)
	}
	return result, nil
}

func scanEvents(rows *sql.Rows) ([]Event, error) {
	var result []Event
	for rows.Next() {
		var e Event
		var ts string
		var durSec *int
		var synced int
		if err := rows.Scan(&e.EventID, &e.ProjectID, &e.ProjectName, &e.EventType,
			&ts, &e.Trigger, &durSec, &e.ContentRef, &synced); err != nil {
			return nil, err
		}
		e.Timestamp, _ = time.Parse(time.RFC3339, ts)
		e.DurationSec = durSec
		e.Synced = synced == 1
		result = append(result, e)
	}
	return result, rows.Err()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
