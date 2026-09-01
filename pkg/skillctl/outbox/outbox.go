// Package outbox is the SPEC-0317 (P0) transactional audit outbox: the single
// AUTHORITATIVE, write-once store of signed skill-invocation evidence.
//
// It is a trust-critical LEAF package — stdlib + internal/dbdriver only; it does
// NOT import pkg/skillctl/registry (or any heavy skillctl surface) so it can be
// depended on from the hot path without pulling the world.
//
// Each row wraps the existing device-signed skillgate.InvocationRecord
// (canonical invocation_event_v1, detached ed25519, event_id =
// inv:<unix-ms>:<10-byte-hex>). payload_hash = sha256(canonical bytes) is stored
// as a COLUMN (R-4.1) — not folded into the signed canonical, so no format bump.
// event_id is the ONLY dedup key end-to-end.
//
// HOT-PATH SAFETY (R-2.4, the hard constraint): the handle pins
// busy_timeout≈250ms per connection (driver_hook_*.go) and SetMaxOpenConns(1).
// On SQLITE_BUSY / open failure Append returns the error so the CALLER spools
// (spool.go) — the decision returns regardless (R-2.4 / R-8.1 default). Append
// itself stays pure and testable.
package outbox

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillgate"
)

// Store is the outbox handle. It mirrors the shape of pkg/tracking's
// RetryQueueDB: a *sql.DB plus the resolved home so spool.jsonl lands beside the
// db under ~/.claude/skillctl.
type Store struct {
	db   *sql.DB
	home string
	dir  string
}

// Event is one materialized audit_events row (the non-authoritative index view).
// Consumers that ENFORCE or DISPLAY a decision must reconstruct the canonical
// bytes from PayloadJSON and re-verify SignatureB64 (R-2.6) — the flat columns
// are indices only.
type Event struct {
	EventID      string
	OccurredAt   string
	EventType    string
	Tool         string
	SkillDigest  string
	SkillName    string
	Decision     string
	RefusalCode  string
	ExitCode     int
	PayloadJSON  string
	PayloadHash  string
	DeviceKeyID  string
	SignatureB64 string
	TranslogSeq  sql.NullInt64
	SyncStatus   int
	SyncedAt     string
	CreatedAt    string
}

// dirName is the state directory, matching the ~/.claude/skillctl 0700
// convention used by verdict_cache.go / invocation_trail.go.
func dirName(home string) string { return filepath.Join(home, ".claude", "skillctl") }

// DBPath is the outbox database path for a given home.
func DBPath(home string) string { return filepath.Join(dirName(home), "outbox.db") }

// nowUTC is a seam so tests can pin time; production is time.Now().
var nowUTC = func() time.Time { return time.Now().UTC() }

func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// Open opens (creating if needed) the outbox at ~/.claude/skillctl/outbox.db.
// The directory is created 0700 and the db file chmod'd 0600. migrate() sets
// WAL once and creates the write-once schema. An empty home is an error (there
// is nowhere to anchor state).
func Open(home string) (*Store, error) {
	if strings.TrimSpace(home) == "" {
		return nil, errors.New("outbox: empty home")
	}
	dir := dirName(home)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("outbox: create state dir: %w", err)
	}
	dbPath := DBPath(home)
	db, err := openHotPathDB(dbPath)
	if err != nil {
		return nil, fmt.Errorf("outbox: open sqlite: %w", err)
	}
	// Tighten the db file to 0600 (best-effort; WAL/-shm sidecars inherit the
	// 0700 dir). A chmod failure is not fatal to correctness.
	_ = os.Chmod(dbPath, 0o600)

	s := &Store{db: db, home: home, dir: dir}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("outbox: migrate: %w", err)
	}
	return s, nil
}

// Close closes the underlying handle.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Home returns the resolved home the store was opened against.
func (s *Store) Home() string { return s.home }

// Checkpoint runs a WAL checkpoint (TRUNCATE) so the -wal sidecar is folded back
// into the main db file. The sync daemon calls this on graceful shutdown so a
// long-lived process does not leave an unbounded WAL. Best-effort: a checkpoint
// failure is not fatal (the WAL is still valid and replays on next open).
func (s *Store) Checkpoint() error {
	if s == nil || s.db == nil {
		return nil
	}
	if _, err := s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return fmt.Errorf("outbox: wal checkpoint: %w", err)
	}
	return nil
}

// migrate sets WAL once (persisted in the file header) then applies the
// idempotent DDL (tables + write-once triggers + indexes).
func (s *Store) migrate() error {
	if _, err := s.db.Exec(pragmaWAL); err != nil {
		return fmt.Errorf("set WAL: %w", err)
	}
	if _, err := s.db.Exec(ddl); err != nil {
		return fmt.Errorf("apply ddl: %w", err)
	}
	return nil
}

// RecordPayload derives the two stored derivations of a record: the full JSON
// (payload_json, the authoritative bytes we can re-verify) and payload_hash =
// hex(sha256(canonical bytes)) (R-4.1 — a COLUMN, NOT part of the signed
// canonical; the "sha256:" prefix is added by translog anchoring, so this is
// stored bare-hex). Returns an error if the record refuses canonicalization
// (e.g. a newline-smuggled field).
func RecordPayload(rec skillgate.InvocationRecord) (payloadJSON, payloadHash string, err error) {
	canon, err := skillgate.CanonicalizeInvocationRecord(&rec)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(canon)
	pj, err := json.Marshal(rec)
	if err != nil {
		return "", "", err
	}
	return string(pj), hex.EncodeToString(sum[:]), nil
}

// deriveDecision maps a record to the non-authoritative decision index: a
// present refusal_code means the invocation was denied, otherwise allowed. This
// is an INDEX only (R-2.6) — enforcement re-derives from the signed payload.
func deriveDecision(rec skillgate.InvocationRecord) string {
	if strings.TrimSpace(rec.RefusalCode) != "" {
		return "deny"
	}
	return "allow"
}

// Append inserts one decided evidence row. It is the hot-path write: a single
// INSERT OR IGNORE keyed on event_id (a replay/reconcile duplicate is a no-op —
// this is where the trail's Replays signal moves to, AC-11). It is PURE: on
// SQLITE_BUSY / any db error it returns the error so the caller spools
// (Spool / AppendOrSpool). It performs no I/O beyond the single INSERT.
//
// payloadJSON and payloadHash are supplied by the caller (see RecordPayload) so
// the exact signed bytes are pinned once and fanned out identically to every
// sink (never re-marshalled per-sink, which would risk divergence).
func (s *Store) Append(rec skillgate.InvocationRecord, payloadJSON, payloadHash string) error {
	if strings.TrimSpace(rec.EventID) == "" {
		return errors.New("outbox: append: empty event_id")
	}
	now := rfc3339(nowUTC())
	_, err := s.db.Exec(`
INSERT OR IGNORE INTO audit_events
  (event_id, occurred_at, event_type, tool, skill_digest, skill_name, decision,
   refusal_code, exit_code, payload_json, payload_hash, device_key_id,
   signature_b64, sync_status, created_at)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,0,?)`,
		rec.EventID, rec.OccurredAt, rec.EventType, rec.Tool, rec.SkillDigest,
		rec.SkillName, deriveDecision(rec), rec.RefusalCode, rec.ExitCode,
		payloadJSON, payloadHash, rec.DeviceKeyID, rec.DeviceSignatureB64, now)
	if err != nil {
		return fmt.Errorf("outbox: append: %w", err)
	}
	return nil
}

// AppendOrSpool tries Append; on ANY failure (SQLITE_BUSY, open error) it falls
// back to the spool.jsonl fallback so the decision can return regardless
// (R-2.4 / R-8.1 default). It returns nil if EITHER sink accepted the row; it
// returns a joined error only if BOTH failed (a genuinely un-recordable state).
func (s *Store) AppendOrSpool(rec skillgate.InvocationRecord, payloadJSON, payloadHash string) error {
	if err := s.Append(rec, payloadJSON, payloadHash); err != nil {
		if serr := s.Spool(rec, payloadJSON, payloadHash); serr != nil {
			return errors.Join(err, serr)
		}
		return nil
	}
	return nil
}

// PendingBatch returns up to limit unsynced rows (sync_status=0) in occurred_at
// order (oldest first) — the drain order the P1 sync uses. limit<=0 defaults to
// 100. Read-only.
func (s *Store) PendingBatch(limit int) ([]Event, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(`
SELECT event_id, occurred_at, event_type, tool, skill_digest, skill_name,
       decision, refusal_code, exit_code, payload_json, payload_hash,
       device_key_id, signature_b64, translog_seq, sync_status, synced_at, created_at
FROM audit_events
WHERE sync_status=0
ORDER BY occurred_at ASC, event_id ASC
LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("outbox: pending batch: %w", err)
	}
	defer rows.Close()
	return scanEvents(rows)
}

// PendingBatchDue returns up to limit unsynced rows (sync_status=0) that are DUE
// for a (re)post: a row is EXCLUDED while it still has a delivery_attempts row
// whose next_retry_at is in the future, mirroring retryqueue.go's
// `next_retry_at <= now` due gate. A row with no attempts (never posted) is always
// due. Ordered oldest-first by occurred_at — the drain order the P1 sync uses.
//
// This is the backoff-aware variant of PendingBatch: without it the sync daemon
// re-POSTs every unsynced row each interval regardless of its deferral, and a
// mixed-ack batch re-POSTs a just-deferred row within one drain. now is an RFC3339
// UTC string (string comparison is valid: all timestamps are fixed-width UTC 'Z').
// limit<=0 defaults to 100. Read-only.
func (s *Store) PendingBatchDue(limit int, now string) ([]Event, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(`
SELECT event_id, occurred_at, event_type, tool, skill_digest, skill_name,
       decision, refusal_code, exit_code, payload_json, payload_hash,
       device_key_id, signature_b64, translog_seq, sync_status, synced_at, created_at
FROM audit_events e
WHERE sync_status=0
  AND NOT EXISTS (
        SELECT 1 FROM delivery_attempts d
        WHERE d.event_id = e.event_id
          AND d.next_retry_at IS NOT NULL
          AND d.next_retry_at > ?
      )
ORDER BY occurred_at ASC, event_id ASC
LIMIT ?`, now, limit)
	if err != nil {
		return nil, fmt.Errorf("outbox: pending batch due: %w", err)
	}
	defer rows.Close()
	return scanEvents(rows)
}

func scanEvents(rows *sql.Rows) ([]Event, error) {
	var out []Event
	for rows.Next() {
		var (
			e           Event
			skillDigest sql.NullString
			skillName   sql.NullString
			refusalCode sql.NullString
			payloadJSON sql.NullString
			syncedAt    sql.NullString
		)
		if err := rows.Scan(&e.EventID, &e.OccurredAt, &e.EventType, &e.Tool,
			&skillDigest, &skillName, &e.Decision, &refusalCode, &e.ExitCode,
			&payloadJSON, &e.PayloadHash, &e.DeviceKeyID, &e.SignatureB64,
			&e.TranslogSeq, &e.SyncStatus, &syncedAt, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("outbox: scan: %w", err)
		}
		e.SkillDigest = skillDigest.String
		e.SkillName = skillName.String
		e.RefusalCode = refusalCode.String
		e.PayloadJSON = payloadJSON.String
		e.SyncedAt = syncedAt.String
		out = append(out, e)
	}
	return out, rows.Err()
}

// Get returns a single row by event_id (ok=false if absent). Read-only helper
// used by tests and the P1 drain's re-verify step.
func (s *Store) Get(eventID string) (Event, bool, error) {
	rows, err := s.db.Query(`
SELECT event_id, occurred_at, event_type, tool, skill_digest, skill_name,
       decision, refusal_code, exit_code, payload_json, payload_hash,
       device_key_id, signature_b64, translog_seq, sync_status, synced_at, created_at
FROM audit_events WHERE event_id=?`, eventID)
	if err != nil {
		return Event{}, false, fmt.Errorf("outbox: get: %w", err)
	}
	defer rows.Close()
	evs, err := scanEvents(rows)
	if err != nil {
		return Event{}, false, err
	}
	if len(evs) == 0 {
		return Event{}, false, nil
	}
	return evs[0], true, nil
}

// PendingCount returns the number of unsynced rows. Read-only.
func (s *Store) PendingCount() (int, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE sync_status=0`).Scan(&n); err != nil {
		return 0, fmt.Errorf("outbox: pending count: %w", err)
	}
	return n, nil
}

// MarkSynced flips sync_status=1 and stamps synced_at for an event that received
// a VALID signed durable-seq ack (the P1 caller enforces that; here it is the
// write). It touches ONLY the two sync-bookkeeping columns, so the write-once
// trigger permits it. Idempotent: re-marking an already-synced event is a no-op.
func (s *Store) MarkSynced(eventID, syncedAt string) error {
	if strings.TrimSpace(syncedAt) == "" {
		syncedAt = rfc3339(nowUTC())
	}
	_, err := s.db.Exec(`UPDATE audit_events SET sync_status=1, synced_at=? WHERE event_id=?`,
		syncedAt, eventID)
	if err != nil {
		return fmt.Errorf("outbox: mark synced: %w", err)
	}
	return nil
}

// BackfillTranslogSeq records the Merkle leaf index for a row, once. It updates
// translog_seq ONLY where it is currently NULL (the write-once trigger also
// forbids a NULL→value→other-value rewrite), so a re-anchor cannot silently
// move an already-anchored row (R-4.2).
//
// NOT-YET-WIRED (AC-5a): no production path calls this yet — the sync/enforce
// drain does not anchor — so translog_seq is NULL in production. It exists (and is
// unit-tested) as the one-shot backfill the future per-batch anchor will use; do
// not read the schema comments as a claim that anchoring runs today.
func (s *Store) BackfillTranslogSeq(eventID string, seq int64) error {
	_, err := s.db.Exec(`UPDATE audit_events SET translog_seq=? WHERE event_id=? AND translog_seq IS NULL`,
		seq, eventID)
	if err != nil {
		return fmt.Errorf("outbox: backfill translog_seq: %w", err)
	}
	return nil
}

// RecordAttempt inserts one delivery attempt row (the retryqueue.go backoff
// lane: 30s→1h, cap 10, scale 2.0 — computed by the P1 caller). Keyed on
// (event_id, attempt) so a replayed attempt number is an INSERT OR IGNORE no-op.
// httpStatus<=0 stores NULL. This is bookkeeping on the SEPARATE
// delivery_attempts table; it never mutates the write-once evidence row.
func (s *Store) RecordAttempt(eventID string, attempt int, at string, httpStatus int, errMsg, nextRetryAt string) error {
	if strings.TrimSpace(at) == "" {
		at = rfc3339(nowUTC())
	}
	var status sql.NullInt64
	if httpStatus > 0 {
		status = sql.NullInt64{Int64: int64(httpStatus), Valid: true}
	}
	_, err := s.db.Exec(`
INSERT OR IGNORE INTO delivery_attempts (event_id, attempt, at, http_status, error, next_retry_at)
VALUES (?,?,?,?,?,?)`, eventID, attempt, at, status, nullIfEmpty(errMsg), nullIfEmpty(nextRetryAt))
	if err != nil {
		return fmt.Errorf("outbox: record attempt: %w", err)
	}
	return nil
}

// Attempts returns the recorded delivery attempts for an event, oldest first.
// Read-only helper for tests / the P1 backoff scheduler.
func (s *Store) Attempts(eventID string) ([]Attempt, error) {
	rows, err := s.db.Query(`
SELECT event_id, attempt, at, http_status, error, next_retry_at
FROM delivery_attempts WHERE event_id=? ORDER BY attempt ASC`, eventID)
	if err != nil {
		return nil, fmt.Errorf("outbox: attempts: %w", err)
	}
	defer rows.Close()
	var out []Attempt
	for rows.Next() {
		var (
			a           Attempt
			httpStatus  sql.NullInt64
			errMsg      sql.NullString
			nextRetryAt sql.NullString
		)
		if err := rows.Scan(&a.EventID, &a.Attempt, &a.At, &httpStatus, &errMsg, &nextRetryAt); err != nil {
			return nil, fmt.Errorf("outbox: scan attempt: %w", err)
		}
		if httpStatus.Valid {
			a.HTTPStatus = int(httpStatus.Int64)
		}
		a.Error = errMsg.String
		a.NextRetryAt = nextRetryAt.String
		out = append(out, a)
	}
	return out, rows.Err()
}

// Attempt is one delivery_attempts row.
type Attempt struct {
	EventID     string
	Attempt     int
	At          string
	HTTPStatus  int
	Error       string
	NextRetryAt string
}

// SetSyncState upserts a sync_state key (high_water_seq, last_success_ts,
// endpoint_epoch, ingest_pubkey …). The P1 sync owns the semantics; P0 provides
// the durable key/value.
func (s *Store) SetSyncState(k, v string) error {
	_, err := s.db.Exec(`
INSERT INTO sync_state (k, v) VALUES (?, ?)
ON CONFLICT(k) DO UPDATE SET v=excluded.v`, k, v)
	if err != nil {
		return fmt.Errorf("outbox: set sync state: %w", err)
	}
	return nil
}

// GetSyncState reads a sync_state key (ok=false if absent).
func (s *Store) GetSyncState(k string) (string, bool, error) {
	var v string
	err := s.db.QueryRow(`SELECT v FROM sync_state WHERE k=?`, k).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("outbox: get sync state: %w", err)
	}
	return v, true, nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
