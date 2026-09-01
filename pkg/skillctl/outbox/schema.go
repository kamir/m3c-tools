// schema.go — DDL for the SPEC-0317 (R-2.3) transactional audit outbox.
//
// The store is the single AUTHORITATIVE system of record for signed skill
// invocation evidence (R-2.5). Decided rows are write-once (R-2.6): the schema
// enforces immutability with TRIGGERS — not convention — so a same-uid rewrite
// of an evidence column ABORTs at the SQL layer. The only permitted mutations
// are the sync bookkeeping (sync_status / synced_at), the one-shot translog_seq
// backfill (NULL→value, per-sync-batch anchoring, R-4.2), and the retention
// NULL-ing of payload_json (R-5.5). Everything else RAISE(ABORT)s.
//
// The flat columns (decision, refusal_code, identity, payload_hash …) are
// NON-authoritative indices (R-2.6): any display/enforcement reconstructs the
// canonical bytes from payload_json and re-verifies signature_b64. A
// column↔payload divergence is itself a tamper signal the ingest flags.
package outbox

// pragmaWAL is executed once at migrate() time; WAL is persisted in the file
// header so it survives reopen. It is kept SEPARATE from the per-connection
// busy_timeout pin (driver_hook_*.go) which must be re-applied every connection.
const pragmaWAL = `PRAGMA journal_mode=WAL;`

// ddl is the full CREATE ... IF NOT EXISTS schema. Idempotent; safe to run on
// every Open. Style mirrors pkg/tracking/retryqueue.go.
const ddl = `
CREATE TABLE IF NOT EXISTS audit_events (
    event_id       TEXT PRIMARY KEY,          -- inv:<unix-ms>:<10-byte-hex>; the ONLY dedup key (R-4.1)
    occurred_at    TEXT NOT NULL,             -- RFC3339 UTC
    event_type     TEXT NOT NULL,             -- e.g. skill.invocation
    tool           TEXT NOT NULL,             -- Skill | Bash | Read | Edit | Write
    skill_digest   TEXT,                      -- sha256:<hex> or ''
    skill_name     TEXT,
    decision       TEXT NOT NULL,             -- allow | deny  (NON-authoritative index, R-2.6)
    refusal_code   TEXT,                      -- stable token or ''
    exit_code      INTEGER NOT NULL,
    payload_json   TEXT,                      -- full signed InvocationRecord JSON (nullable ONLY by retention)
    payload_hash   TEXT NOT NULL,             -- sha256 hex of canonical bytes (R-4.1 column, not in signed msg)
    device_key_id  TEXT NOT NULL,
    signature_b64  TEXT NOT NULL,             -- detached ed25519 over canonical bytes (authoritative)
    translog_seq   INTEGER,                   -- Merkle leaf index; backfilled per sync batch (R-4.2)
    sync_status    INTEGER NOT NULL DEFAULT 0,-- 0 unsynced, 1 synced
    synced_at      TEXT,
    created_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_events_sync ON audit_events(sync_status, occurred_at);
CREATE INDEX IF NOT EXISTS idx_audit_events_seq  ON audit_events(translog_seq);

-- Write-once evidence (R-2.6): the only permitted mutations are sync_status /
-- synced_at, the translog_seq backfill (NULL->value once), and the retention
-- NULL-ing of payload_json (R-5.5). Any other change to an evidence column
-- ABORTs the UPDATE.
CREATE TRIGGER IF NOT EXISTS audit_events_immutable
BEFORE UPDATE ON audit_events
BEGIN
  SELECT CASE WHEN
       OLD.event_id      <> NEW.event_id
    OR OLD.occurred_at   <> NEW.occurred_at
    OR OLD.event_type    <> NEW.event_type
    OR OLD.tool          <> NEW.tool
    OR OLD.decision      <> NEW.decision
    OR OLD.exit_code     <> NEW.exit_code
    OR OLD.refusal_code  IS NOT NEW.refusal_code
    OR OLD.skill_digest  IS NOT NEW.skill_digest
    OR OLD.skill_name    IS NOT NEW.skill_name
    OR OLD.payload_hash  <> NEW.payload_hash
    OR OLD.device_key_id <> NEW.device_key_id
    OR OLD.signature_b64 <> NEW.signature_b64
    OR OLD.created_at    <> NEW.created_at
    OR (OLD.translog_seq IS NOT NULL AND OLD.translog_seq <> NEW.translog_seq) -- seq backfills once
  THEN RAISE(ABORT, 'audit_events: evidence columns are write-once') END;
  SELECT CASE WHEN NEW.payload_json IS NOT NULL AND NEW.payload_json <> OLD.payload_json
  THEN RAISE(ABORT, 'audit_events: payload_json is write-once (retention may only NULL it)') END;
END;

CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
BEFORE DELETE ON audit_events
BEGIN
  SELECT RAISE(ABORT, 'audit_events: rows are never deleted; retention nulls payload_json only');
END;

CREATE TABLE IF NOT EXISTS sync_state (
    k TEXT PRIMARY KEY,   -- high_water_seq | last_success_ts | endpoint_epoch | ingest_pubkey
    v TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS delivery_attempts (
    event_id      TEXT NOT NULL,
    attempt       INTEGER NOT NULL,
    at            TEXT NOT NULL,
    http_status   INTEGER,
    error         TEXT,
    next_retry_at TEXT,                                  -- retryqueue.go backoff 30s->1h cap 10
    PRIMARY KEY (event_id, attempt),
    FOREIGN KEY (event_id) REFERENCES audit_events(event_id)
);
CREATE INDEX IF NOT EXISTS idx_delivery_attempts_next ON delivery_attempts(next_retry_at);

-- Table-backed successors to verdicts.json / gate-policy.yaml / revoked-*.json
-- (R-2.3): same signed-HEAD + epoch-monotonic + content-digest semantics (R-7).
-- Loose files remain the migration source + fallback read. epoch is monotonic;
-- a write with a lower epoch than stored is rejected in Go (caches.go).
CREATE TABLE IF NOT EXISTS trust_cache (
    name TEXT PRIMARY KEY, epoch INTEGER NOT NULL, issued_at TEXT, content_digest TEXT NOT NULL,
    signed_head_b64 TEXT, payload_json TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS policy_cache (
    name TEXT PRIMARY KEY, epoch INTEGER NOT NULL, issued_at TEXT, content_digest TEXT NOT NULL,
    signed_head_b64 TEXT, payload_json TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS revocation_cache (
    digest TEXT PRIMARY KEY, epoch INTEGER NOT NULL, issued_at TEXT, content_digest TEXT NOT NULL,
    signed_head_b64 TEXT, payload_json TEXT NOT NULL, updated_at TEXT NOT NULL
);`
