// caches.go — typed accessors for the table-backed trust/policy/revocation
// caches (R-2.3). The tables are created in P0; they are POPULATED in P2 (the
// loose files — verdicts.json / gate-policy.yaml / revoked-*.json — remain the
// migration source and the fallback read per R-2.3). The accessors here carry
// the epoch-monotonic guarantee (R-7): a Put with an epoch LOWER than the stored
// one is rejected in Go, so a rollback to a stale, previously-valid signed HEAD
// cannot silently downgrade the cache.
package outbox

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// CacheEntry is one row of a signed-HEAD cache. Key is the primary key column
// (name for trust/policy, digest for revocation). ContentDigest + SignedHeadB64
// carry the R-7 signed-HEAD/content-digest semantics; PayloadJSON is the full
// cached document.
type CacheEntry struct {
	Key           string
	Epoch         int64
	IssuedAt      string
	ContentDigest string
	SignedHeadB64 string
	PayloadJSON   string
	UpdatedAt     string
}

// ErrEpochRegression is returned by a Put whose epoch is strictly lower than the
// stored epoch for the same key — the monotonicity floor (R-7).
var ErrEpochRegression = errors.New("outbox: cache epoch regression (stored epoch is newer)")

type cacheTable struct {
	table  string // trust_cache | policy_cache | revocation_cache
	keyCol string // name | digest
}

var (
	trustCache      = cacheTable{table: "trust_cache", keyCol: "name"}
	policyCache     = cacheTable{table: "policy_cache", keyCol: "name"}
	revocationCache = cacheTable{table: "revocation_cache", keyCol: "digest"}
)

// put upserts a cache row under the epoch-monotonic guard. It reads the stored
// epoch first and rejects a strictly-lower epoch; then it UPSERTs. The read +
// write are wrapped in a single transaction so a concurrent higher-epoch write
// cannot be clobbered by a stale one that passed the check on an old read.
func (t cacheTable) put(s *Store, e CacheEntry) error {
	if strings.TrimSpace(e.Key) == "" {
		return fmt.Errorf("outbox: %s: empty key", t.table)
	}
	if e.UpdatedAt == "" {
		e.UpdatedAt = rfc3339(nowUTC())
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("outbox: %s: begin: %w", t.table, err)
	}
	defer func() { _ = tx.Rollback() }()

	var storedEpoch int64
	row := tx.QueryRow(fmt.Sprintf(`SELECT epoch FROM %s WHERE %s=?`, t.table, t.keyCol), e.Key)
	switch err := row.Scan(&storedEpoch); {
	case errors.Is(err, sql.ErrNoRows):
		// fresh insert
	case err != nil:
		return fmt.Errorf("outbox: %s: read epoch: %w", t.table, err)
	default:
		if e.Epoch < storedEpoch {
			return ErrEpochRegression
		}
	}

	_, err = tx.Exec(fmt.Sprintf(`
INSERT INTO %s (%s, epoch, issued_at, content_digest, signed_head_b64, payload_json, updated_at)
VALUES (?,?,?,?,?,?,?)
ON CONFLICT(%s) DO UPDATE SET
  epoch=excluded.epoch, issued_at=excluded.issued_at, content_digest=excluded.content_digest,
  signed_head_b64=excluded.signed_head_b64, payload_json=excluded.payload_json,
  updated_at=excluded.updated_at`, t.table, t.keyCol, t.keyCol),
		e.Key, e.Epoch, e.IssuedAt, e.ContentDigest, nullIfEmpty(e.SignedHeadB64), e.PayloadJSON, e.UpdatedAt)
	if err != nil {
		return fmt.Errorf("outbox: %s: upsert: %w", t.table, err)
	}
	return tx.Commit()
}

func (t cacheTable) get(s *Store, key string) (CacheEntry, bool, error) {
	var (
		e        CacheEntry
		signed   sql.NullString
		issuedAt sql.NullString
	)
	e.Key = key
	err := s.db.QueryRow(fmt.Sprintf(`
SELECT epoch, issued_at, content_digest, signed_head_b64, payload_json, updated_at
FROM %s WHERE %s=?`, t.table, t.keyCol), key).
		Scan(&e.Epoch, &issuedAt, &e.ContentDigest, &signed, &e.PayloadJSON, &e.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return CacheEntry{}, false, nil
	}
	if err != nil {
		return CacheEntry{}, false, fmt.Errorf("outbox: %s: get: %w", t.table, err)
	}
	e.IssuedAt = issuedAt.String
	e.SignedHeadB64 = signed.String
	return e, true, nil
}

// PutTrustCache upserts a trust-cache row (epoch-monotonic).
func (s *Store) PutTrustCache(e CacheEntry) error { return trustCache.put(s, e) }

// GetTrustCache reads a trust-cache row by name.
func (s *Store) GetTrustCache(name string) (CacheEntry, bool, error) { return trustCache.get(s, name) }

// PutPolicyCache upserts a policy-cache row (epoch-monotonic).
func (s *Store) PutPolicyCache(e CacheEntry) error { return policyCache.put(s, e) }

// GetPolicyCache reads a policy-cache row by name.
func (s *Store) GetPolicyCache(name string) (CacheEntry, bool, error) {
	return policyCache.get(s, name)
}

// PutRevocationCache upserts a revocation-cache row (epoch-monotonic).
func (s *Store) PutRevocationCache(e CacheEntry) error { return revocationCache.put(s, e) }

// GetRevocationCache reads a revocation-cache row by digest.
func (s *Store) GetRevocationCache(digest string) (CacheEntry, bool, error) {
	return revocationCache.get(s, digest)
}
