// Package mutationstate persists local-operator mutation history under an OS lock.
// It trusts the selected root, local operator and OS clock. It does not protect
// against malicious same-user changes, whole-directory loss or machine rollback.
package mutationstate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

const (
	// MaxEvidenceBytes bounds a complete signed revocation-list input.
	MaxEvidenceBytes = 1 << 20
	maxRecordBytes   = 2 << 20
	recordName       = "record.json"
	lockName         = "lock"
	stateSchema      = "m3c.mutation-state/v1"
)

var (
	// ErrNotEnrolled includes incomplete state; ordinary operations never repair it.
	ErrNotEnrolled = errors.New("mutation state is absent or incomplete; explicit enrollment or operator recovery required")
	// ErrAlreadyEnrolled also covers a reserved directory from failed enrollment.
	ErrAlreadyEnrolled = errors.New("mutation state directory already reserved; enrollment refused")
	// ErrInvalidState marks malformed, mismatched or inconsistent local history.
	ErrInvalidState = errors.New("invalid mutation state")
	// ErrPersistence means durability was not confirmed, even if a rename occurred.
	ErrPersistence = errors.New("mutation state persistence not confirmed")
)

// Status is a validated history snapshot, not a mutation authorization.
type Status struct {
	Schema              string    `json:"schema"`
	Registry            string    `json:"registry"`
	RootFingerprint     string    `json:"root_fingerprint"`
	EvidenceFingerprint string    `json:"evidence_fingerprint"`
	Epoch               int       `json:"epoch"`
	IssuedAt            time.Time `json:"issued_at"`
	LastSeen            time.Time `json:"last_seen"`
}

type record struct {
	Schema              string    `json:"schema"`
	Registry            string    `json:"registry"`
	RootFingerprint     string    `json:"root_fingerprint"`
	EvidenceFingerprint string    `json:"evidence_fingerprint"`
	Epoch               int       `json:"epoch"`
	IssuedAt            time.Time `json:"issued_at"`
	LastSeen            time.Time `json:"last_seen"`
	FullList            []byte    `json:"full_list"`
}

func (r record) status() Status {
	return Status{r.Schema, r.Registry, r.RootFingerprint, r.EvidenceFingerprint, r.Epoch, r.IssuedAt, r.LastSeen}
}

// Store snapshots the caller's pinned root. Only Enroll creates state paths.
// All operations serialize on a stable lock file that is never replaced.
type Store struct {
	base, dir, statePath, lockPath string
	registry, fingerprint          string
	root                           *verify.TrustRoot
	now                            func() time.Time
	ops                            fileOps
}

// New selects a registry-specific directory without creating or enrolling it.
// A changed pinned-root fingerprint requires separate operator recovery; New
// does not authenticate how the caller obtained the pinned root.
func New(dir string, root *verify.TrustRoot) (*Store, error) {
	if root == nil || root.MinRevocationEpoch < 0 {
		return nil, ErrInvalidState
	}
	registry := strings.TrimRight(strings.TrimSpace(root.RegistryURL), "/")
	if registry == "" {
		return nil, ErrInvalidState
	}
	raw, err := json.Marshal(root)
	if err != nil {
		return nil, ErrInvalidState
	}
	var snapshot verify.TrustRoot
	if err = json.Unmarshal(raw, &snapshot); err != nil {
		return nil, ErrInvalidState
	}
	if _, err = snapshot.Freshness(); err != nil {
		return nil, fmt.Errorf("mutation state root policy: %w", err)
	}
	base, err := canonicalBase(dir)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256([]byte(registry))
	target := filepath.Join(base, hex.EncodeToString(hash[:]))
	return &Store{base: base, dir: target, statePath: filepath.Join(target, recordName), lockPath: filepath.Join(target, lockName), registry: registry, fingerprint: fingerprint(raw), root: &snapshot, now: time.Now, ops: defaultFileOps()}, nil
}

func fingerprint(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

// Status validates signature and stored history, including stale evidence. It
// does not refresh LastSeen or claim that the list is currently young enough.
func (s *Store) Status(ctx context.Context) (Status, error) {
	lock, err := s.acquire(ctx)
	if err != nil {
		return Status{}, err
	}
	r, _, err := s.load()
	err = errors.Join(err, lock.Close())
	if err != nil {
		return Status{}, err
	}
	return r.status(), nil
}

// Enroll explicitly reserves a previously absent registry directory. A failed
// initial write leaves the reservation intact and requires operator recovery.
// Enrollment validates signed evidence directly, without fabricated clock history.
func (s *Store) Enroll(ctx context.Context, raw []byte) (Status, error) {
	if err := ctx.Err(); err != nil {
		return Status{}, err
	}
	if len(raw) == 0 || len(raw) > MaxEvidenceBytes {
		return Status{}, ErrInvalidState
	}
	raw = append([]byte(nil), raw...)
	now := s.now().UTC()
	list, err := s.authority(raw, now, true)
	if err != nil {
		return Status{}, err
	}
	if err = s.prepareBase(); err != nil {
		return Status{}, err
	}
	if err = os.Mkdir(s.dir, 0700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return Status{}, ErrAlreadyEnrolled
		}
		return Status{}, err
	}
	if err = secureCreated(s.dir); err != nil {
		return Status{}, errors.Join(ErrPersistence, err)
	}
	if err = s.ops.syncDir(s.base); err != nil {
		return Status{}, errors.Join(ErrPersistence, err)
	}
	// The stable lock is created once, within the exclusively reserved directory.
	// #nosec G304 -- registry-specific local state path; no external path input is used here.
	lock, err := os.OpenFile(s.lockPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return Status{}, errors.Join(ErrPersistence, err)
	}
	if err = secureCreated(s.lockPath); err == nil {
		err = errors.Join(lock.Sync(), s.ops.syncDir(s.dir))
	}
	err = errors.Join(err, lock.Close())
	if err != nil {
		return Status{}, errors.Join(ErrPersistence, err)
	}
	held, err := s.acquire(ctx)
	if err != nil {
		return Status{}, err
	}
	r := s.newRecord(raw, list, now)
	err = s.publish(ctx, r)
	err = errors.Join(err, held.Close())
	if err != nil {
		return Status{}, err
	}
	return r.status(), nil
}

// Adopt updates an enrolled store with fresh authenticated evidence. Stale prior
// evidence remains valid history. Same-epoch updates must preserve the revoked
// set and cannot move its signed issuance time backward.
func (s *Store) Adopt(ctx context.Context, raw []byte) (Status, error) {
	if len(raw) == 0 || len(raw) > MaxEvidenceBytes {
		return Status{}, ErrInvalidState
	}
	raw = append([]byte(nil), raw...)
	held, err := s.acquire(ctx)
	if err != nil {
		return Status{}, err
	}
	r, err := s.adoptLocked(ctx, raw)
	err = errors.Join(err, held.Close())
	if err != nil {
		return Status{}, err
	}
	return r.status(), nil
}

func (s *Store) adoptLocked(ctx context.Context, raw []byte) (record, error) {
	r, old, err := s.load()
	if err != nil {
		return r, err
	}
	now := s.now().UTC()
	if now.IsZero() || now.Before(r.LastSeen) {
		return r, fmt.Errorf("mutation clock rollback: %w", verify.ErrRevocationStale)
	}
	next, err := s.authority(raw, now, true)
	if err != nil {
		return r, err
	}
	issued, _ := time.Parse(time.RFC3339Nano, strings.TrimSpace(next.IssuedAt))
	if next.Epoch < r.Epoch || issued.Before(r.IssuedAt) {
		return r, errors.Join(ErrInvalidState, verify.ErrRevocationStale)
	}
	if next.Epoch == r.Epoch {
		a, err := verify.CanonicalRevocationBytes(s.registry, "", 0, old.RevokedDigests)
		if err != nil {
			return r, err
		}
		b, err := verify.CanonicalRevocationBytes(s.registry, "", 0, next.RevokedDigests)
		if err != nil {
			return r, err
		}
		if string(a) != string(b) {
			return r, ErrInvalidState
		}
	}
	r = s.newRecord(raw, next, now)
	return r, s.publish(ctx, r)
}

// Session holds the stable interprocess lock until Close. Callers must keep it
// through their actual mutation, including its final commit or refusal.
type Session struct {
	file     *os.File
	decision verify.MutationFreshnessDecision
	once     sync.Once
	closeErr error
}

// Decision returns a value copy of this session's evaluated freshness decision.
func (s *Session) Decision() verify.MutationFreshnessDecision { return s.decision }

// Close releases the lock. It is idempotent and reports the first close error.
func (s *Session) Close() error { s.once.Do(func() { s.closeErr = s.file.Close() }); return s.closeErr }

// Begin verifies the persisted full list against real prior history and writes
// the new clock floor durably before returning a held session. A denial never
// grants a session; successful persistence is still not an installation result.
func (s *Store) Begin(ctx context.Context, action verify.MutationAction, digest string) (*Session, error) {
	held, err := s.acquire(ctx)
	if err != nil {
		return nil, err
	}
	r, list, err := s.load()
	var dec verify.MutationFreshnessDecision
	if err == nil {
		dec, err = verify.EvaluateMutationFreshness(verify.MutationFreshnessOpts{Action: action, ExpectedRegistry: s.registry, SubjectDigest: digest, Root: s.root, Revocations: list, MinimumEpoch: r.Epoch, Clock: verify.MutationClockState{Now: s.now().UTC(), LastObservedAt: r.LastSeen}})
		if dec.Reason == "subject_revoked" {
			err = fmt.Errorf("mutation subject is revoked: %w", verify.ErrIdentityRevoked)
		}
		if err == nil {
			r.LastSeen = dec.EvaluatedAt
			err = s.publish(ctx, r)
		}
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		return nil, errors.Join(err, held.Close())
	}
	return &Session{file: held, decision: dec}, nil
}

func (s *Store) newRecord(raw []byte, list *verify.RevocationList, now time.Time) record {
	issued, _ := time.Parse(time.RFC3339Nano, strings.TrimSpace(list.IssuedAt))
	return record{stateSchema, s.registry, s.fingerprint, fingerprint(raw), list.Epoch, issued.UTC(), now.UTC(), append([]byte(nil), raw...)}
}
