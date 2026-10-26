package registry

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	ErrNativeHistoryRequired         = errors.New("native history must be explicitly enrolled")
	ErrNativeHistoryInvalid          = errors.New("native history is invalid; operator recovery is required")
	ErrNativeHistoryExists           = errors.New("native history reservation already exists; operator recovery is required")
	ErrNativeHistoryStale            = errors.New("native history is stale or its clock or epoch moved backward")
	ErrNativeSubjectRevoked          = errors.New("native installation subject is revoked")
	ErrNativeConsentInvalid          = errors.New("native installation consent is missing, invalid or expired")
	ErrNativeSessionUnavailable      = errors.New("native installation session is unavailable")
	ErrNativePersistence             = errors.New("native history persistence is uncertain")
	ErrNativeDependenciesUnavailable = errors.New("native dependency verification is unavailable in this version; installation is denied")
)

type nativeJournalFailure struct{ kind, cause error }

func (e *nativeJournalFailure) Error() string { return e.kind.Error() }
func (e *nativeJournalFailure) Unwrap() []error {
	if e.cause == nil {
		return []error{e.kind}
	}
	return []error{e.kind, e.cause}
}
func nativeJournalFail(kind, cause error) error { return &nativeJournalFailure{kind, cause} }

func nativeJournalPublic(err error) error {
	if err == nil {
		return nil
	}
	kind := errors.New("native journal operation failed")
	for _, candidate := range []error{ErrNativePersistence, ErrNativeEvidenceInvalid, ErrNativeHistoryExists, ErrNativeHistoryStale, ErrNativeSubjectRevoked, ErrNativeHistoryInvalid, ErrNativeHistoryRequired, ErrNativeSessionUnavailable} {
		if errors.Is(err, candidate) {
			kind = candidate
			break
		}
	}
	return nativeJournalFail(kind, err)
}

// NativeJournalStatus is copied authenticated history, not mutation permission.
type NativeJournalStatus struct {
	HistoryAuthorityID, EvidenceDigest string
	Epoch                              int64
	IssuedAt, LastSeen                 time.Time
}

// NativeJournal owns explicit native history. Only Enroll creates its reservation.
type NativeJournal struct {
	selection *NativeInstallSelection
	base, dir string
	now       func() time.Time
	ops       nativeJournalFileOps
}

// OpenNativeJournal snapshots an explicit selection without creating state.
func OpenNativeJournal(selection *NativeInstallSelection) (*NativeJournal, error) {
	if selection == nil || selection.validate() != nil {
		return nil, ErrNativeHistoryInvalid
	}
	// Selection fields are private immutable snapshots. Keep a separate descriptor
	// so a caller cannot redirect an existing journal by replacing its selection.
	copySelection := *selection
	copySelection.runtimeRaw = append([]byte(nil), selection.runtimeRaw...)
	roots, err := snapshotAgentRoots(selection.artifactRoots)
	if err != nil {
		return nil, ErrNativeHistoryInvalid
	}
	copySelection.artifactRoots = roots
	authority, err := selection.authority.WithPolicy(selection.authority.minimumEpoch, selection.authority.maxAge)
	if err != nil {
		return nil, ErrNativeHistoryInvalid
	}
	copySelection.authority = authority
	if !nativeSHA(authority.historyID) {
		return nil, ErrNativeHistoryInvalid
	}
	base := filepath.Join(selection.home, ".claude", "native-mutation-state")
	return &NativeJournal{selection: &copySelection, base: base, dir: filepath.Join(base, authority.historyID), now: func() time.Time { return time.Now().UTC() }, ops: defaultNativeJournalFileOps()}, nil
}
func nativeJournalContext(ctx context.Context) error {
	if ctx == nil {
		return ErrNativeSessionUnavailable
	}
	return ctx.Err()
}
func (j *NativeJournal) valid() error {
	if j == nil || j.selection == nil || j.now == nil || j.selection.validate() != nil || j.dir != filepath.Join(j.selection.home, ".claude", "native-mutation-state", j.selection.authority.historyID) {
		return ErrNativeHistoryInvalid
	}
	return nil
}

// Status authenticates retained history, including old history needed for Adopt.
func (j *NativeJournal) Status(ctx context.Context) (status NativeJournalStatus, err error) {
	defer func() {
		err = nativeJournalPublic(err)
		if err != nil {
			status = NativeJournalStatus{}
		}
	}()
	lease, err := j.acquire(ctx)
	if err != nil {
		return status, err
	}
	defer func() {
		err = errors.Join(err, lease.Close())
		if err != nil {
			status = NativeJournalStatus{}
		}
	}()
	record, _, err := lease.load(ctx)
	if err != nil {
		return status, err
	}
	return record.status(), nil
}

// Enroll reserves an absent authority directory. Interrupted reservations cannot
// be automatically retried or repaired by this API.
func (j *NativeJournal) Enroll(ctx context.Context, raw []byte) (status NativeJournalStatus, err error) {
	defer func() {
		err = nativeJournalPublic(err)
		if err != nil {
			status = NativeJournalStatus{}
		}
	}()
	if err = nativeJournalContext(ctx); err != nil {
		return status, err
	}
	if err = j.valid(); err != nil {
		return status, err
	}
	evidence, err := authenticateNativeEvidence(raw, j.selection.authority)
	if err != nil {
		return status, nativeJournalFail(ErrNativeEvidenceInvalid, err)
	}
	now := j.now().UTC()
	if err = j.fresh(evidence, now); err != nil {
		return status, err
	}
	dirs, err := j.openDirs(true)
	if err != nil {
		return status, err
	}
	defer func() {
		err = errors.Join(err, closeNativeJournalDirs(dirs, j.ops))
		if err != nil {
			status = NativeJournalStatus{}
		}
	}()
	parent := dirs[len(dirs)-1]
	if err = parent.root.Mkdir(j.selection.authority.historyID, 0700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return status, ErrNativeHistoryExists
		}
		return status, nativeJournalFail(ErrNativePersistence, err)
	}
	if err = nativeJournalSecure(j.dir); err != nil {
		return status, nativeJournalFail(ErrNativePersistence, err)
	}
	if err = j.ops.syncDir(j.base); err != nil {
		return status, nativeJournalFail(ErrNativePersistence, err)
	}
	authorityDir, err := openNativeJournalDir(parent, j.selection.authority.historyID, true)
	if err != nil {
		return status, nativeJournalFail(ErrNativePersistence, err)
	}
	dirs = append(dirs, authorityDir)
	lock, err := authorityDir.root.OpenFile(nativeJournalLock, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return status, nativeJournalFail(ErrNativePersistence, err)
	}
	e := nativeJournalSecure(filepath.Join(j.dir, nativeJournalLock))
	if e == nil {
		e = errors.Join(j.ops.sync(lock), j.ops.syncDir(j.dir))
	}
	e = errors.Join(e, j.ops.close(lock))
	if e != nil {
		return status, nativeJournalFail(ErrNativePersistence, e)
	}
	// Close this initial directory chain before acquiring the stable lock afresh.
	e = closeNativeJournalDirs(dirs, j.ops)
	dirs = nil
	if e != nil {
		return status, nativeJournalFail(ErrNativePersistence, e)
	}
	lease, err := j.acquire(ctx)
	if err != nil {
		return status, err
	}
	defer func() {
		err = errors.Join(err, lease.Close())
		if err != nil {
			status = NativeJournalStatus{}
		}
	}()
	now = j.now().UTC()
	if err = j.fresh(evidence, now); err != nil {
		return status, err
	}
	record := j.newRecord(evidence, now)
	if err = lease.publish(ctx, record, evidence); err != nil {
		return status, err
	}
	return record.status(), nil
}

// Adopt is an explicit authenticated update of an already enrolled history.
func (j *NativeJournal) Adopt(ctx context.Context, raw []byte) (status NativeJournalStatus, err error) {
	defer func() {
		err = nativeJournalPublic(err)
		if err != nil {
			status = NativeJournalStatus{}
		}
	}()
	if err = nativeJournalContext(ctx); err != nil {
		return status, err
	}
	if len(raw) == 0 || len(raw) > nativeJournalEvidenceMax {
		return status, ErrNativeEvidenceInvalid
	}
	lease, err := j.acquire(ctx)
	if err != nil {
		return status, err
	}
	defer func() {
		err = errors.Join(err, lease.Close())
		if err != nil {
			status = NativeJournalStatus{}
		}
	}()
	old, previous, err := lease.load(ctx)
	if err != nil {
		return status, err
	}
	now := j.now().UTC()
	if now.IsZero() || now.Before(old.LastSeen) {
		return status, ErrNativeHistoryStale
	}
	evidence, err := authenticateNativeEvidence(raw, j.selection.authority)
	if err != nil {
		return status, nativeJournalFail(ErrNativeEvidenceInvalid, err)
	}
	if err = j.fresh(evidence, now); err != nil {
		return status, err
	}
	if evidence.epoch < old.Epoch || evidence.issued.Before(old.IssuedAt) || (evidence.epoch == old.Epoch && (!sameNativeDigestSet(evidence.set, previous.set) || !sameNativeDigestSet(evidence.emergency, previous.emergency))) {
		return status, ErrNativeHistoryStale
	}
	record := j.newRecord(evidence, now)
	if err = lease.publish(ctx, record, evidence); err != nil {
		return status, err
	}
	return record.status(), nil
}
func sameNativeDigestSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aa := append([]string(nil), a...)
	bb := append([]string(nil), b...)
	sort.Strings(aa)
	sort.Strings(bb)
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}
func (j *NativeJournal) fresh(e *nativeAuthenticatedEvidence, now time.Time) error {
	if now.IsZero() || e.epoch < j.selection.authority.minimumEpoch || e.issued.After(now) || now.Sub(e.issued) > j.selection.authority.maxAge {
		return ErrNativeHistoryStale
	}
	return nil
}

type nativeJournalLease struct {
	journal          *NativeJournal
	dirs             []*nativeJournalDir
	file             *os.File
	stateInfo        os.FileInfo
	history          *nativeJournalRecord
	poisoned, closed bool
	closeErr         error
	mu               sync.Mutex
}

func (l *nativeJournalLease) Close() error {
	if l == nil {
		return ErrNativeSessionUnavailable
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return l.closeErr
	}
	l.closed = true
	if l.journal == nil || l.file == nil {
		l.closeErr = ErrNativeSessionUnavailable
		return l.closeErr
	}
	l.closeErr = errors.Join(l.journal.ops.close(l.file), closeNativeJournalDirs(l.dirs, l.journal.ops))
	l.file = nil
	l.dirs = nil
	if l.closeErr != nil {
		l.closeErr = nativeJournalFail(ErrNativePersistence, l.closeErr)
	}
	return l.closeErr
}
func (l *nativeJournalLease) recheck(ctx context.Context, rootDigest string) error {
	if l == nil {
		return ErrNativeSessionUnavailable
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.file == nil || l.journal == nil || l.poisoned {
		return ErrNativeSessionUnavailable
	}
	if err := nativeJournalContext(ctx); err != nil {
		return err
	}
	if len(rootDigest) != 71 || !strings.HasPrefix(rootDigest, "sha256:") || !nativeSHA(rootDigest[7:]) {
		return ErrNativeEvidenceInvalid
	}
	r, e, err := l.load(ctx)
	if err != nil {
		l.poisoned = true
		return err
	}
	if l.history != nil && !sameNativeRecord(*l.history, r) {
		return ErrNativeHistoryInvalid
	}
	now := l.journal.now().UTC()
	if now.IsZero() || now.Before(r.LastSeen) {
		return ErrNativeHistoryStale
	}
	denial := l.journal.fresh(e, now)
	if denial == nil {
		for _, d := range e.set {
			if d == rootDigest {
				denial = ErrNativeSubjectRevoked
				break
			}
		}
	}
	r.LastSeen = now
	if err = l.publish(ctx, r, e); err != nil {
		return errors.Join(denial, err)
	}
	return denial
}
