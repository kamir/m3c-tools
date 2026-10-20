// The fallback audit spool uses OS file locks and durable writes. Reconcile
// rotates the active file into an immutable pending batch before database I/O,
// so concurrent appends cannot be deleted by a drain. A process crash releases
// locks; an unfinished pending batch is replayed using event_id deduplication.
package outbox

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillgate"
)

// spoolEntry is the on-disk envelope: the full signed record plus the two
// derivations Append needs. Storing payload_json/payload_hash here (rather than
// re-deriving on reconcile) pins the exact bytes once so the spooled row and a
// directly-appended row are byte-identical (no per-sink divergence).
type spoolEntry struct {
	Record      skillgate.InvocationRecord `json:"record"`
	PayloadJSON string                     `json:"payload_json"`
	PayloadHash string                     `json:"payload_hash"`
}

// SpoolPath is the fallback file beside outbox.db.
func (s *Store) SpoolPath() string { return filepath.Join(s.dir, "spool.jsonl") }

// Spool durably appends one row to spool.jsonl. Lock contention is bounded;
// filesystem write and sync latency depends on the underlying storage.
func (s *Store) Spool(rec skillgate.InvocationRecord, payloadJSON, payloadHash string) error {
	return spoolAppend(s.dir, rec, payloadJSON, payloadHash)
}

// SpoolTo durably appends without opening the database, including when the
// database cannot be opened. Errors from locking, writes, sync and close reach
// the caller so it can enforce its local-audit requirement.
func SpoolTo(home string, rec skillgate.InvocationRecord, payloadJSON, payloadHash string) error {
	return spoolAppend(dirName(home), rec, payloadJSON, payloadHash)
}

func spoolAppend(dir string, rec skillgate.InvocationRecord, payloadJSON, payloadHash string) error {
	line, err := json.Marshal(spoolEntry{Record: rec, PayloadJSON: payloadJSON, PayloadHash: payloadHash})
	if err != nil {
		return fmt.Errorf("outbox: spool marshal: %w", err)
	}
	if err := ensureSpoolDir(dir); err != nil {
		return err
	}
	lock, err := acquireSpoolLock(filepath.Join(dir, "spool.lock"))
	if err != nil {
		return err
	}
	return errors.Join(writeSpoolLine(filepath.Join(dir, "spool.jsonl"), append(line, '\n')), lock.Close())
}

func writeSpoolLine(path string, line []byte) error {
	// #nosec G304 -- caller constructs the fixed spool filename under its private local audit directory; no bundle or remote path is accepted.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("outbox: spool open: %w", err)
	}
	if err := persistSpoolLine(f, line); err != nil {
		return fmt.Errorf("outbox: spool write/sync/close: %w", err)
	}
	return syncSpoolDir(filepath.Dir(path))
}

type spoolWriter interface {
	Write([]byte) (int, error)
	Sync() error
	Close() error
}

func persistSpoolLine(f spoolWriter, line []byte) error {
	n, writeErr := f.Write(line)
	if writeErr == nil && n != len(line) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = f.Sync()
	}
	return errors.Join(writeErr, f.Close())
}

func ensureSpoolDir(dir string) error {
	var created []string
	for path := dir; ; path = filepath.Dir(path) {
		if _, err := os.Stat(path); err == nil {
			break
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("outbox: spool directory stat: %w", err)
		}
		created = append(created, path)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("outbox: spool mkdir: %w", err)
	}
	// Persist newly created directory entries through their existing ancestor.
	for _, path := range created {
		if err := syncSpoolDir(filepath.Dir(path)); err != nil {
			return err
		}
	}
	return nil
}

// Lock files are never unlinked: replacing their inode would allow two callers
// to hold apparently exclusive locks on different files. Close releases the OS
// lock even if a process exits before its deferred cleanup runs.
func acquireSpoolLock(path string) (*os.File, error) {
	// #nosec G304 -- callers supply fixed lock filenames under the operator-owned audit directory, never paths from remote events.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("outbox: spool lock open: %w", err)
	}
	deadline := time.Now().Add(50 * time.Millisecond)
	for {
		err = trySpoolLock(f)
		if err == nil {
			return f, nil
		}
		if !spoolLockBusy(err) || !time.Now().Before(deadline) {
			return nil, fmt.Errorf("outbox: spool lock: %w", errors.Join(err, f.Close()))
		}
		time.Sleep(time.Millisecond)
	}
}

// rotateSpool keeps a previously interrupted batch intact. Active writers take
// the same lock only while the active filename is renamed, never during SQL.
func (s *Store) rotateSpool() (path string, err error) {
	lock, err := acquireSpoolLock(filepath.Join(s.dir, "spool.lock"))
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	path = filepath.Join(s.dir, "spool.pending.jsonl")
	if _, err := os.Stat(path); err == nil {
		return path, nil
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("outbox: pending spool stat: %w", err)
	}
	if err := renameSpool(s.SpoolPath(), path); err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("outbox: spool rotate: %w", err)
	}
	return path, syncSpoolDir(s.dir)
}

// Reconcile drains one immutable pending batch in occurred_at order. Rows are
// deduplicated by event_id, so interrupted drains replay safely. Malformed
// evidence is retained in the pending file and reported, never silently removed.
// A subsequent call drains appends made while the previous batch was processing.
func (s *Store) Reconcile() (drained int, err error) {
	lock, err := acquireSpoolLock(filepath.Join(s.dir, "spool.drain.lock"))
	if err != nil {
		return 0, err
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	path, err := s.rotateSpool()
	if err != nil || path == "" {
		return 0, err
	}
	// #nosec G304 -- rotateSpool returns only the fixed pending filename inside this store's local audit directory.
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("outbox: reconcile read: %w", err)
	}

	var (
		entries []spoolEntry
		skipped int
	)
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}
		var e spoolEntry
		if uerr := json.Unmarshal(raw, &e); uerr != nil || e.Record.EventID == "" {
			skipped++
			continue
		}
		entries = append(entries, e)
	}
	if serr := sc.Err(); serr != nil {
		return 0, fmt.Errorf("outbox: reconcile scan: %w", serr)
	}

	// Keep insertion order stable across retries.
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Record.OccurredAt != entries[j].Record.OccurredAt {
			return entries[i].Record.OccurredAt < entries[j].Record.OccurredAt
		}
		return entries[i].Record.EventID < entries[j].Record.EventID
	})

	for _, e := range entries {
		if aerr := s.Append(e.Record, e.PayloadJSON, e.PayloadHash); aerr != nil {
			// The db is still contended: leave the spool in place so a later
			// Reconcile retries (idempotent). Report what we managed to drain.
			return drained, fmt.Errorf("outbox: reconcile append: %w", aerr)
		}
		drained++
	}

	if skipped != 0 {
		return drained, fmt.Errorf("outbox: reconcile retained %s: %d malformed line(s)", path, skipped)
	}
	if rerr := os.Remove(path); rerr != nil {
		return drained, fmt.Errorf("outbox: reconcile cleanup: %w", rerr)
	}
	return drained, syncSpoolDir(s.dir)
}
