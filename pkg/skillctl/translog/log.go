package translog

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DefaultLogPath is the conventional on-disk location of the local
// append-only transparency log, relative to the user's home directory.
const DefaultLogPath = ".claude/skillctl/transparency-log.jsonl"

// Log is an in-memory RFC-6962 Merkle log backed by an append-only JSONL
// file. Each line is one LogEntry; the file order IS the leaf order. The
// log is the authoritative local record from which STHs and inclusion
// proofs are produced.
//
// Concurrency: a single process mutex guards Append + persistence. The file
// is opened O_APPEND so concurrent processes append atomically at the OS
// level for lines below PIPE_BUF; cross-process ordering beyond that is out
// of L1 scope (a single local agent owns its log).
type Log struct {
	mu      sync.Mutex
	path    string
	logID   string
	entries []LogEntry
	leaves  [][HashSize]byte
}

// Errors specific to the log container.
var (
	// ErrLogIDRequired — a Log needs a non-empty, well-formed log id.
	ErrLogIDRequired = errors.New("translog: log_id is required")
)

// OpenLog loads (or initialises) the append-only log at path for the given
// logID. A missing file yields an empty log ready to Append; a malformed
// line aborts the load (we never silently skip corrupt history — that would
// hide tampering). logID must satisfy logIDPattern.
func OpenLog(path, logID string) (*Log, error) {
	if path == "" {
		return nil, errors.New("translog: log path is required")
	}
	if !logIDPattern.MatchString(logID) {
		return nil, fmt.Errorf("%w: %q invalid (allowed [A-Za-z0-9._:-], 1-128 chars)", ErrLogIDRequired, logID)
	}
	l := &Log{path: path, logID: logID}

	f, err := os.Open(path) //nolint:gosec // path is operator-provided, not attacker-tainted
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return l, nil // fresh log
		}
		return nil, fmt.Errorf("translog: open %s: %w", path, err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	// Allow long lines (a JSON entry is small, but be generous).
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := sc.Bytes()
		if len(raw) == 0 {
			continue
		}
		var e LogEntry
		if err := json.Unmarshal(raw, &e); err != nil {
			return nil, fmt.Errorf("translog: %s line %d: bad JSON: %w", path, lineNo, err)
		}
		leaf, err := e.LeafHash()
		if err != nil {
			return nil, fmt.Errorf("translog: %s line %d: invalid entry: %w", path, lineNo, err)
		}
		l.entries = append(l.entries, e)
		l.leaves = append(l.leaves, leaf)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("translog: read %s: %w", path, err)
	}
	return l, nil
}

// DefaultLogFilePath returns the absolute default log path under the user's
// home directory.
func DefaultLogFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("translog: resolve home dir: %w", err)
	}
	return filepath.Join(home, DefaultLogPath), nil
}

// Size returns the current number of leaves (entries) in the log.
func (l *Log) Size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

// LogID returns the log's identifier.
func (l *Log) LogID() string { return l.logID }

// Append validates the entry, appends it to the in-memory tree, and
// durably appends one JSON line to the backing file. It returns the index
// the entry was assigned (its leaf position) so the caller can immediately
// request an inclusion proof.
//
// Persistence is fsync'd before returning so a crash cannot lose an entry
// that a caller believes was logged. If the disk write fails the in-memory
// state is rolled back so the tree and the file never diverge.
func (l *Log) Append(e LogEntry) (int, error) {
	leaf, err := e.LeafHash()
	if err != nil {
		return -1, err
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	line, err := json.Marshal(e)
	if err != nil {
		return -1, fmt.Errorf("translog: marshal entry: %w", err)
	}

	if err := l.appendLine(line); err != nil {
		return -1, err
	}

	idx := len(l.entries)
	l.entries = append(l.entries, e)
	l.leaves = append(l.leaves, leaf)
	return idx, nil
}

// appendLine writes one JSONL record (line + '\n') to the backing file with
// O_APPEND and fsyncs. Best-effort directory creation on first write.
func (l *Log) appendLine(line []byte) error {
	if dir := filepath.Dir(l.path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("translog: create dir %s: %w", dir, err)
		}
	}
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("translog: open for append %s: %w", l.path, err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		_ = f.Close()
		return fmt.Errorf("translog: append %s: %w", l.path, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("translog: fsync %s: %w", l.path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("translog: close %s: %w", l.path, err)
	}
	return nil
}

// Root returns the current Merkle Tree Hash over all entries. Errors with
// ErrEmptyTree when the log has no entries.
func (l *Log) Root() ([HashSize]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return MerkleTreeHash(l.leaves)
}

// SignHead builds and signs an STH over the current tree state with the
// log's ed25519 private key, stamped at time t (UTC seconds). Errors with
// ErrEmptyTree on an empty log — there is nothing to commit.
func (l *Log) SignHead(logKey ed25519.PrivateKey, t time.Time) (STH, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	root, err := MerkleTreeHash(l.leaves)
	if err != nil {
		return STH{}, err
	}
	s := STH{
		TreeSize:  len(l.leaves),
		RootHash:  hex.EncodeToString(root[:]),
		Timestamp: FormatSTHTimestamp(t),
		LogID:     l.logID,
	}
	return SignSTH(logKey, s)
}

// ProveInclusion returns the inclusion proof for the entry at index against
// the CURRENT tree size. The returned proof verifies (with the leaf hash
// and the current root) via VerifyInclusion.
func (l *Log) ProveInclusion(index int) (proof [][HashSize]byte, size int, leaf [HashSize]byte, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	size = len(l.leaves)
	if index < 0 || index >= size {
		return nil, size, leaf, fmt.Errorf("%w: index=%d size=%d", ErrIndexOutOfRange, index, size)
	}
	leaf = l.leaves[index]
	p, err := InclusionProof(index, size, l.leaves)
	if err != nil {
		return nil, size, leaf, err
	}
	return p, size, leaf, nil
}

// ProveConsistency returns the consistency proof between an earlier size
// `from` and the current size. Errors if from is out of range.
func (l *Log) ProveConsistency(from int) (proof [][HashSize]byte, second int, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	second = len(l.leaves)
	if from < 0 || from > second {
		return nil, second, fmt.Errorf("%w: from=%d size=%d", ErrBadConsistencyArgs, from, second)
	}
	p, err := ConsistencyProof(from, second, l.leaves)
	if err != nil {
		return nil, second, err
	}
	return p, second, nil
}

// EntryAt returns a copy of the entry at index (read-only access for CLI
// display and proof export).
func (l *Log) EntryAt(index int) (LogEntry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if index < 0 || index >= len(l.entries) {
		return LogEntry{}, fmt.Errorf("%w: index=%d size=%d", ErrIndexOutOfRange, index, len(l.entries))
	}
	return l.entries[index], nil
}

// FindByDigest returns the indices of all entries whose Digest matches.
// Used by the CLI `prove <event>` verb to resolve an event reference to its
// leaf position without the caller tracking indices.
func (l *Log) FindByDigest(digest string) []int {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []int
	for i, e := range l.entries {
		if e.Digest == digest {
			out = append(out, i)
		}
	}
	return out
}

// LeafHashes returns a copy of the current leaf-hash slice, so a caller can
// build proofs externally without holding the lock. Defensive copy: callers
// must not be able to mutate the log's internal state.
func (l *Log) LeafHashes() [][HashSize]byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([][HashSize]byte, len(l.leaves))
	copy(out, l.leaves)
	return out
}

// writeJSONLines is a small helper for tests / export: dump the entries as
// JSONL to w in order.
func (l *Log) writeJSONLines(w io.Writer) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	bw := bufio.NewWriter(w)
	for _, e := range l.entries {
		b, err := json.Marshal(e)
		if err != nil {
			return err
		}
		if _, err := bw.Write(append(b, '\n')); err != nil {
			return err
		}
	}
	return bw.Flush()
}
