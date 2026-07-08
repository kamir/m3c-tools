// spool.go — the bounded JSONL fallback for R-2.4 hot-path safety.
//
// When Append can't reach the db (SQLITE_BUSY at the ~250ms pin, or an open
// failure), the caller spools the row here so the DECISION RETURNS REGARDLESS
// (R-2.4 / R-8.1 default). The spool is a single O_APPEND Write per line (0600),
// which is cross-process atomic for lines below PIPE_BUF — the same discipline
// the invocation-trail.jsonl appender uses. The next sync/enforce Reconcile
// drains it into audit_events in occurred_at order (R-2.5).
//
// NOT-YET-BUILT (AC-5a): per-batch translog anchoring — stamping translog_seq and
// emitting a signed tree head so the local trail becomes tamper-EVIDENT — is not
// wired. BackfillTranslogSeq exists and is unit-tested, but NOTHING in the
// sync/enforce drain calls it, so translog_seq stays NULL in production and there
// is no local-monotonicity guarantee to preserve here. The tamper-detection claim
// is therefore scoped to the sync DURABLE-SEQ path (a row is marked synced only on
// a VALID counter-signed durable-seq ack), NOT to local translog monotonicity.
// Reconcile only ORDERS rows by occurred_at; it does not anchor.
package outbox

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

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

// Spool appends one row to spool.jsonl as a single O_APPEND Write (0600). It is
// the fallback the caller invokes when Append fails; it performs no db I/O so it
// cannot itself stall on the lock that made Append fail.
func (s *Store) Spool(rec skillgate.InvocationRecord, payloadJSON, payloadHash string) error {
	line, err := json.Marshal(spoolEntry{Record: rec, PayloadJSON: payloadJSON, PayloadHash: payloadHash})
	if err != nil {
		return fmt.Errorf("outbox: spool marshal: %w", err)
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("outbox: spool mkdir: %w", err)
	}
	f, err := os.OpenFile(s.SpoolPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("outbox: spool open: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("outbox: spool write: %w", err)
	}
	return nil
}

// Reconcile drains spool.jsonl into audit_events in occurred_at order and, on
// success, removes the spool file. It is idempotent end-to-end: each row is an
// INSERT OR IGNORE keyed on event_id, so a crash between the inserts and the
// unlink just replays the same no-ops on the next Reconcile. Returns the number
// of rows drained (distinct inserts attempted, including dedup no-ops).
//
// Ordering (R-2.5): rows are sorted by occurred_at (then event_id) before insert
// so a FUTURE translog anchor (AC-5a, NOT-YET-BUILT) could stamp translog_seq in a
// stable order; today nothing anchors, so this ordering only fixes the insert
// order of spilled rows. A malformed line is SKIPPED (counted) rather than
// aborting the whole drain — one bad line must not strand the rest of the queue.
func (s *Store) Reconcile() (drained int, err error) {
	path := s.SpoolPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil // nothing spooled
		}
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

	// occurred_at order (R-2.5), stable on event_id.
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Record.OccurredAt != entries[j].Record.OccurredAt {
			return entries[i].Record.OccurredAt < entries[j].Record.OccurredAt
		}
		return entries[i].Record.EventID < entries[j].Record.EventID
	})

	for _, e := range entries {
		if aerr := s.Append(e.Record, e.PayloadJSON, e.PayloadHash); aerr != nil {
			// The db is still contended — leave the spool in place so a later
			// Reconcile retries (idempotent). Report what we managed to drain.
			return drained, fmt.Errorf("outbox: reconcile append: %w", aerr)
		}
		drained++
	}

	// All rows landed (dedup no-ops included). Remove the spool; a fresh failure
	// re-creates it. Skipped malformed lines are dropped with the file — they are
	// unusable evidence by definition (no valid event_id to anchor).
	if rerr := os.Remove(path); rerr != nil && !os.IsNotExist(rerr) {
		return drained, fmt.Errorf("outbox: reconcile cleanup: %w", rerr)
	}
	_ = skipped
	return drained, nil
}
