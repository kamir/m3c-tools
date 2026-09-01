package outbox

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillgate"
)

// testKey is a fixed ed25519 key so records are deterministically signable.
var testKey = func() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	return ed25519.NewKeyFromSeed(seed)
}()

// makeRecord builds a signed InvocationRecord with a distinct event_id and
// occurred_at, plus its RecordPayload derivations.
func makeRecord(t *testing.T, idx int, occurred string) (skillgate.InvocationRecord, string, string) {
	t.Helper()
	rec := skillgate.InvocationRecord{
		Schema:      skillgate.InvocationSchema,
		EventID:     fmt.Sprintf("inv:%013d:%04x", time.Now().UnixMilli(), idx),
		EventType:   "skill.invocation",
		SkillName:   "demo-skill",
		SkillDigest: "sha256:deadbeef",
		Tool:        "Skill",
		OccurredAt:  occurred,
		DeviceKeyID: "test-key",
		ExitCode:    0,
	}
	signFn := func(msg []byte) []byte { return ed25519.Sign(testKey, msg) }
	if err := skillgate.SignInvocationRecord(&rec, signFn, base64.StdEncoding.EncodeToString); err != nil {
		t.Fatalf("sign: %v", err)
	}
	pj, ph, err := RecordPayload(rec)
	if err != nil {
		t.Fatalf("RecordPayload: %v", err)
	}
	return rec, pj, ph
}

func openTemp(t *testing.T) *Store {
	t.Helper()
	home := t.TempDir()
	s, err := Open(home)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestAppendAndPendingBatch(t *testing.T) {
	s := openTemp(t)
	rec, pj, ph := makeRecord(t, 1, "2026-07-08T10:00:00Z")
	if err := s.Append(rec, pj, ph); err != nil {
		t.Fatalf("Append: %v", err)
	}
	batch, err := s.PendingBatch(10)
	if err != nil {
		t.Fatalf("PendingBatch: %v", err)
	}
	if len(batch) != 1 {
		t.Fatalf("want 1 pending, got %d", len(batch))
	}
	got := batch[0]
	if got.EventID != rec.EventID || got.PayloadHash != ph || got.SignatureB64 != rec.DeviceSignatureB64 {
		t.Fatalf("row mismatch: %+v", got)
	}
	if got.Decision != "allow" {
		t.Fatalf("decision: want allow got %q", got.Decision)
	}
	if got.SyncStatus != 0 {
		t.Fatalf("sync_status: want 0 got %d", got.SyncStatus)
	}
}

func TestAppendDedupOnEventID(t *testing.T) {
	s := openTemp(t)
	rec, pj, ph := makeRecord(t, 7, "2026-07-08T10:00:00Z")
	for i := 0; i < 3; i++ {
		if err := s.Append(rec, pj, ph); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	n, err := s.PendingCount()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("replayed event_id must dedup: want 1 got %d", n)
	}
}

// TestPendingBatchDueExcludesFutureBackoff — the backoff-aware drain set: a row
// whose delivery_attempts.next_retry_at is in the future is EXCLUDED until the
// backoff elapses, while a row with no attempts (or an elapsed next_retry_at) is
// due. This is what stops the sync daemon re-posting a just-deferred row.
func TestPendingBatchDueExcludesFutureBackoff(t *testing.T) {
	s := openTemp(t)
	recA, pjA, phA := makeRecord(t, 1, "2026-07-08T10:00:00Z")
	recB, pjB, phB := makeRecord(t, 2, "2026-07-08T10:00:01Z")
	if err := s.Append(recA, pjA, phA); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(recB, pjB, phB); err != nil {
		t.Fatal(err)
	}

	const now = "2026-07-08T12:00:00Z"
	// A: deferred into the future — must be excluded.
	if err := s.RecordAttempt(recA.EventID, 1, "2026-07-08T11:59:00Z", 500, "5xx", "2026-07-08T12:30:00Z"); err != nil {
		t.Fatal(err)
	}
	// B: an elapsed backoff — must be due again.
	if err := s.RecordAttempt(recB.EventID, 1, "2026-07-08T11:00:00Z", 500, "5xx", "2026-07-08T11:30:00Z"); err != nil {
		t.Fatal(err)
	}

	due, err := s.PendingBatchDue(10, now)
	if err != nil {
		t.Fatalf("PendingBatchDue: %v", err)
	}
	if len(due) != 1 || due[0].EventID != recB.EventID {
		var ids []string
		for _, e := range due {
			ids = append(ids, e.EventID)
		}
		t.Fatalf("due set = %v, want only %s (A is backed off into the future)", ids, recB.EventID)
	}

	// After A's backoff elapses, both are due.
	if all, _ := s.PendingBatchDue(10, "2026-07-08T13:00:00Z"); len(all) != 2 {
		t.Fatalf("after backoff elapses both rows must be due; got %d", len(all))
	}
}

func TestConcurrentAppend(t *testing.T) {
	s := openTemp(t)
	const n = 64
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec, pj, ph := makeRecord(t, i, "2026-07-08T10:00:00Z")
			errs[i] = s.Append(rec, pj, ph)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	count, err := s.PendingCount()
	if err != nil {
		t.Fatal(err)
	}
	if count != n {
		t.Fatalf("want %d rows, got %d", n, count)
	}
}

func TestMarkSynced(t *testing.T) {
	s := openTemp(t)
	rec, pj, ph := makeRecord(t, 2, "2026-07-08T10:00:00Z")
	if err := s.Append(rec, pj, ph); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkSynced(rec.EventID, "2026-07-08T11:00:00Z"); err != nil {
		t.Fatalf("MarkSynced: %v", err)
	}
	if n, _ := s.PendingCount(); n != 0 {
		t.Fatalf("synced row must leave pending: got %d", n)
	}
	ev, ok, err := s.Get(rec.EventID)
	if err != nil || !ok {
		t.Fatalf("Get: ok=%v err=%v", ok, err)
	}
	if ev.SyncStatus != 1 || ev.SyncedAt != "2026-07-08T11:00:00Z" {
		t.Fatalf("mark-synced not persisted: %+v", ev)
	}
	// Idempotent re-mark.
	if err := s.MarkSynced(rec.EventID, "2026-07-08T12:00:00Z"); err != nil {
		t.Fatalf("re-MarkSynced: %v", err)
	}
}

func TestWriteOnceEvidenceColumnsRejected(t *testing.T) {
	s := openTemp(t)
	rec, pj, ph := makeRecord(t, 3, "2026-07-08T10:00:00Z")
	if err := s.Append(rec, pj, ph); err != nil {
		t.Fatal(err)
	}

	// Direct mutation of an evidence column must ABORT via the trigger.
	if _, err := s.db.Exec(`UPDATE audit_events SET decision='deny' WHERE event_id=?`, rec.EventID); err == nil {
		t.Fatal("expected trigger to reject decision rewrite")
	}
	if _, err := s.db.Exec(`UPDATE audit_events SET signature_b64='forged' WHERE event_id=?`, rec.EventID); err == nil {
		t.Fatal("expected trigger to reject signature rewrite")
	}
	if _, err := s.db.Exec(`UPDATE audit_events SET payload_json='{"tampered":true}' WHERE event_id=?`, rec.EventID); err == nil {
		t.Fatal("expected trigger to reject payload_json rewrite")
	}
	// DELETE is forbidden entirely.
	if _, err := s.db.Exec(`DELETE FROM audit_events WHERE event_id=?`, rec.EventID); err == nil {
		t.Fatal("expected trigger to reject DELETE")
	}

	// Retention NULL-ing of payload_json is PERMITTED.
	if _, err := s.db.Exec(`UPDATE audit_events SET payload_json=NULL WHERE event_id=?`, rec.EventID); err != nil {
		t.Fatalf("retention null of payload_json must be permitted: %v", err)
	}
}

func TestBackfillTranslogSeqOnceThenLocked(t *testing.T) {
	s := openTemp(t)
	rec, pj, ph := makeRecord(t, 4, "2026-07-08T10:00:00Z")
	if err := s.Append(rec, pj, ph); err != nil {
		t.Fatal(err)
	}
	if err := s.BackfillTranslogSeq(rec.EventID, 5); err != nil {
		t.Fatalf("first backfill: %v", err)
	}
	ev, _, _ := s.Get(rec.EventID)
	if !ev.TranslogSeq.Valid || ev.TranslogSeq.Int64 != 5 {
		t.Fatalf("translog_seq not set: %+v", ev.TranslogSeq)
	}
	// A second backfill via the guarded API is a no-op (WHERE seq IS NULL).
	if err := s.BackfillTranslogSeq(rec.EventID, 6); err != nil {
		t.Fatalf("guarded re-backfill should be a no-op: %v", err)
	}
	ev, _, _ = s.Get(rec.EventID)
	if ev.TranslogSeq.Int64 != 5 {
		t.Fatalf("guarded re-backfill changed seq to %d", ev.TranslogSeq.Int64)
	}
	// A direct rewrite of an already-set seq must ABORT via the trigger.
	if _, err := s.db.Exec(`UPDATE audit_events SET translog_seq=6 WHERE event_id=?`, rec.EventID); err == nil {
		t.Fatal("expected trigger to reject translog_seq rewrite once set")
	}
}

func TestRecordAttempt(t *testing.T) {
	s := openTemp(t)
	rec, pj, ph := makeRecord(t, 5, "2026-07-08T10:00:00Z")
	if err := s.Append(rec, pj, ph); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordAttempt(rec.EventID, 1, "2026-07-08T10:01:00Z", 503, "server busy", "2026-07-08T10:01:30Z"); err != nil {
		t.Fatalf("RecordAttempt: %v", err)
	}
	if err := s.RecordAttempt(rec.EventID, 2, "2026-07-08T10:02:00Z", 0, "dial timeout", "2026-07-08T10:03:00Z"); err != nil {
		t.Fatalf("RecordAttempt 2: %v", err)
	}
	// Replayed attempt number dedups.
	if err := s.RecordAttempt(rec.EventID, 1, "x", 500, "dup", "y"); err != nil {
		t.Fatalf("RecordAttempt dup: %v", err)
	}
	atts, err := s.Attempts(rec.EventID)
	if err != nil {
		t.Fatal(err)
	}
	if len(atts) != 2 {
		t.Fatalf("want 2 attempts, got %d", len(atts))
	}
	if atts[0].HTTPStatus != 503 || atts[1].HTTPStatus != 0 {
		t.Fatalf("attempt status mismatch: %+v", atts)
	}
	if atts[0].NextRetryAt != "2026-07-08T10:01:30Z" {
		t.Fatalf("next_retry_at mismatch: %q", atts[0].NextRetryAt)
	}
}

func TestSyncState(t *testing.T) {
	s := openTemp(t)
	if _, ok, _ := s.GetSyncState("high_water_seq"); ok {
		t.Fatal("expected absent key")
	}
	if err := s.SetSyncState("high_water_seq", "42"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSyncState("high_water_seq", "43"); err != nil {
		t.Fatal(err)
	}
	v, ok, err := s.GetSyncState("high_water_seq")
	if err != nil || !ok || v != "43" {
		t.Fatalf("sync_state upsert: v=%q ok=%v err=%v", v, ok, err)
	}
}

func TestCachesEpochMonotonic(t *testing.T) {
	s := openTemp(t)
	base := CacheEntry{Key: "self-roots", Epoch: 5, ContentDigest: "sha256:aa", PayloadJSON: `{"v":5}`}
	if err := s.PutTrustCache(base); err != nil {
		t.Fatalf("put epoch 5: %v", err)
	}
	// Higher epoch accepted.
	if err := s.PutTrustCache(CacheEntry{Key: "self-roots", Epoch: 6, ContentDigest: "sha256:bb", PayloadJSON: `{"v":6}`}); err != nil {
		t.Fatalf("put epoch 6: %v", err)
	}
	// Lower epoch rejected.
	err := s.PutTrustCache(CacheEntry{Key: "self-roots", Epoch: 4, ContentDigest: "sha256:cc", PayloadJSON: `{"v":4}`})
	if err != ErrEpochRegression {
		t.Fatalf("want ErrEpochRegression, got %v", err)
	}
	got, ok, err := s.GetTrustCache("self-roots")
	if err != nil || !ok {
		t.Fatalf("GetTrustCache: ok=%v err=%v", ok, err)
	}
	if got.Epoch != 6 || got.PayloadJSON != `{"v":6}` {
		t.Fatalf("stale write leaked through: %+v", got)
	}
	// Equal epoch is permitted (a re-fetch of the same head).
	if err := s.PutPolicyCache(CacheEntry{Key: "p", Epoch: 1, ContentDigest: "d", PayloadJSON: "{}"}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutPolicyCache(CacheEntry{Key: "p", Epoch: 1, ContentDigest: "d", PayloadJSON: "{}"}); err != nil {
		t.Fatalf("equal epoch should be permitted: %v", err)
	}
	// Revocation cache keyed on digest.
	if err := s.PutRevocationCache(CacheEntry{Key: "sha256:evil", Epoch: 1, ContentDigest: "d", PayloadJSON: "{}"}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.GetRevocationCache("sha256:evil"); !ok {
		t.Fatal("revocation entry not found")
	}
}
