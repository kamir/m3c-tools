package auditevent

import (
	"encoding/json"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/outbox"
)

// The OutboxSink persists via the SPEC-0317 outbox, is idempotent on event_id
// (REQ-6.2), and stores the full envelope in payload_json for round-trip.
func TestOutboxSink_DurableAndIdempotent(t *testing.T) {
	home := t.TempDir()
	st, err := outbox.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	sink := NewOutboxSinkWithStore(st, home)

	e := New(EventPolicyAllow, OutcomeSuccess, SeverityInfo, "skillctl/test")
	e.EventID = "aud-idem-1"
	e.Skill = &SkillRef{Name: "compliance-review", Digest: "sha256:abc"}

	if err := sink.Write(e); err != nil {
		t.Fatalf("write 1: %v", err)
	}
	if err := sink.Write(e); err != nil {
		t.Fatalf("write 2 (replay): %v", err)
	}

	cnt, err := st.PendingCount()
	if err != nil {
		t.Fatal(err)
	}
	if cnt != 1 {
		t.Fatalf("idempotency on event_id failed: %d rows, want 1 (AUD-04/05)", cnt)
	}

	row, ok, err := st.Get("aud-idem-1")
	if err != nil || !ok {
		t.Fatalf("row missing: ok=%v err=%v", ok, err)
	}
	if row.EventType != "policy.allow" || row.Decision != "allow" || row.SkillName != "compliance-review" {
		t.Fatalf("index columns wrong: %+v", row)
	}
	if row.SignatureB64 != "" || row.DeviceKeyID != "" {
		t.Fatalf("an audit row must be UNSIGNED (REQ-1.2/AUD-08): sig=%q keyid=%q", row.SignatureB64, row.DeviceKeyID)
	}
	var back Event
	if err := json.Unmarshal([]byte(row.PayloadJSON), &back); err != nil {
		t.Fatalf("payload_json is not the envelope: %v", err)
	}
	if back.EventID != "aud-idem-1" || back.EventType != EventPolicyAllow {
		t.Fatalf("envelope did not round-trip out of payload_json: %+v", back)
	}
}

// The durable record survives a process restart: a fresh handle over the same
// home still finds it (inherent to the SQLite outbox).
func TestOutboxSink_SurvivesProcessRestart(t *testing.T) {
	home := t.TempDir()
	sink, err := NewOutboxSink(home)
	if err != nil {
		t.Fatal(err)
	}
	e := New(EventPolicyDeny, OutcomeDeny, SeverityWarning, "skillctl/test")
	e.EventID = "aud-restart-1"
	if err := sink.Write(e); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// A new process would reopen a fresh handle.
	st, err := outbox.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	row, ok, err := st.Get("aud-restart-1")
	if err != nil || !ok {
		t.Fatalf("row did not survive restart: ok=%v err=%v", ok, err)
	}
	if row.Decision != "deny" {
		t.Fatalf("deny index lost across restart: %+v", row)
	}
}

// When Open fails (spool-only sink), a Write still lands durably in spool.jsonl
// and a later Reconcile drains it into audit_events.
func TestOutboxSink_SpoolFallbackAndReconcile(t *testing.T) {
	home := t.TempDir()
	sink := NewOutboxSinkWithStore(nil, home) // spool-only (nil store)
	e := New(EventPolicyAllow, OutcomeSuccess, SeverityInfo, "skillctl/test")
	e.EventID = "aud-spool-1"
	if err := sink.Write(e); err != nil {
		t.Fatalf("spool write: %v", err)
	}

	st, err := outbox.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, ok, _ := st.Get("aud-spool-1"); ok {
		t.Fatalf("spool row must not be in the db before Reconcile")
	}
	drained, err := st.Reconcile()
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if drained != 1 {
		t.Fatalf("reconcile drained %d, want 1", drained)
	}
	if _, ok, _ := st.Get("aud-spool-1"); !ok {
		t.Fatalf("row not drained from spool into audit_events")
	}
}

// The durable Dispatcher plus the OutboxSink is the recommended production wiring
// (§6): an event dispatched in durable mode is persisted to the outbox.
func TestOutboxSink_DurableDispatcherPersists(t *testing.T) {
	home := t.TempDir()
	st, err := outbox.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	d := NewDispatcherMode(ModeDurable, DefaultRedactor(), NewOutboxSinkWithStore(st, home))

	e := New(EventSkillExecute, OutcomeSuccess, SeverityInfo, "skillctl/test")
	e.EventID = "aud-disp-1"
	if err := d.Dispatch(e); err != nil {
		t.Fatalf("durable dispatch: %v", err)
	}
	if _, ok, _ := st.Get("aud-disp-1"); !ok {
		t.Fatalf("durable dispatch did not persist to the outbox")
	}
}

// An event with no event_id is rejected: there is no dedup key (REQ-6.2).
func TestOutboxSink_RejectsMissingEventID(t *testing.T) {
	home := t.TempDir()
	st, err := outbox.Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	sink := NewOutboxSinkWithStore(st, home)
	e := &Event{
		Schema: SchemaV1, Timestamp: "2026-09-04T00:00:00.000Z",
		EventType: EventPolicyAllow, Outcome: OutcomeSuccess, Severity: SeverityInfo,
		Producer: "skillctl/test",
	} // deliberately no EventID
	if err := sink.Write(e); err == nil {
		t.Fatal("write with no event_id must error (no dedup key)")
	}
}
