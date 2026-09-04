package auditevent

// outboxsink.go: the FR-0110a durable Sink (SPEC-0403 §6 / §7.1). It persists an
// audit Event by delegating to the EXISTING SPEC-0317 outbox
// (pkg/skillctl/outbox). There is NO second store (REQ-2.2 / §7.1): this is one
// more producer wired onto the store that already holds the enforce producer's
// rows. Durability (restart survival) and idempotency-on-event_id (REQ-6.2 /
// AUD-04/05) are inherent to the outbox: Append is a single INSERT OR IGNORE
// keyed on event_id, with a spool.jsonl fallback drained by a later Reconcile.
//
// PROJECTION. The outbox's write API is shaped around the device-signed
// skillgate.InvocationRecord. An audit Event is projected onto it two ways at
// once: (1) the record's flat columns index the row (event_id, event_type,
// occurred_at, skill, decision), and (2) the FULL redacted envelope JSON is
// stored as payload_json so every envelope field round-trips out of the durable
// store (the flat columns are only a NON-authoritative index, SPEC-0317 R-2.6).
//
// UNSIGNED BY CONSTRUCTION. The projected record carries NO device signature
// (DeviceKeyID / DeviceSignatureB64 stay empty) and Tool is the fixed marker
// "audit". An audit event is an accountability record, NOT cryptographic evidence
// (REQ-1.2 / AUD-08); it must never masquerade as a signed invocation-evidence
// row. The empty signature and the "audit" tool marker keep the two row classes
// distinguishable. NOTE for a future producer: the SPEC-0317 sync drain
// re-verifies signatures, so wiring this sink onto a producer whose store is
// sync-drained needs the signed-vs-unsigned handling resolved first (that wiring
// is NOT part of FR-0110a; the gate default path stays best-effort file-backed).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/kamir/m3c-tools/pkg/skillctl/outbox"
	"github.com/kamir/m3c-tools/pkg/skillgate"
)

// OutboxSink is a Sink that durably persists events via the SPEC-0317 outbox. It
// is the durable-mode sink (§6). Not for the gate hot path by default: the gate
// stays best-effort file-backed (REQ-6.4).
type OutboxSink struct {
	store *outbox.Store // nil => spool-only (Open failed on a writable dir).
	home  string        // backs the spool fallback (outbox.SpoolTo).
}

// NewOutboxSink opens (creating if needed) the outbox under home and returns a
// durable sink over it. If Open itself fails (e.g. a corrupt outbox.db on an
// otherwise-writable dir) it returns a SPOOL-ONLY sink rather than an error,
// mirroring the enforce producer (defaultEnforceOutboxSink): a row then still
// lands durably in spool.jsonl and a later `skillctl sync` Reconcile drains it.
// An empty home is the one hard error (there is nowhere to anchor state).
func NewOutboxSink(home string) (*OutboxSink, error) {
	if home == "" {
		return nil, fmt.Errorf("auditevent: outbox sink needs a home")
	}
	st, err := outbox.Open(home)
	if err != nil {
		return &OutboxSink{store: nil, home: home}, nil // spool-only fallback.
	}
	return &OutboxSink{store: st, home: home}, nil
}

// NewOutboxSinkWithStore wraps an already-open store (dependency injection for a
// caller that owns the outbox lifecycle, and for tests). A nil store selects the
// spool-only path anchored at home.
func NewOutboxSinkWithStore(st *outbox.Store, home string) *OutboxSink {
	return &OutboxSink{store: st, home: home}
}

// Name identifies the sink for observability (FR-0111).
func (o *OutboxSink) Name() string { return "outbox" }

// localSink marks OutboxSink as a LocalSink (REQ-6.10b): it persists to the local
// SPEC-0317 outbox (SQLite + spool.jsonl) and reaches NO broker; the network drain
// is the SEPARATE `skillctl sync` process. It is therefore the recommended
// fulfillment sink under ModeRequired, where "durably accepted" is exactly spool
// acceptance, never a remote ack.
func (o *OutboxSink) localSink() {}

// Close closes the underlying store (if this sink opened one). A spool-only sink
// holds nothing to close.
func (o *OutboxSink) Close() error {
	if o.store != nil {
		return o.store.Close()
	}
	return nil
}

// Write durably persists one already-redacted, already-validated event. It is
// idempotent on event_id (REQ-6.2): a replay is an INSERT OR IGNORE no-op. It
// returns an error only if the row could land in NEITHER the outbox nor the
// spool (a genuinely un-recordable state). An event with no event_id is rejected
// (dedup has no key otherwise).
func (o *OutboxSink) Write(e *Event) error {
	if e == nil {
		return fmt.Errorf("auditevent: outbox sink: nil event")
	}
	if e.EventID == "" {
		return fmt.Errorf("auditevent: outbox sink: event has no event_id (dedup key, REQ-6.2)")
	}
	rec := projectRecord(e)
	// Store the FULL redacted envelope as payload_json so the durable row
	// round-trips every field; payload_hash is over those exact bytes.
	payloadJSON, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("auditevent: outbox sink: marshal envelope: %w", err)
	}
	sum := sha256.Sum256(payloadJSON)
	payloadHash := hex.EncodeToString(sum[:])

	if o.store == nil {
		if err := outbox.SpoolTo(o.home, rec, string(payloadJSON), payloadHash); err != nil {
			return fmt.Errorf("auditevent: outbox sink: spool: %w", err)
		}
		return nil
	}
	if err := o.store.AppendOrSpool(rec, string(payloadJSON), payloadHash); err != nil {
		return fmt.Errorf("auditevent: outbox sink: append/spool: %w", err)
	}
	return nil
}

// projectRecord maps an audit envelope onto the outbox audit_events index columns
// via an UNSIGNED skillgate.InvocationRecord (see the file header). The decision
// index column is derived by the outbox from RefusalCode (present => deny), so a
// deny-class outcome carries the event_type as its refusal_code to keep the index
// consistent with the envelope.
func projectRecord(e *Event) skillgate.InvocationRecord {
	rec := skillgate.InvocationRecord{
		Schema:     skillgate.InvocationSchema,
		EventID:    e.EventID,
		EventType:  string(e.EventType),
		OccurredAt: e.Timestamp,
		SessionID:  e.SessionID,
		Tool:       "audit", // marker: an audit-sourced row, not signed invocation evidence.
		Action:     "audit",
	}
	if e.Skill != nil {
		rec.SkillName = e.Skill.Name
		rec.SkillVersion = e.Skill.Version
		rec.SkillDigest = e.Skill.Digest
	}
	if e.Outcome == OutcomeDeny || e.Outcome == OutcomeFailure {
		rec.RefusalCode = string(e.EventType)
	}
	rec.ExitCode = extInt(e, "gate.exit_code")
	return rec
}
