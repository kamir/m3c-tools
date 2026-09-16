// Package auditexport is the seam between the audit-event drain
// (skillctl sync, SPEC-0317 R-5) and a selectable sink (SPEC-0455).
//
// Unit T-00 (SPEC-0455 section 12a) ships ONLY the contract types and the
// conformance suite; implementations, the name register and the sync wiring
// arrive with T-01. Two invariants are baked into the shape of this API:
//
//   - Identity flows exclusively through the signed envelope carried in
//     Record.Payload (REQ-4.4, the FR-0090 class): the interface knows no
//     paths, topics, file names or registry annotations a sink could
//     project identity from.
//   - "synced" is reachable only through a verified durable ack (REQ-4.3,
//     decision D6): a Backend reports Synced solely for events whose
//     durable acknowledgement it verified itself, and the drain marks rows
//     synced only from Result.Synced AND only when AckClass() is
//     AckDurable. That is the double lock from the T-00/T-01 plan.
package auditexport

import "context"

// AckClass declares what a backend's acknowledgement can prove (REQ-4.3).
type AckClass string

const (
	// AckDurable: the backend cryptographically verifies a durable-seq
	// acknowledgement in the sense of SPEC-0317 R-5.3 before reporting an
	// event in Result.Synced. Only this class may lead to synced rows.
	AckDurable AckClass = "durable"

	// AckReceived: the transport accepted the batch but persistence is
	// unproven (an accepted git push, a produce without a durable offset
	// protocol). Never marks rows synced (decision D6); bookkeeping for
	// these deliveries lives in the auditexport delivery ledger (D7),
	// never in the outbox evidence table.
	AckReceived AckClass = "received"
)

// Record is one audit event on its way out: the signature-bound event id
// and the redacted, signed envelope bytes. Redaction ran BEFORE the seam
// (REQ-4.5); a backend forwards the payload verbatim and never mutates it.
type Record struct {
	EventID string
	Payload []byte
}

// Result reports per-event outcomes of one Deliver call. An event id
// appears in at most one of the three fields; ids that appear nowhere are
// treated as deferred by the caller (safe default: not synced).
type Result struct {
	// Synced lists event ids whose durable acknowledgement the backend
	// itself verified. The drain marks outbox rows synced only from here.
	Synced []string

	// Forwarded lists event ids the transport accepted without a
	// verified durable acknowledgement (AckReceived backends).
	Forwarded []string

	// Deferred carries per-event failures the caller should retry with
	// backoff; a tampered or unverifiable ack lands here, never in
	// Synced.
	Deferred map[string]error
}

// Backend is one configured sink behind the seam. The sync agent resolves
// exactly one Backend per run (REQ-4.1); the name-to-implementation
// register is part of unit T-01.
type Backend interface {
	// AckClass declares, once per backend, the strongest acknowledgement
	// this backend can verify. It never varies per call.
	AckClass() AckClass

	// Deliver ships one batch and reports per-event outcomes. Redelivery
	// of an already-delivered event id is a no-op at the sink and is
	// acknowledged again (REQ-4.6): the caller may retry safely.
	Deliver(ctx context.Context, batch []Record) (Result, error)
}
