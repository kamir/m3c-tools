// er1.go: the er1 backend, decision D5 of SPEC-0455.
//
// This is the pre-seam drain's egress path moved verbatim behind the
// Backend interface: outbox.IngestClient keeps owning the HTTP contract,
// the durable-seq canonicalization and the ed25519 ack verification
// (SPEC-0317 R-5.2/R-5.3); this adapter only maps its outcomes onto the
// seam's vocabulary. It reports Synced EXCLUSIVELY for acks that
// IngestClient.VerifyAck accepted: the backend half of the double lock.
package auditexport

import (
	"context"

	"github.com/kamir/m3c-tools/pkg/skillctl/outbox"
)

// ER1 delivers audit events to the KafShield/aims-core HTTPS ingest
// contract via the outbox.IngestClient the caller configured.
type ER1 struct {
	Client *outbox.IngestClient
}

// AckClass: er1 verifies signed durable-seq acknowledgements (REQ-6.1).
func (b *ER1) AckClass() AckClass { return AckDurable }

// Deliver posts one batch. Batch-level failures return the typed errors
// from errors.go; on a 2xx, every record lands in Synced (valid signed
// durable-seq ack) or in Deferred with the pre-seam bare-2xx reason.
func (b *ER1) Deliver(ctx context.Context, batch []Record) (Result, error) {
	records := make([][]byte, 0, len(batch))
	for _, r := range batch {
		records = append(records, r.Payload)
	}

	resp, status, err := b.Client.PostBatch(ctx, records)
	switch {
	case err != nil || status == 0 || status/100 == 5:
		return Result{}, &TransientError{Status: status, Cause: err}
	case status/100 == 4:
		return Result{}, &RejectedError{Status: status}
	}

	acks := map[string]outbox.DurableAck{}
	if resp != nil {
		for _, a := range resp.Acks {
			acks[a.EventID] = a
		}
	}
	res := Result{Deferred: map[string]error{}}
	for _, r := range batch {
		if ack, ok := acks[r.EventID]; ok && b.Client.VerifyAck(ack) {
			res.Synced = append(res.Synced, r.EventID)
		} else {
			res.Deferred[r.EventID] = &StatusError{Status: status, Reason: "bare-2xx: no valid durable-seq ack"}
		}
	}
	return res, nil
}
