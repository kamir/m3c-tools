// errors.go: the typed outcomes a Backend hands the drain (unit T-01).
//
// The seam keeps the drain's THREE historic outcome classes intact
// (sync_cmds.go pre-seam behavior, pinned by the AC-4 tests): per-event
// results travel in Result; the two BATCH-level outcomes travel as typed
// errors so the caller can keep its exact reporting and exit-code paths.
package auditexport

import "fmt"

// StatusError is a per-event deferral that carries the transport status
// code beside the reason, so the caller's bookkeeping (delivery_attempts
// rows) can record the same status it recorded before the seam existed.
// Error() returns ONLY the reason: the string that lands in the attempt
// row stays byte-identical to the pre-seam drain.
type StatusError struct {
	Status int
	Reason string
}

func (e *StatusError) Error() string { return e.Reason }

// TransientError is a whole-batch transient failure (network error, a 5xx,
// or no status at all): nothing was acknowledged, everything may be
// retried with backoff. Cause is nil when only a status is known.
type TransientError struct {
	Status int
	Cause  error
}

func (e *TransientError) Error() string {
	if e.Cause != nil {
		return e.Cause.Error()
	}
	return fmt.Sprintf("transient status %d", e.Status)
}

func (e *TransientError) Unwrap() error { return e.Cause }

// RejectedError is a permanent batch reject by the sink's authorizer
// (auth/validation, 4xx): retrying without operator action is pointless.
type RejectedError struct {
	Status int
}

func (e *RejectedError) Error() string {
	return fmt.Sprintf("ingest rejected batch with status %d", e.Status)
}
