package auditevent

// sink.go: the Event → Dispatcher → Sink seam (SPEC-0403 §7.2, REQ-7.2). Event
// creation is separated from transport: the core carries NO broker-specific
// semantics. This file holds the local sink abstraction and a fan-out Dispatcher.
//
// WHY THE INTERFACE IS SHAPED THIS WAY (forward-compat with FR-0110). A Sink
// receives the STRUCTURED *Event, not pre-serialized bytes, so a future
// outbox-backed durable sink (FR-0110) can project the event onto the
// SPEC-0317 audit_events columns (event_id, event_type, occurred_at, …) without
// re-parsing JSON, while a file/stream sink serializes it itself. Delivery MODES
// (best-effort / durable / required, §6) are a Dispatcher-level policy, NOT a
// Sink concern: a Sink only reports whether its Write succeeded; the Dispatcher
// decides what a failure means. FR-0110 therefore adds mode handling here and an
// OutboxSink implementing this same interface; no signature change.

import (
	"errors"
	"fmt"
)

// Sink is a destination for redacted audit events. Implementations MUST be safe
// for the Dispatcher to call Write on from one goroutine at a time; they need not
// be internally concurrent.
type Sink interface {
	// Write emits or persists one already-redacted, already-validated event. A
	// returned error means this sink did not accept the event; the Dispatcher's
	// mode decides whether that is fatal (FR-0110). Write MUST NOT mutate e.
	Write(e *Event) error
	// Name identifies the sink for observability (audit.sink.* events, FR-0111).
	Name() string
	// Close releases the sink's resources. It MUST be safe to call once; calling
	// Write after Close may error.
	Close() error
}

// Dispatcher redacts an event, validates it, and fans it out to every configured
// sink. In FR-0109 it is best-effort by construction: a sink failure is collected
// and returned but never panics and never blocks; this preserves the SPEC-0255
// decision-invariance default for the gate hot path (REQ-6.4). The explicit
// best-effort / durable / required delivery modes (§6) arrive in FR-0110; this
// type is their attachment point.
type Dispatcher struct {
	redactor Redactor
	sinks    []Sink
}

// NewDispatcher builds a Dispatcher applying r to every event before fan-out.
// Pass DefaultRedactor() unless a policy supplies its own (REQ-5.6).
func NewDispatcher(r Redactor, sinks ...Sink) *Dispatcher {
	return &Dispatcher{redactor: r, sinks: sinks}
}

// Dispatch redacts e in place (so no un-redacted copy lingers), stamps any
// missing mandatory envelope fields, validates, then writes to every sink.
//
// It returns an error if the event is invalid (no sink is written in that case)
// or if one or more sinks failed (the event was still offered to the others).
// A caller on the decision hot path (the gate) treats this as advisory and
// ignores the result; logging never changes a decision by default (REQ-6.4).
func (d *Dispatcher) Dispatch(e *Event) error {
	if e == nil {
		return fmt.Errorf("%w: nil event", ErrInvalidEvent)
	}
	// Ergonomic defaults so a producer that forgot the envelope still emits a
	// well-formed line; an explicitly-set field is never overwritten.
	if e.Schema == "" {
		e.Schema = SchemaV1
	}
	if e.Timestamp == "" {
		e.Timestamp = idNow().Format(timestampLayout)
	}
	if e.EventID == "" {
		e.EventID = NewEventID()
	}

	d.redactor.Redact(e)

	if err := e.Validate(); err != nil {
		return err
	}

	var errs []error
	for _, s := range d.sinks {
		if err := s.Write(e); err != nil {
			errs = append(errs, fmt.Errorf("sink %q: %w", s.Name(), err))
		}
	}
	return errors.Join(errs...)
}

// Close closes every sink, joining any errors. Sinks are closed even if an
// earlier one failed.
func (d *Dispatcher) Close() error {
	var errs []error
	for _, s := range d.sinks {
		if err := s.Close(); err != nil {
			errs = append(errs, fmt.Errorf("sink %q: %w", s.Name(), err))
		}
	}
	return errors.Join(errs...)
}
