package auditevent

// delivery.go: the FR-0110a delivery semantics (SPEC-0403 §6) PLUS the FR-0110b
// `required` fail-close (§6b). Stiller Verlust darf nicht das Standardverhalten
// sein (REQ-6.1): the delivery MODE is an explicit, selectable Dispatcher
// property, NOT a Sink concern (a Sink only reports whether its Write succeeded;
// the Dispatcher decides what a failure means, sink.go).
//
// SCOPE. This file implements `best-effort`, `durable`, and now the `required`
// ENFORCEMENT: for an event whose type is on an explicitly configured positive
// list (REQ-6.6/6.9) and is NOT a denial type (REQ-6.7), a delivery that was not
// durably accepted returns the load-bearing sentinel ErrRequiredNotDurable, and
// a caller that opted in (IsFailClosed) fails its consequential operation closed.
// The positive-list policy + its validation live in required.go. Every OTHER
// path (any non-required mode, a required Dispatcher with no policy, an event not
// on the list, a denial type, or a durable success) returns only an ADVISORY
// error, so the SPEC-0255 / REQ-6.4 decision-invariance default is byte-identical
// to FR-0110a on every path a required policy does not explicitly cover.

import (
	"errors"
	"fmt"
)

// ErrRequiredNotDurable is the sentinel a Dispatch returns when a MANDATORY audit
// event (an allow-listed, non-denial type under an active RequiredPolicy, §6b)
// could not be durably accepted. It is the ONLY error class the Dispatcher marks
// load-bearing: a caller on a consequential path MUST fail its operation closed
// when IsFailClosed reports true (REQ-6.6, AUD-01). Every other delivery error
// stays advisory, so a caller that never checks IsFailClosed (the gate hot path)
// keeps its byte-identical default decision (REQ-6.4).
var ErrRequiredNotDurable = errors.New("auditevent: required audit event not durably accepted")

// IsFailClosed reports whether err carries the required-mode fail-close signal
// (ErrRequiredNotDurable). It is the caller's opt-in: a caller that ignores
// Dispatch's error entirely (as the gate hot path does today) sees no behavior
// change from FR-0110b, which is exactly what REQ-6.4 requires. A required-mode
// caller wraps its consequential step so that IsFailClosed(err) == fail closed.
//
// NOTE ON SCOPE: this is the DURABILITY fail-close only (REQ-6.6/6.10b, "not
// durably accepted"). A validation error (ErrInvalidEvent) is a producer bug, not
// a durability failure, and is returned distinctly; a mandatory-event producer
// should treat that as its own hard stop, but it is not this contract.
func IsFailClosed(err error) bool { return errors.Is(err, ErrRequiredNotDurable) }

// DispatchRequired dispatches e and, for a MANDATORY event, fail-closes on ANY
// non-nil Dispatch error, not only ErrRequiredNotDurable (SPEC-0403 §6b, AUD-01).
//
// WHY THIS EXISTS. IsFailClosed reports ONLY the durability fail-close
// (ErrRequiredNotDurable). But a mandatory event can fail Dispatch for a SECOND
// reason: it is MALFORMED (ErrInvalidEvent from Validate), in which case Dispatch
// returns before any sink is written and the event is never recorded. A required
// caller that gates solely on IsFailClosed would then let a malformed mandatory
// event proceed UN-AUDITED, which is exactly the false assurance §6b/AUD-01 forbid
// (a consequential operation reported successful while its mandatory audit event
// was silently dropped). DispatchRequired closes that gap: for a mandatory event,
// a validation error is as fail-closing as a durability error.
//
// It changes NOTHING for a non-mandatory event: a denial type (REQ-6.7, exempt), a
// type not on the positive list, an unconfirmed policy.allow, a nil/absent policy,
// or any non-required mode all return Dispatch's error verbatim, so the SPEC-0255 /
// REQ-6.4 decision-invariance default is untouched. Use plain Dispatch on the gate
// hot path; use DispatchRequired at a consequential producer that has opted into
// required for e's type.
func (d *Dispatcher) DispatchRequired(e *Event) error {
	err := d.Dispatch(e)
	if err == nil || IsFailClosed(err) {
		return err // success, or already load-bearing (durability fail-close).
	}
	if d.isMandatory(e) {
		// A mandatory event that did not go through (a malformed ErrInvalidEvent, or
		// any other non-durability delivery error) MUST fail the caller closed: the
		// operation cannot be reported audited when its required event was not
		// recorded (AUD-01). Wrap in the load-bearing sentinel so IsFailClosed==true.
		// Two %w: the result satisfies IsFailClosed (ErrRequiredNotDurable) AND still
		// carries the underlying cause (e.g. ErrInvalidEvent) for an operator.
		return fmt.Errorf("%w: a MANDATORY audit event was not recorded (event_type=%s): %w",
			ErrRequiredNotDurable, mandatoryTypeOf(e), err)
	}
	return err // not a mandatory event: advisory, decision-invariant (REQ-6.4).
}

// isMandatory reports whether e is an event this Dispatcher's required policy would
// fail-close on: required mode, a non-nil policy, and (for a non-nil event) a
// fail-closeable type (on the positive list, not a denial type, and, for
// policy.allow, confirmed). A NIL event under an active required policy is treated
// as mandatory: the caller invoked the required variant, so a nil event is the
// worst un-audited case and must not slip through as merely advisory.
func (d *Dispatcher) isMandatory(e *Event) bool {
	if d.mode != ModeRequired || d.required == nil {
		return false
	}
	if e == nil {
		return true
	}
	return d.required.failCloseable(e.EventType)
}

// mandatoryTypeOf renders the event type for a fail-close message, tolerating a
// nil event.
func mandatoryTypeOf(e *Event) EventType {
	if e == nil {
		return "<nil>"
	}
	return e.EventType
}

// Mode is the SPEC-0403 §6 delivery semantics selector (REQ-6.1).
type Mode string

const (
	// ModeBestEffort: a delivery failure never blocks the operation; the error is
	// advisory (development default, and the landed gate-hot-path behavior, REQ-6.4).
	ModeBestEffort Mode = "best-effort"
	// ModeDurable: an event that cannot be delivered immediately is persisted
	// locally and retried; via the OutboxSink it survives process restart and is
	// idempotent on event_id (REQ-6.2). The recommended production mode.
	ModeDurable Mode = "durable"
	// ModeRequired: a consequential operation MUST fail if its mandatory audit
	// event was not durably accepted (REQ-6.1, high-security policy).
	//
	// FR-0110b ENFORCEMENT: a required Dispatcher fail-closes ONLY for the event
	// types on an explicitly configured positive list (REQ-6.6/6.9: policy.allow,
	// skill.execute, capability.grant, trustroot.change, config.change), with
	// denial types exempt even if listed (REQ-6.7) and policy.allow requiring a
	// separate confirmation (REQ-6.10a). Build a required Dispatcher via
	// NewDispatcherRequired with a policy from RequiredConfig.BuildPolicy
	// (required.go); a required Dispatcher built WITHOUT a policy (via
	// NewDispatcherMode) never fail-closes and behaves like ModeDurable, so no
	// path silently gains fail-close.
	ModeRequired Mode = "required"
)

// defaultDurableRetries is the in-process retry budget a durable/required
// Dispatcher applies to a failing sink Write. It smooths a transient sink hiccup.
// The DURABILITY guarantee itself (restart survival plus dedup) comes from the
// OutboxSink/outbox spool plus Reconcile, NOT from this loop, so a small budget is
// enough and there is deliberately no sleep/backoff on it (that lives in the
// outbox's delivery_attempts lane).
const defaultDurableRetries = 3

// Valid reports whether m is a recognized delivery mode.
func (m Mode) Valid() bool {
	switch m {
	case ModeBestEffort, ModeDurable, ModeRequired:
		return true
	default:
		return false
	}
}

// NewDispatcherMode builds a Dispatcher with an explicit delivery mode (§6). An
// unknown or empty mode falls back to ModeBestEffort (fail-safe: never silently
// stricter than the landed default). Durable/required get defaultDurableRetries;
// override with WithDurableRetries.
func NewDispatcherMode(mode Mode, r Redactor, sinks ...Sink) *Dispatcher {
	if !mode.Valid() {
		mode = ModeBestEffort
	}
	retries := 1
	if mode == ModeDurable || mode == ModeRequired {
		retries = defaultDurableRetries
	}
	return &Dispatcher{redactor: r, sinks: sinks, mode: mode, durableRetries: retries}
}

// Mode returns the Dispatcher's delivery mode.
func (d *Dispatcher) Mode() Mode { return d.mode }

// WithDurableRetries overrides the in-process retry budget for durable/required
// modes (floored at 1) and returns the Dispatcher for chaining. It is a no-op
// notion in best-effort mode, where a single Write attempt is the contract.
func (d *Dispatcher) WithDurableRetries(n int) *Dispatcher {
	if n < 1 {
		n = 1
	}
	d.durableRetries = n
	return d
}

// deliver fans e out to every sink and joins the per-sink errors. It is the
// single fan-out point Dispatch calls after redaction and validation. It NEVER
// panics.
//
// FR-0110b fail-close: under ModeRequired with an active RequiredPolicy, if the
// event type is fail-closeable (on the positive list, not a denial type, and, for
// policy.allow, confirmed) AND delivery did not durably succeed (any configured
// sink failed to accept the write), the joined error is wrapped in
// ErrRequiredNotDurable so IsFailClosed reports true and the caller fails closed.
//
// "Durably accepted" is defined as EVERY configured sink accepting the write. The
// recommended required wiring is a SINGLE durable sink (OutboxSink), for which
// that is exactly spool acceptance (REQ-6.10b), never a network ack: the OutboxSink
// reaches no broker, so a required policy can never hang a load path on a remote
// promise. Adding a flaky best-effort sink alongside the durable one is a
// mis-config that fails SAFE (closed), not open.
//
// On every OTHER path (any non-required mode, no policy, a non-listed type, a
// denial type, or a durable success) deliver returns only the advisory joined
// error, which a gate-hot-path caller ignores (REQ-6.4).
func (d *Dispatcher) deliver(e *Event) error {
	var errs []error
	for _, s := range d.sinks {
		if err := d.writeToSinks(s, e); err != nil {
			errs = append(errs, fmt.Errorf("sink %q: %w", s.Name(), err))
		}
	}
	joined := errors.Join(errs...)
	if joined != nil && d.mode == ModeRequired && d.required.failCloseable(e.EventType) {
		return fmt.Errorf("%w (event_type=%s, spool acceptance is the fulfillment point, REQ-6.10b): %v",
			ErrRequiredNotDurable, e.EventType, joined)
	}
	return joined
}

// writeToSinks performs one sink Write under the Dispatcher's mode.
//
//   - best-effort: exactly one Write attempt; the error (if any) is returned
//     advisory (byte-for-byte the FR-0109 landed behavior).
//   - durable / required: up to durableRetries in-process attempts to ride out a
//     transient failure; the durable sink (OutboxSink) additionally spools so the
//     row survives restart and is deduped on event_id (REQ-6.2). writeToSinks
//     itself is identical for durable and required: the FR-0110b fail-close
//     decision (whether a residual failure is load-bearing) is made ONCE in
//     deliver, from the event type and the policy, not per sink here.
func (d *Dispatcher) writeToSinks(s Sink, e *Event) error {
	switch d.mode {
	case ModeDurable, ModeRequired:
		attempts := d.durableRetries
		if attempts < 1 {
			attempts = 1
		}
		var err error
		for i := 0; i < attempts; i++ {
			if err = s.Write(e); err == nil {
				return nil
			}
		}
		return err
	default: // ModeBestEffort
		return s.Write(e)
	}
}
