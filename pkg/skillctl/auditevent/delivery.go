package auditevent

// delivery.go: the FR-0110a delivery semantics (SPEC-0403 §6). Stiller Verlust
// darf nicht das Standardverhalten sein (REQ-6.1): the delivery MODE is an
// explicit, selectable Dispatcher property, NOT a Sink concern (a Sink only
// reports whether its Write succeeded; the Dispatcher decides what a failure
// means, sink.go).
//
// SCOPE (FR-0110a). This file implements `best-effort` and `durable`. `required`
// (REQ-6.1 / §6b, the hot-path fail-close for the positive-list event types) is
// MODELED here so a producer can already name it, but its ENFORCEMENT is
// explicitly OUT OF SCOPE: it is FR-0110b, a separate challenge-gated PR. See
// writeToSinks: `required` currently behaves like `durable` and NEVER fails the
// caller, so the SPEC-0255 / REQ-6.4 decision-invariance default is untouched by
// this PR.

import (
	"errors"
	"fmt"
)

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
	// TODO(FR-0110b): ENFORCEMENT (hot-path fail-close for the §6b/REQ-6.9
	// positive list: policy.allow, skill.execute, capability.grant,
	// trustroot.change, config.change, with deny-class events exempt per REQ-6.7,
	// and the getrennte Bestaetigung for policy.allow per REQ-6.10) is a SEPARATE,
	// challenge-gated PR. It is NOT implemented here: this PR must not fail-close
	// anywhere. Until FR-0110b lands, ModeRequired is accepted by Valid() and
	// behaves exactly like ModeDurable (never fails the caller).
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
// single fan-out point Dispatch calls after redaction and validation. The
// returned error is advisory in best-effort/durable; a caller on the decision hot
// path (the gate) ignores it (REQ-6.4). It NEVER panics and NEVER fails-closed
// here: required-mode enforcement is FR-0110b (see writeToSinks).
func (d *Dispatcher) deliver(e *Event) error {
	var errs []error
	for _, s := range d.sinks {
		if err := d.writeToSinks(s, e); err != nil {
			errs = append(errs, fmt.Errorf("sink %q: %w", s.Name(), err))
		}
	}
	return errors.Join(errs...)
}

// writeToSinks performs one sink Write under the Dispatcher's mode.
//
//   - best-effort: exactly one Write attempt; the error (if any) is returned
//     advisory (byte-for-byte the FR-0109 landed behavior).
//   - durable: up to durableRetries in-process attempts to ride out a transient
//     failure; the durable sink (OutboxSink) additionally spools so the row
//     survives restart and is deduped on event_id (REQ-6.2).
//   - required: TODO(FR-0110b). The hot-path fail-close is a separate PR. Until
//     then this behaves EXACTLY like durable and never fails the caller, so
//     decision-invariance (REQ-6.4 / SPEC-0255) is preserved by this PR.
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
