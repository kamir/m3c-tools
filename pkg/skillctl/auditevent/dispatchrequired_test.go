package auditevent

// dispatchrequired_test.go: the FR-0110b challenge-gate follow-up (1) bite test.
//
// The gate found that IsFailClosed reports ONLY the durability fail-close
// (ErrRequiredNotDurable). A MALFORMED mandatory event fails Dispatch with
// ErrInvalidEvent (Validate rejects it before any sink is written), for which
// IsFailClosed is false, so a required caller gating solely on IsFailClosed would
// let a malformed mandatory event proceed UN-AUDITED (AUD-01). DispatchRequired
// closes that: for a mandatory event, ANY non-nil Dispatch error fail-closes.
//
// Each test is bite-proof: the comment names the guard whose removal makes it fail.

import (
	"errors"
	"testing"
)

// malformedPolicyAllow builds a policy.allow event (a MANDATORY type under the
// confirmed policy) that is MALFORMED: its outcome is not in the vocabulary, so
// Validate rejects it with ErrInvalidEvent before any sink is written.
func malformedPolicyAllow() *Event {
	e := New(EventPolicyAllow, OutcomeSuccess, SeverityInfo, "skillctl/x")
	e.EventID = "aud-malformed-1"
	e.Outcome = "bogus-outcome" // not a known Outcome → Validate fails (ErrInvalidEvent).
	return e
}

// (1) THE BITE. A malformed MANDATORY event: plain Dispatch returns a non-fail-close
// error (the gap), DispatchRequired fail-closes (the fix).
// BITE: delete the `d.isMandatory(e)` branch in DispatchRequired (return err
// verbatim) and the malformed policy.allow returns bare ErrInvalidEvent →
// IsFailClosed goes false → this test fails on the second assertion.
func TestDispatchRequired_MalformedMandatory_FailsClosed(t *testing.T) {
	home := t.TempDir()
	// A real, spool-only, LOCAL fulfillment sink (so construction is accepted and a
	// WELL-FORMED event would be durably accepted; the malformation is the only fault).
	d := mustRequired(t, policyAllowConfirmed(t), NewOutboxSinkWithStore(nil, home))

	// Control: plain Dispatch surfaces the malformation as ErrInvalidEvent, which is
	// NOT load-bearing. This is exactly the gap the helper exists to close: a caller
	// gating only on IsFailClosed would proceed here, un-audited.
	plain := d.Dispatch(malformedPolicyAllow())
	if !errors.Is(plain, ErrInvalidEvent) {
		t.Fatalf("a malformed event must fail Dispatch validation (ErrInvalidEvent); got %v", plain)
	}
	if IsFailClosed(plain) {
		t.Fatalf("plain Dispatch must NOT report a validation error as fail-closed (that is the gap); got IsFailClosed=true")
	}

	// The fix: DispatchRequired fail-closes the SAME malformed mandatory event.
	got := d.DispatchRequired(malformedPolicyAllow())
	if !IsFailClosed(got) {
		t.Fatalf("DispatchRequired must fail closed on a malformed MANDATORY event (AUD-01); got err=%v (IsFailClosed=false)", got)
	}
	// The load-bearing wrapper must still carry the underlying validation cause, so an
	// operator can see WHY it failed closed, not merely THAT it did.
	if !errors.Is(got, ErrRequiredNotDurable) || !errors.Is(got, ErrInvalidEvent) {
		t.Fatalf("the fail-close error must wrap BOTH ErrRequiredNotDurable and the underlying ErrInvalidEvent; got %v", got)
	}
}

// (2) A well-formed mandatory event whose LOCAL spool accepts it proceeds through
// DispatchRequired exactly as through Dispatch (no false fail-close).
func TestDispatchRequired_WellFormedMandatory_Proceeds(t *testing.T) {
	home := t.TempDir()
	d := mustRequired(t, policyAllowConfirmed(t), NewOutboxSinkWithStore(nil, home))
	e := New(EventPolicyAllow, OutcomeSuccess, SeverityInfo, "skillctl/x")
	e.EventID = "aud-req-ok-1"
	if err := d.DispatchRequired(e); err != nil {
		t.Fatalf("a spool-accepted mandatory event must proceed through DispatchRequired; got %v", err)
	}
}

// (3) A well-formed mandatory event whose spool FAILS fail-closes through
// DispatchRequired too (the durability path, unchanged from Dispatch).
func TestDispatchRequired_DurabilityFailure_FailsClosed(t *testing.T) {
	d := mustRequired(t, policyAllowConfirmed(t), &failingSink{})
	got := d.DispatchRequired(New(EventPolicyAllow, OutcomeSuccess, SeverityInfo, "skillctl/x"))
	if !IsFailClosed(got) {
		t.Fatalf("a mandatory event whose durable sink failed must fail closed; got %v", got)
	}
}

// (4) A DENIAL type stays exempt EVEN through DispatchRequired and EVEN when
// malformed (REQ-6.7): an already-failed operation is never failed a second time.
// BITE: if isMandatory ignored the denial exemption, a malformed policy.deny would
// fail-close here.
func TestDispatchRequired_MalformedDenial_NotFailClosed(t *testing.T) {
	// A policy that lists a denial type alongside an enforceable one, all confirmed:
	// the only reason the denial does not fail-close is the REQ-6.7 exemption.
	pol := &RequiredPolicy{
		allow:         map[EventType]struct{}{EventPolicyDeny: {}, EventSkillExecute: {}},
		policyAllowOK: true,
	}
	d := mustRequired(t, pol, &failingSink{})
	e := New(EventPolicyDeny, OutcomeDeny, SeverityWarning, "skillctl/x")
	e.Severity = "bogus-severity" // malform it too.
	got := d.DispatchRequired(e)
	if IsFailClosed(got) {
		t.Fatalf("a denial event must never fail closed through DispatchRequired, even malformed (REQ-6.7); got fail-close")
	}
}

// (5) A non-listed type is not mandatory: DispatchRequired returns Dispatch's error
// verbatim (decision-invariant, REQ-6.4). A malformed non-mandatory event stays
// advisory.
func TestDispatchRequired_NonMandatory_Advisory(t *testing.T) {
	// policy.allow confirmed, but the event is skill.verify (NOT on the list).
	d := mustRequired(t, policyAllowConfirmed(t), &failingSink{})
	e := New(EventSkillVerify, OutcomeSuccess, SeverityInfo, "skillctl/x")
	e.Outcome = "bogus" // malform: ErrInvalidEvent.
	got := d.DispatchRequired(e)
	if IsFailClosed(got) {
		t.Fatalf("a non-listed (non-mandatory) event must not fail closed through DispatchRequired (REQ-6.4); got fail-close")
	}
	if !errors.Is(got, ErrInvalidEvent) {
		t.Fatalf("a non-mandatory malformed event must surface the advisory validation error verbatim; got %v", got)
	}
}
