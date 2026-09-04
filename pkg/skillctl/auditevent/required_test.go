package auditevent

// required_test.go: the FR-0110b bite tests (SPEC-0403 §6b). Each test is written
// so that REMOVING the specific guard it targets makes it FAIL (bite-proof); the
// comment on each names the guard and the removal that breaks it. These are
// hermetic: no env, no network, no ambient managed-settings file. The library
// fail-close signal is IsFailClosed(err); the exit-code (load-path) form of the
// policy.allow case lives in cmd/skillctl/enforce_require_audit_test.go (the
// SPEC-0317 R-8.2 require_local_audit path, the live instantiation of this policy
// in the gate hot path, which FR-0110b reconciles with rather than duplicates).

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// policyAllowConfirmed is the validated policy the enforce path's require_local_audit
// mirrors: policy.allow, fail-closeable, with the REQ-6.10a confirmation.
func policyAllowConfirmed(t *testing.T) *RequiredPolicy {
	t.Helper()
	p, err := RequiredConfig{Mode: "required", AllowList: []string{"policy.allow"}, ConfirmPolicyAllow: true}.BuildPolicy()
	if err != nil || p == nil {
		t.Fatalf("expected a valid policy.allow required policy, got p=%v err=%v", p, err)
	}
	return p
}

// (1) required + allow-listed policy.allow + a spool write that FAILS → the
// operation fails closed (IsFailClosed true, with a clear reason).
// BITE: delete the `d.required.failCloseable(...)` branch in deliver (making every
// residual error advisory) and IsFailClosed goes false → this fails.
func TestRequired_PolicyAllow_SpoolFails_FailsClosed(t *testing.T) {
	d := NewDispatcherRequired(policyAllowConfirmed(t), Redactor{}, &failingSink{}) // failingSink models a full-disk/unwritable spool.
	err := d.Dispatch(New(EventPolicyAllow, OutcomeSuccess, SeverityInfo, "skillctl/x"))
	if !IsFailClosed(err) {
		t.Fatalf("policy.allow that could not be durably accepted must fail closed; got err=%v (IsFailClosed=false)", err)
	}
	if !strings.Contains(err.Error(), "policy.allow") || !strings.Contains(err.Error(), "REQ-6.10b") {
		t.Fatalf("fail-close reason must name the event type and the spool fulfillment rule; got %q", err.Error())
	}
}

// (2) spool write SUCCEEDS → the operation proceeds. The sink is the REAL
// spool-only OutboxSink (no broker reachable), so this also proves the fulfillment
// point is local spool acceptance, never a network ack (REQ-6.10b).
// BITE: if a durable success wrongly wrapped ErrRequiredNotDurable, err != nil here.
func TestRequired_PolicyAllow_SpoolSucceeds_Proceeds(t *testing.T) {
	home := t.TempDir()
	sink := NewOutboxSinkWithStore(nil, home) // nil store → spool-only, no db, no network.
	d := NewDispatcherRequired(policyAllowConfirmed(t), Redactor{}, sink)

	e := New(EventPolicyAllow, OutcomeSuccess, SeverityInfo, "skillctl/x")
	e.EventID = "aud-required-ok-1"
	if err := d.Dispatch(e); err != nil {
		t.Fatalf("a spool-accepted policy.allow must proceed (spool is the fulfillment point); got err=%v", err)
	}
	spool := filepath.Join(home, ".claude", "skillctl", "spool.jsonl")
	if b, err := os.ReadFile(spool); err != nil || len(b) == 0 {
		t.Fatalf("expected the line durably accepted by the local spool (no network); read err=%v len=%d", err, len(b))
	}
}

// (3) a DENIAL event under required is NEVER failed a second time, EVEN when it is
// on the allow-list (REQ-6.7, the non-configurable exemption). Constructed by hand
// (BuildPolicy would skip a denial type) to prove the RUNTIME guard.
// BITE: delete the `IsDenialEventType(t)` check in failCloseable and every one of
// these becomes fail-closed → this fails.
func TestRequired_DenialEvents_NeverFailClosed(t *testing.T) {
	for _, dt := range []EventType{EventPolicyDeny, EventSignatureReject, EventRevocationDetect} {
		// Denial type PLUS a real enforceable type on the list, all confirmed, so the
		// only reason the denial does not fail-close is the exemption.
		pol := &RequiredPolicy{
			allow:         map[EventType]struct{}{dt: {}, EventSkillExecute: {}},
			policyAllowOK: true,
		}
		if pol.failCloseable(dt) {
			t.Fatalf("denial type %q must be exempt from required fail-close even when listed (REQ-6.7)", dt)
		}
		d := NewDispatcherRequired(pol, Redactor{}, &failingSink{})
		// A denial event carries a deny/failure outcome; use one the taxonomy accepts.
		out := OutcomeDeny
		if dt == EventSignatureReject {
			out = OutcomeFailure
		}
		err := d.Dispatch(New(dt, out, SeverityWarning, "skillctl/x"))
		if IsFailClosed(err) {
			t.Fatalf("dispatching denial %q under required must not fail closed (already-failed op); got fail-close", dt)
		}
	}
}

// (4) required with an EMPTY allow-list is a config error (REQ-6.6): the policy is
// rejected, never silently downgraded to advisory.
// BITE: delete the REQ-6.6 empty-list check and an empty list falls through to the
// "no enforceable type" branch, whose message does NOT contain "non-empty
// allow-list" → this fails on the message assertion.
func TestRequired_EmptyAllowList_RejectedAsConfigError(t *testing.T) {
	for _, empty := range [][]string{nil, {}, {""}, {"  "}} {
		_, err := RequiredConfig{Mode: "required", AllowList: empty}.BuildPolicy()
		if !errors.Is(err, ErrRequiredConfig) {
			t.Fatalf("required with empty allow-list %v must be a config error; got %v", empty, err)
		}
		if !strings.Contains(err.Error(), "non-empty allow-list") {
			t.Fatalf("empty-list rejection must cite REQ-6.6 (non-empty allow-list); got %q", err.Error())
		}
	}
	// A well-formed required config (a non-policy.allow type) builds cleanly, proving
	// the rejection is specific to the empty list, not a blanket refusal.
	if p, err := (RequiredConfig{Mode: "required", AllowList: []string{"skill.execute"}}).BuildPolicy(); err != nil || p == nil {
		t.Fatalf("a well-formed required config must build; got p=%v err=%v", p, err)
	}
}

// (5) the DEFAULT / unconfigured path is decision-invariant: a failing sink never
// produces a load-bearing (fail-close) error. Two shapes: (a) the best-effort
// default, and (b) a required Dispatcher with NO policy (the FR-0110a shape).
// BITE: if a required Dispatcher fail-closed without an explicit policy (REQ-6.4
// violation), case (b) trips IsFailClosed → this fails.
func TestRequired_DefaultPath_DecisionInvariant(t *testing.T) {
	// (a) best-effort default: the sink error is surfaced ADVISORY, never fail-close.
	dBE := NewDispatcher(Redactor{}, &failingSink{})
	errBE := dBE.Dispatch(New(EventPolicyAllow, OutcomeSuccess, SeverityInfo, "skillctl/x"))
	if errBE == nil {
		t.Fatal("best-effort must still surface the sink error (advisory)")
	}
	if IsFailClosed(errBE) {
		t.Fatal("best-effort must NEVER fail closed (REQ-6.4)")
	}
	// (b) required MODE but no configured policy: durable-equivalent, never fail-close.
	dNoPol := NewDispatcherMode(ModeRequired, Redactor{}, &failingSink{})
	errNoPol := dNoPol.Dispatch(New(EventPolicyAllow, OutcomeSuccess, SeverityInfo, "skillctl/x"))
	if IsFailClosed(errNoPol) {
		t.Fatal("required mode with NO explicit policy must not fail closed (REQ-6.4: no path silently gains fail-close)")
	}
}

// (6) policy.allow requires the SEPARATE confirmation (REQ-6.10a). Proven three
// ways: BuildPolicy rejects an unconfirmed config; the runtime guard refuses an
// unconfirmed policy; and the confirmed policy DOES fail-close.
// BITE: delete the `t == EventPolicyAllow && !p.policyAllowOK` check and the
// unconfirmed policy becomes fail-closeable → the middle assertion fails; delete
// the BuildPolicy REQ-6.10a check and the first assertion fails.
func TestRequired_PolicyAllow_NeedsSeparateConfirmation(t *testing.T) {
	// Config-time: policy.allow without the separate confirmation is rejected.
	if _, err := (RequiredConfig{Mode: "required", AllowList: []string{"policy.allow"}, ConfirmPolicyAllow: false}).BuildPolicy(); !errors.Is(err, ErrRequiredConfig) {
		t.Fatalf("policy.allow without the separate confirmation must be a config error (REQ-6.10a); got %v", err)
	}
	// Runtime guard: an unconfirmed policy.allow is not fail-closeable even if listed.
	unconf := &RequiredPolicy{allow: map[EventType]struct{}{EventPolicyAllow: {}}, policyAllowOK: false}
	if unconf.failCloseable(EventPolicyAllow) {
		t.Fatal("unconfirmed policy.allow must not be fail-closeable (REQ-6.10a)")
	}
	if IsFailClosed(NewDispatcherRequired(unconf, Redactor{}, &failingSink{}).Dispatch(New(EventPolicyAllow, OutcomeSuccess, SeverityInfo, "skillctl/x"))) {
		t.Fatal("dispatching policy.allow under an unconfirmed policy must not fail closed")
	}
	// Confirmed: it IS fail-closeable and DOES fail-close on a failing sink.
	conf := policyAllowConfirmed(t)
	if !conf.failCloseable(EventPolicyAllow) {
		t.Fatal("confirmed policy.allow must be fail-closeable")
	}
	if !IsFailClosed(NewDispatcherRequired(conf, Redactor{}, &failingSink{}).Dispatch(New(EventPolicyAllow, OutcomeSuccess, SeverityInfo, "skillctl/x"))) {
		t.Fatal("confirmed policy.allow with a failing spool must fail closed")
	}
}

// A non-policy.allow eligible type (skill.execute) needs NO separate confirmation
// and fail-closes on a failing sink but proceeds on a spool success: the general
// mechanism for the REQ-6.9 "granted effect" types.
// BITE: this covers the four non-policy.allow types; if failCloseable wrongly gated
// them behind policyAllowOK, the fail-close assertion trips.
func TestRequired_SkillExecute_FailClosesWithoutExtraConfirm(t *testing.T) {
	p, err := RequiredConfig{Mode: "required", AllowList: []string{"skill.execute"}}.BuildPolicy()
	if err != nil || p == nil {
		t.Fatalf("skill.execute required config must build without a policy.allow confirmation; got p=%v err=%v", p, err)
	}
	if !IsFailClosed(NewDispatcherRequired(p, Redactor{}, &failingSink{}).Dispatch(New(EventSkillExecute, OutcomeSuccess, SeverityInfo, "skillctl/x"))) {
		t.Fatal("skill.execute that could not be durably accepted must fail closed")
	}
	// Spool success → proceeds.
	home := t.TempDir()
	d := NewDispatcherRequired(p, Redactor{}, NewOutboxSinkWithStore(nil, home))
	e := New(EventSkillExecute, OutcomeSuccess, SeverityInfo, "skillctl/x")
	e.EventID = "aud-skexec-ok-1"
	if err := d.Dispatch(e); err != nil {
		t.Fatalf("a spool-accepted skill.execute must proceed; got %v", err)
	}
}

// A type outside the REQ-6.9 five is a config error (REQ-6.9/6.8: the list is the
// DoS bound; arbitrary types would widen it).
// BITE: drop the canonicalRequiredTypes membership check and this builds instead.
func TestRequired_NonEligibleType_RejectedAsConfigError(t *testing.T) {
	for _, bad := range []string{"invocation.complete", "skill.verify", "audit.sink.fail", "not.a.type"} {
		if _, err := (RequiredConfig{Mode: "required", AllowList: []string{bad}}).BuildPolicy(); !errors.Is(err, ErrRequiredConfig) {
			t.Fatalf("required-ineligible type %q must be a config error (REQ-6.9); got %v", bad, err)
		}
	}
}

// A denial type is TOLERATED on the list (not a config error) but inert: it does
// not by itself satisfy the non-empty requirement.
// BITE: if a lone denial type built a non-nil enforcing policy, the first case fails.
func TestRequired_DenialOnlyList_RejectedButDenialTolerated(t *testing.T) {
	// Only a denial type → nothing enforceable → config error.
	if _, err := (RequiredConfig{Mode: "required", AllowList: []string{"policy.deny"}}).BuildPolicy(); !errors.Is(err, ErrRequiredConfig) {
		t.Fatalf("a required list of only denial types must be rejected (REQ-6.6/6.7); got %v", err)
	}
	// A denial type ALONGSIDE an enforceable type is tolerated; the denial stays inert.
	p, err := RequiredConfig{Mode: "required", AllowList: []string{"policy.deny", "config.change"}}.BuildPolicy()
	if err != nil || p == nil {
		t.Fatalf("a denial type alongside an enforceable type must build; got p=%v err=%v", p, err)
	}
	if p.failCloseable(EventPolicyDeny) {
		t.Fatal("a tolerated denial type must remain inert (REQ-6.7)")
	}
	if !p.failCloseable(EventConfigChange) {
		t.Fatal("the enforceable type alongside it must still fail-close")
	}
}

// Non-required modes never build a policy and never fail-close (sanity for REQ-6.4).
func TestRequired_NonRequiredModes_NoPolicy(t *testing.T) {
	for _, m := range []string{"", "best-effort", "durable", "teleport"} {
		p, err := RequiredConfig{Mode: m, AllowList: []string{"policy.allow"}, ConfirmPolicyAllow: true}.BuildPolicy()
		if err != nil || p != nil {
			t.Fatalf("mode %q must yield no policy and no error; got p=%v err=%v", m, p, err)
		}
	}
}
