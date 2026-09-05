package auditevent

import (
	"encoding/json"
	"errors"
	"testing"
)

// Every declared reason must be classified, and every classification must name a
// type the taxonomy knows. This is the test the reasonClasses table exists for:
// it makes "add a reason, forget to classify it" a build-time-ish failure rather
// than a runtime event that silently never gets written.
func TestEveryReasonIsClassifiedAndKnown(t *testing.T) {
	for _, r := range KnownReasonCodes() {
		if r == ReasonOK || r == ReasonInternalError {
			continue // handled explicitly, not via the table.
		}
		cls, ok := reasonClasses[r]
		if !ok {
			t.Errorf("reason %q has no classification", r)
			continue
		}
		if !IsKnownEventType(cls.refusalType) {
			t.Errorf("reason %q maps to event type %q, which is not in the taxonomy", r, cls.refusalType)
		}
		if cls.category == "" {
			t.Errorf("reason %q has an empty error category", r)
		}
	}
}

// A refusal must never be reported as a success, and the exit code must survive
// verbatim. Both halves matter: the first is the security statement, the second
// is what an operator actually greps for.
func TestRefusalIsNotASuccessAndKeepsItsExitCode(t *testing.T) {
	e, err := FromLifecycleEvent(LifecycleEvent{
		Op:       OpInstall,
		Skill:    "eric-demo-skill",
		Digest:   "sha256:abc",
		Reason:   ReasonDigestMismatch,
		ExitCode: 10,
	}, "skillctl/test")
	if err != nil {
		t.Fatalf("FromLifecycleEvent: %v", err)
	}
	if e.Outcome == OutcomeSuccess {
		t.Fatal("a digest mismatch was reported as a success")
	}
	if e.EventType != EventSignatureReject {
		t.Errorf("event_type = %q, want %q", e.EventType, EventSignatureReject)
	}
	if e.Error == nil || e.Error.Code != string(ReasonDigestMismatch) {
		t.Errorf("error.code did not carry the reason: %+v", e.Error)
	}
	// The numbered code is not derivable from the taxonomy, so it has to be
	// carried, and it has to survive the JSON round trip.
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back map[string]any
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got, ok := back["lifecycle.exit_code"].(float64); !ok || int(got) != 10 {
		t.Errorf("lifecycle.exit_code = %v, want 10", back["lifecycle.exit_code"])
	}
}

// An internal fault is not a refusal. Conflating them would make an outage read
// as a wall of policy denials, which is exactly backwards for an operator
// deciding whether they are under attack or merely broken.
func TestInternalErrorIsNotADenial(t *testing.T) {
	e, err := FromLifecycleEvent(LifecycleEvent{
		Op: OpVerify, Skill: "s", Reason: ReasonInternalError, ExitCode: 1,
	}, "skillctl/test")
	if err != nil {
		t.Fatalf("FromLifecycleEvent: %v", err)
	}
	if e.Outcome != OutcomeError {
		t.Errorf("outcome = %q, want %q", e.Outcome, OutcomeError)
	}
	if e.Outcome == OutcomeDeny {
		t.Fatal("an internal fault was classified as a policy denial")
	}
	if e.EventType != EventSkillVerify {
		t.Errorf("event_type = %q, want %q", e.EventType, EventSkillVerify)
	}
}

// A revoked artifact is the one refusal that says "this passed before and must
// not now". It is pinned at critical so it cannot quietly be demoted to the same
// severity as a governance shortfall.
func TestRevocationIsCritical(t *testing.T) {
	e, err := FromLifecycleEvent(LifecycleEvent{
		Op: OpInstall, Skill: "s", Reason: ReasonIdentityRevoked, ExitCode: 17,
	}, "skillctl/test")
	if err != nil {
		t.Fatalf("FromLifecycleEvent: %v", err)
	}
	if e.Severity != SeverityCritical {
		t.Errorf("severity = %q, want %q", e.Severity, SeverityCritical)
	}
	if e.EventType != EventRevocationDetect {
		t.Errorf("event_type = %q, want %q", e.EventType, EventRevocationDetect)
	}
}

// An unclassified reason must be refused rather than written as something
// plausible. The producer is fire-and-forget, so refusing costs a missing line;
// guessing would cost a misleading record, which is worse in an evidence log.
func TestUnclassifiedReasonIsRefused(t *testing.T) {
	_, err := FromLifecycleEvent(LifecycleEvent{
		Op: OpInstall, Skill: "s", Reason: ReasonCode("something_nobody_declared"),
	}, "skillctl/test")
	if err == nil {
		t.Fatal("an unclassified reason produced an event instead of an error")
	}
	if !errors.Is(err, ErrInvalidEvent) {
		t.Errorf("error does not wrap ErrInvalidEvent: %v", err)
	}
}

// The op is part of the contract: an unknown verb must not silently become an
// install record.
func TestUnknownOpIsRefused(t *testing.T) {
	if _, err := FromLifecycleEvent(LifecycleEvent{Op: LifecycleOp("pack"), Reason: ReasonOK}, "p"); err == nil {
		t.Fatal("an unknown lifecycle op was accepted")
	}
}

// Success on both verbs lands in the right family, and carries no error block.
func TestSuccessMapsPerVerb(t *testing.T) {
	for _, tc := range []struct {
		op   LifecycleOp
		want EventType
	}{
		{OpInstall, EventSkillInstall},
		{OpVerify, EventSkillVerify},
	} {
		e, err := FromLifecycleEvent(LifecycleEvent{Op: tc.op, Skill: "s", Reason: ReasonOK}, "skillctl/test")
		if err != nil {
			t.Fatalf("%s: %v", tc.op, err)
		}
		if e.EventType != tc.want {
			t.Errorf("%s: event_type = %q, want %q", tc.op, e.EventType, tc.want)
		}
		if e.Outcome != OutcomeSuccess {
			t.Errorf("%s: outcome = %q, want success", tc.op, e.Outcome)
		}
		if e.Error != nil {
			t.Errorf("%s: a success carried an error block: %+v", tc.op, e.Error)
		}
	}
}
