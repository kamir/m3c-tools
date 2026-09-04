package auditevent

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// TestEventRoundTripStable proves marshal -> unmarshal -> marshal is byte-stable
// for a fully-populated envelope, including nested refs and extension fields
// (REQ-3.4 canonical JSONL, REQ-3.3 extension fields survive).
func TestEventRoundTripStable(t *testing.T) {
	e := New(EventSkillVerify, OutcomeSuccess, SeverityInfo, "skillctl/0.4.0")
	e.Message = "Skill artifact successfully verified"
	e.Skill = &SkillRef{Name: "compliance-review", Version: "2.3.1", Digest: "sha256:abc"}
	e.Actor = &ActorRef{Type: "workload", ID: "agent://legal-reviewer"}
	e.Principal = &PrincipalRef{ID: "principal-1"}
	e.InvocationID = "inv_123"
	e.SessionID = "sess_9"
	e.CorrelationID = "corr_7"
	e.Resource = &ResourceRef{Type: "skill", ID: "compliance-review"}
	e.Policy = &PolicyRef{ID: "pol-1", Decision: "allow"}
	e.Reference = &ReferenceRef{Source: "ref://doc", Digest: "sha256:def"}
	e.Capability = &CapabilityRef{Type: "egress", Name: "network"}
	e.Error = &ErrorRef{Code: "none", Category: "none"}
	if err := e.SetExt("trace_id", "otel-abc"); err != nil {
		t.Fatalf("SetExt: %v", err)
	}

	b1, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal 1: %v", err)
	}
	var e2 Event
	if err := json.Unmarshal(b1, &e2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	b2, err := json.Marshal(&e2)
	if err != nil {
		t.Fatalf("marshal 2: %v", err)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatalf("round-trip not stable:\n b1=%s\n b2=%s", b1, b2)
	}
	// The extension field must have survived into Ext.
	if _, ok := e2.Ext["trace_id"]; !ok {
		t.Fatalf("extension field trace_id lost on round-trip; ext=%v", e2.Ext)
	}
}

// TestUnknownOptionalFieldTolerated is REQ-3.3: an unknown optional field must
// NOT invalidate an otherwise valid event, and it must survive a re-marshal.
func TestUnknownOptionalFieldTolerated(t *testing.T) {
	raw := `{
	  "schema": "skillctl.audit.v1",
	  "timestamp": "2026-09-03T21:41:22.318Z",
	  "event_id": "01K0000000000000000000TEST",
	  "event_type": "skill.verify",
	  "outcome": "success",
	  "severity": "info",
	  "producer": "skillctl/9.9.9",
	  "some_future_field": {"nested": [1,2,3]},
	  "another_new_scalar": 42
	}`
	var e Event
	if err := json.Unmarshal([]byte(raw), &e); err != nil {
		t.Fatalf("tolerant unmarshal must not error: %v", err)
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("unknown optional fields must not fail validation: %v", err)
	}
	if e.EventType != EventSkillVerify {
		t.Fatalf("known field corrupted: event_type=%q", e.EventType)
	}
	if _, ok := e.Ext["some_future_field"]; !ok {
		t.Fatalf("unknown field not captured in Ext: %v", e.Ext)
	}
	out, err := json.Marshal(&e)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if !strings.Contains(string(out), "some_future_field") ||
		!strings.Contains(string(out), "another_new_scalar") {
		t.Fatalf("extension fields not preserved on re-marshal: %s", out)
	}
}

// TestValidateMandatoryFields is the mandatory-field contract (REQ-3.1) plus the
// controlled vocabularies (REQ-4.1). Every mutation of a valid baseline that
// drops a mandatory field or uses an unknown vocabulary value must be rejected.
func TestValidateMandatoryFields(t *testing.T) {
	base := func() *Event {
		return &Event{
			Schema: SchemaV1, Timestamp: "2026-09-03T21:41:22.318Z",
			EventID: "01K0000000000000000000TEST", EventType: EventSkillVerify,
			Outcome: OutcomeSuccess, Severity: SeverityInfo, Producer: "skillctl/x",
		}
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("baseline must be valid: %v", err)
	}

	cases := []struct {
		name string
		mut  func(*Event)
	}{
		{"no schema", func(e *Event) { e.Schema = "" }},
		{"no timestamp", func(e *Event) { e.Timestamp = "" }},
		{"no event_id", func(e *Event) { e.EventID = "" }},
		{"no event_type", func(e *Event) { e.EventType = "" }},
		{"no outcome", func(e *Event) { e.Outcome = "" }},
		{"no severity", func(e *Event) { e.Severity = "" }},
		{"no producer", func(e *Event) { e.Producer = "" }},
		{"unknown event_type", func(e *Event) { e.EventType = "skill.teleport" }},
		{"unknown outcome", func(e *Event) { e.Outcome = "maybe" }},
		{"unknown severity", func(e *Event) { e.Severity = "loud" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := base()
			tc.mut(e)
			err := e.Validate()
			if err == nil {
				t.Fatalf("expected rejection")
			}
			if !errors.Is(err, ErrInvalidEvent) {
				t.Fatalf("error must wrap ErrInvalidEvent: %v", err)
			}
		})
	}
}

// TestValidateNilEvent covers the nil receiver path.
func TestValidateNilEvent(t *testing.T) {
	var e *Event
	if err := e.Validate(); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("nil event must be invalid: %v", err)
	}
}

// TestExtCannotShadowCanonicalField proves an extension key colliding with a
// canonical field is refused by SetExt and dropped on marshal (a canonical field
// is never overwritten by an extension).
func TestExtCannotShadowCanonicalField(t *testing.T) {
	e := New(EventPolicyAllow, OutcomeSuccess, SeverityInfo, "skillctl/x")
	if err := e.SetExt("event_type", "attacker.controlled"); err == nil {
		t.Fatalf("SetExt of a canonical key must error")
	}
	// Force a colliding key directly into Ext and prove marshal drops it.
	e.Ext = map[string]json.RawMessage{"event_type": json.RawMessage(`"attacker.controlled"`)}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]string
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["event_type"] != string(EventPolicyAllow) {
		t.Fatalf("canonical event_type was shadowed by an extension key: %q", got["event_type"])
	}
}
