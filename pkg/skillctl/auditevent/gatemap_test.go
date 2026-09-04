package auditevent

import (
	"encoding/json"
	"errors"
	"testing"
)

// TestGateDecisionMapping is the §4 mapping table: every SPEC-0255 verdict maps
// to the right taxonomy type, outcome and severity, and the original verdict is
// preserved verbatim in policy.decision (REQ-4.3, lossless collapse).
func TestGateDecisionMapping(t *testing.T) {
	cases := []struct {
		decision string
		wantType EventType
		wantOut  Outcome
		wantSev  Severity
	}{
		{"allow", EventPolicyAllow, OutcomeSuccess, SeverityInfo},
		{"deny", EventPolicyDeny, OutcomeDeny, SeverityWarning},
		{"quarantine", EventPolicyDeny, OutcomeDeny, SeverityWarning},
		{"leave", EventPolicyEvaluate, OutcomeSuccess, SeverityInfo},
	}
	for _, tc := range cases {
		t.Run(tc.decision, func(t *testing.T) {
			g := GateEvent{Ts: "2026-09-03T21:41:22Z", Source: "hook", Skill: "s", Decision: tc.decision}
			e, err := FromGateEvent(g, "skillctl/test")
			if err != nil {
				t.Fatalf("FromGateEvent: %v", err)
			}
			if e.EventType != tc.wantType || e.Outcome != tc.wantOut || e.Severity != tc.wantSev {
				t.Fatalf("mapping %q: got (%s,%s,%s) want (%s,%s,%s)",
					tc.decision, e.EventType, e.Outcome, e.Severity, tc.wantType, tc.wantOut, tc.wantSev)
			}
			if e.Policy == nil || e.Policy.Decision != tc.decision {
				t.Fatalf("original verdict not preserved in policy.decision: %+v", e.Policy)
			}
			if err := e.Validate(); err != nil {
				t.Fatalf("mapped event invalid: %v", err)
			}
		})
	}
}

// TestGateUnknownDecisionRejected proves an unknown verdict is an error, not a
// silently mis-typed event.
func TestGateUnknownDecisionRejected(t *testing.T) {
	_, err := FromGateEvent(GateEvent{Ts: "t", Decision: "explode"}, "skillctl/test")
	if !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("unknown decision must error with ErrInvalidEvent: %v", err)
	}
}

// TestGateEventGolden pins the full envelope for a realistic recorded deny line.
// The event_id is overwritten with a fixed value (id generation is proven
// separately in eventid_test); everything else is the mapping's output.
func TestGateEventGolden(t *testing.T) {
	line := `{"ts":"2026-09-03T21:41:22Z","source":"hook","skill":"compliance-review",` +
		`"decision":"deny","reason":"revoked bundle","exit_code":2,` +
		`"content_digest":"sha256:abc","online":true,"cache_hit":false,"session_id":"sess_9"}`

	var g GateEvent
	if err := json.Unmarshal([]byte(line), &g); err != nil {
		t.Fatalf("unmarshal gate line: %v", err)
	}
	e, err := FromGateEvent(g, "skillctl/0.4.0")
	if err != nil {
		t.Fatalf("FromGateEvent: %v", err)
	}
	e.EventID = "01GOLDENGATEEVENT000000000" // pin the only non-deterministic field.

	got, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"actor":{"type":"gate","id":"hook"},"event_id":"01GOLDENGATEEVENT000000000","event_type":"policy.deny","gate.cache_hit":false,"gate.exit_code":2,"gate.online":true,"message":"revoked bundle","outcome":"deny","policy":{"decision":"deny"},"producer":"skillctl/0.4.0","schema":"skillctl.audit.v1","session_id":"sess_9","severity":"warning","skill":{"name":"compliance-review","digest":"sha256:abc"},"timestamp":"2026-09-03T21:41:22Z"}`
	if string(got) != want {
		t.Fatalf("golden mismatch:\n got=%s\nwant=%s", got, want)
	}
}
