package auditevent

// gatemap.go: the SPEC-0403 §4 mapping. The existing SPEC-0255 gate-audit.jsonl
// line (cmd/skillctl's gateEvent) is projected onto the shared envelope. The §4
// note is explicit: the gateEvent (ts · source · skill · decision · reason ·
// exit_code · content_digest · online · cache_hit · session_id) becomes
// policy.allow / policy.deny / policy.evaluate carrying the §3 envelope, and the
// original SPEC-0247/SPEC-0255 verdict (allow · deny · quarantine · leave) is
// preserved verbatim in policy.decision (REQ-4.3) so nothing is lost.
//
// SCOPE (FR-0109). This is a PURE mapping function proven by a golden test. It
// does NOT rewire cmd/skillctl/gate_audit.go: that runtime change (and the
// gate-stats dual-read of pre-migration lines, O6) is FR-0110. GateEvent is
// mirrored here rather than imported because gateEvent lives in package main.

import (
	"encoding/json"
	"fmt"
)

// GateEvent mirrors cmd/skillctl's gateEvent, one line of gate-audit.jsonl
// (SPEC-0255). The JSON tags match the on-disk field names so a real recorded
// line unmarshals straight into it.
type GateEvent struct {
	Ts            string `json:"ts"`             // RFC3339 UTC.
	Source        string `json:"source"`         // "hook" | "sweep".
	Skill         string `json:"skill"`          // skill name.
	Decision      string `json:"decision"`       // allow | deny | quarantine | leave.
	Reason        string `json:"reason"`         // human-readable reason.
	ExitCode      int    `json:"exit_code"`      // gate exit code.
	ContentDigest string `json:"content_digest"` // sha256:<hex> of the bundle.
	Online        bool   `json:"online"`         // the online chain ran (hook path).
	CacheHit      bool   `json:"cache_hit"`      // a verdict-cache hit served it (hook path).
	SessionID     string `json:"session_id"`     // Claude Code session id.
}

// FromGateEvent maps one recorded gate decision onto the shared audit envelope.
// producer is the caller's producer tag (e.g. ProducerString(version)); the
// event's timestamp is taken from the recorded line and a fresh event_id is
// minted (a gate line has no id of its own). The gate-runtime-only telemetry
// (exit_code, online, cache_hit) is carried as extension fields (REQ-3.3) rather
// than forced into the core taxonomy. An unknown decision string is an error.
func FromGateEvent(g GateEvent, producer string) (*Event, error) {
	eventType, outcome, severity, err := classifyGateDecision(g.Decision)
	if err != nil {
		return nil, err
	}

	e := &Event{
		Schema:    SchemaV1,
		Timestamp: g.Ts,
		EventID:   NewEventID(),
		EventType: eventType,
		Outcome:   outcome,
		Severity:  severity,
		Producer:  producer,
		SessionID: g.SessionID,
		Actor:     &ActorRef{Type: "gate", ID: g.Source},
		// Preserve the exact SPEC-0247/SPEC-0255 verdict; event_type is the
		// taxonomy classification, policy.decision is the source vocabulary.
		Policy: &PolicyRef{Decision: g.Decision},
	}
	if g.Skill != "" || g.ContentDigest != "" {
		e.Skill = &SkillRef{Name: g.Skill, Digest: g.ContentDigest}
	}
	if g.Reason != "" {
		e.Message = g.Reason
	}
	// Gate-runtime telemetry becomes extension fields, keyed under a "gate."
	// prefix so they never collide with a canonical field. SetExt of a bool or
	// int cannot fail.
	_ = e.SetExt("gate.exit_code", g.ExitCode) //nolint:errcheck // marshaling an int cannot fail.
	_ = e.SetExt("gate.online", g.Online)      //nolint:errcheck // marshaling a bool cannot fail.
	_ = e.SetExt("gate.cache_hit", g.CacheHit) //nolint:errcheck // marshaling a bool cannot fail.

	if err := e.Validate(); err != nil {
		return nil, err
	}
	return e, nil
}

// ToGateEvent reconstructs the SPEC-0255 gate view from a skillctl.audit.v1
// envelope that FromGateEvent produced. It is the reader half of the O6 clean-cut
// (SPEC-0403 §13-O6): `gate-stats` consumes ONLY this new format. ok is false for
// anything that is not a gate policy event on the current schema. an old flat
// gate-audit.jsonl line unmarshals into an Event with an empty Schema / nil
// Policy and is therefore rejected here (abandoned, not migrated, not read).
func ToGateEvent(e *Event) (GateEvent, bool) {
	if e == nil || e.Schema != SchemaV1 || e.Policy == nil || e.Policy.Decision == "" {
		return GateEvent{}, false
	}
	g := GateEvent{
		Ts:        e.Timestamp,
		Decision:  e.Policy.Decision,
		Reason:    e.Message,
		SessionID: e.SessionID,
	}
	if e.Actor != nil {
		g.Source = e.Actor.ID
	}
	if e.Skill != nil {
		g.Skill = e.Skill.Name
		g.ContentDigest = e.Skill.Digest
	}
	g.ExitCode = extInt(e, "gate.exit_code")
	g.Online = extBool(e, "gate.online")
	g.CacheHit = extBool(e, "gate.cache_hit")
	return g, true
}

// extInt reads an integer extension field, returning 0 if it is absent or not an
// integer (a tolerant read: a missing gate telemetry field is a zero, not a fault).
func extInt(e *Event, key string) int {
	raw, ok := e.Ext[key]
	if !ok {
		return 0
	}
	var n int
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0
	}
	return n
}

// extBool reads a boolean extension field, returning false if it is absent or not
// a bool.
func extBool(e *Event, key string) bool {
	raw, ok := e.Ext[key]
	if !ok {
		return false
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err != nil {
		return false
	}
	return b
}

// classifyGateDecision maps a SPEC-0255 verdict to (event_type, outcome,
// severity):
//
//	allow      -> policy.allow    success  info     (the gate permitted the skill)
//	deny       -> policy.deny     deny     warning  (the gate refused it)
//	quarantine -> policy.deny     deny     warning  (isolation is a deny-class action)
//	leave      -> policy.evaluate success  info     (a sweep that took no action)
//
// quarantine and leave collapse onto policy.deny / policy.evaluate per the §4
// note; the exact verdict survives in policy.decision so the collapse is lossless.
func classifyGateDecision(decision string) (EventType, Outcome, Severity, error) {
	switch decision {
	case "allow":
		return EventPolicyAllow, OutcomeSuccess, SeverityInfo, nil
	case "deny":
		return EventPolicyDeny, OutcomeDeny, SeverityWarning, nil
	case "quarantine":
		return EventPolicyDeny, OutcomeDeny, SeverityWarning, nil
	case "leave":
		return EventPolicyEvaluate, OutcomeSuccess, SeverityInfo, nil
	default:
		return "", "", "", fmt.Errorf("%w: unknown gate decision %q", ErrInvalidEvent, decision)
	}
}
