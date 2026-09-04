// Package auditevent is the FR-0109 foundation of SPEC-0403 (skillctl Audit
// Event Layer): the ONE shared, versioned audit-event envelope, its taxonomy,
// a redaction step, a Sink abstraction and a Dispatcher.
//
// SCOPE (FR-0109 only). This package defines WHAT an audit event IS: the
// envelope (§3), the taxonomy (§4), the default infrastructure-free file sink
// and the redaction/data-minimization step (§5/§5.1), plus the Event → Dispatcher
// → Sink seam (§7.2) so transport stays separate from event creation. It does
// NOT own durability or delivery modes (best-effort / durable / required,
// FR-0110, §6), the outbox itself (SPEC-0317 owns it, §7.1: this package writes
// INTO it via a future OutboxSink, it does not build a second store), a Kafka
// sink (FR-0112, EC-blocked, §7.2) or any CLI verb (skillctl auditlog, FR-0111,
// §8). The Sink interface below is deliberately shaped so an outbox-backed
// durable sink slots in without a signature change.
//
// RELATION TO SPEC-0383 (§3.1). skillctl.audit.v1 is an EXPRESSION within the
// decision-event family, not a competitor: audit events are the capability.*
// stream. This package owns the audit envelope; the transport hull and fleet
// egress (SPEC-0351 / SPEC-0383 T2) are out of scope here.
//
// NOT AN EVIDENCE RECORD (REQ-1.2 / AUD-08). An Event in this package is an
// accountability record, not cryptographic evidence. It carries no signature in
// v1 (the optional hash-chain / signature fields of §9 are deferred); a line in
// a log is never, by itself, verified evidence.
package auditevent

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// SchemaV1 is the versioned schema tag every v1 audit event carries. It is a
// value at a fixed field, so a future format change is a value change; not a
// silent reinterpretation (REQ-3.1 / REQ-4.2).
const SchemaV1 = "skillctl.audit.v1"

// ErrInvalidEvent is the sentinel wrapped by Validate for every rejection, so
// callers can errors.Is it without matching on message text.
var ErrInvalidEvent = errors.New("auditevent: invalid event")

// SkillRef identifies the skill an event concerns (REQ-3.2 skill.{name,version,digest}).
type SkillRef struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	Digest  string `json:"digest,omitempty"` // sha256:<hex> of the bundle.
}

// ActorRef identifies the workload or human that performed the action
// (REQ-3.2 actor.{type,id}).
type ActorRef struct {
	Type string `json:"type,omitempty"` // e.g. workload | human | gate.
	ID   string `json:"id,omitempty"`
}

// PrincipalRef identifies the security principal on whose behalf the action ran
// (REQ-3.2 principal.id).
type PrincipalRef struct {
	ID string `json:"id,omitempty"`
}

// ResourceRef identifies the resource acted upon (REQ-3.2 resource.{type,id}).
type ResourceRef struct {
	Type string `json:"type,omitempty"`
	ID   string `json:"id,omitempty"`
}

// PolicyRef carries the policy identity and its decision, using the SPEC-0247 /
// SPEC-0255 vocabulary (allow · deny · quarantine · leave) verbatim so no
// information is lost when the taxonomy classifies the event (REQ-3.2 / REQ-4.3).
type PolicyRef struct {
	ID       string `json:"id,omitempty"`
	Decision string `json:"decision,omitempty"`
}

// ReferenceRef identifies a bound reference document by source and digest; never
// its contents (REQ-3.2 reference.{source,digest}; REQ-5.4 forbids the full doc).
type ReferenceRef struct {
	Source string `json:"source,omitempty"`
	Digest string `json:"digest,omitempty"`
}

// CapabilityRef identifies the capability an event concerns, against the
// SPEC-0402 vocabulary (REQ-3.2 capability.{type,name}; REQ-4.3).
type CapabilityRef struct {
	Type string `json:"type,omitempty"`
	Name string `json:"name,omitempty"`
}

// ErrorRef carries a stable error code and category; never a raw error string
// that might embed a secret (REQ-3.2 error.{code,category}).
type ErrorRef struct {
	Code     string `json:"code,omitempty"`
	Category string `json:"category,omitempty"`
}

// Event is the shared, versioned audit envelope (SPEC-0403 §3). The first seven
// fields are MANDATORY (REQ-3.1); the rest are optional and applied where
// meaningful (REQ-3.2). Unknown optional fields on the wire are tolerated and
// preserved in Ext (REQ-3.3); JSON Lines is the canonical representation (REQ-3.4).
type Event struct {
	// --- mandatory (REQ-3.1) ---

	Schema    string    `json:"schema"`     // SchemaV1.
	Timestamp string    `json:"timestamp"`  // RFC3339 UTC, millisecond precision.
	EventID   string    `json:"event_id"`   // ULID-like, stable per event (AUD-04).
	EventType EventType `json:"event_type"` // a taxonomy constant (REQ-4.1).
	Outcome   Outcome   `json:"outcome"`    // success | failure | deny | error.
	Severity  Severity  `json:"severity"`   // info | notice | warning | error | critical.
	Producer  string    `json:"producer"`   // e.g. skillctl/0.4.0.

	// --- optional, applied where meaningful (REQ-3.2) ---

	Message       string         `json:"message,omitempty"` // short human-readable note; never a full prompt/response (REQ-5.4).
	Skill         *SkillRef      `json:"skill,omitempty"`
	Actor         *ActorRef      `json:"actor,omitempty"`
	Principal     *PrincipalRef  `json:"principal,omitempty"`
	InvocationID  string         `json:"invocation_id,omitempty"`
	SessionID     string         `json:"session_id,omitempty"`
	CorrelationID string         `json:"correlation_id,omitempty"`
	Resource      *ResourceRef   `json:"resource,omitempty"`
	Policy        *PolicyRef     `json:"policy,omitempty"`
	Reference     *ReferenceRef  `json:"reference,omitempty"`
	Capability    *CapabilityRef `json:"capability,omitempty"`
	Error         *ErrorRef      `json:"error,omitempty"`

	// Ext captures extension / unknown top-level fields so an event a newer
	// producer wrote does not break an older consumer, and a producer's own
	// extension fields survive a round-trip (REQ-3.3). An Ext key that collides
	// with a canonical field name is dropped on marshal; a canonical field can
	// never be shadowed. Ext is NOT emitted under its own key; its entries are
	// merged at the top level.
	Ext map[string]json.RawMessage `json:"-"`
}

// knownEventKeys is the set of canonical top-level JSON keys. UnmarshalJSON
// removes these from the raw object; whatever remains is an extension field
// captured in Ext (REQ-3.3). Keep in sync with the struct tags above.
var knownEventKeys = map[string]struct{}{
	"schema": {}, "timestamp": {}, "event_id": {}, "event_type": {},
	"outcome": {}, "severity": {}, "producer": {}, "message": {},
	"skill": {}, "actor": {}, "principal": {}, "invocation_id": {},
	"session_id": {}, "correlation_id": {}, "resource": {}, "policy": {},
	"reference": {}, "capability": {}, "error": {},
}

// New builds a v1 Event with the mandatory envelope stamped: SchemaV1, an RFC3339
// millisecond UTC timestamp, and a fresh ULID-like event_id. The optional fields
// are filled by the caller. Producer is required by Validate; pass e.g.
// ProducerString(version).
func New(eventType EventType, outcome Outcome, severity Severity, producer string) *Event {
	return &Event{
		Schema:    SchemaV1,
		Timestamp: time.Now().UTC().Format(timestampLayout),
		EventID:   NewEventID(),
		EventType: eventType,
		Outcome:   outcome,
		Severity:  severity,
		Producer:  producer,
	}
}

// ProducerString formats a producer tag as "skillctl/<version>" (REQ-3.1). An
// empty version yields the bare component name.
func ProducerString(version string) string {
	if version == "" {
		return "skillctl"
	}
	return "skillctl/" + version
}

// timestampLayout is RFC3339 with millisecond precision and a Z zone, matching
// the §3 example (2026-09-03T21:41:22.318Z).
const timestampLayout = "2006-01-02T15:04:05.000Z07:00"

// Validate enforces the mandatory envelope (REQ-3.1) and the controlled
// vocabularies (REQ-4.1 event_type, outcome, severity). It returns an error
// wrapping ErrInvalidEvent. Unknown OPTIONAL fields never fail validation
// (REQ-3.3); they live in Ext and are ignored here.
func (e *Event) Validate() error {
	if e == nil {
		return fmt.Errorf("%w: nil event", ErrInvalidEvent)
	}
	switch {
	case e.Schema == "":
		return fmt.Errorf("%w: missing schema", ErrInvalidEvent)
	case e.Timestamp == "":
		return fmt.Errorf("%w: missing timestamp", ErrInvalidEvent)
	case e.EventID == "":
		return fmt.Errorf("%w: missing event_id", ErrInvalidEvent)
	case e.EventType == "":
		return fmt.Errorf("%w: missing event_type", ErrInvalidEvent)
	case e.Outcome == "":
		return fmt.Errorf("%w: missing outcome", ErrInvalidEvent)
	case e.Severity == "":
		return fmt.Errorf("%w: missing severity", ErrInvalidEvent)
	case e.Producer == "":
		return fmt.Errorf("%w: missing producer", ErrInvalidEvent)
	}
	if !IsKnownEventType(e.EventType) {
		return fmt.Errorf("%w: unknown event_type %q", ErrInvalidEvent, e.EventType)
	}
	if !IsKnownOutcome(e.Outcome) {
		return fmt.Errorf("%w: unknown outcome %q", ErrInvalidEvent, e.Outcome)
	}
	if !IsKnownSeverity(e.Severity) {
		return fmt.Errorf("%w: unknown severity %q", ErrInvalidEvent, e.Severity)
	}
	return nil
}

// MarshalJSON emits the canonical single-object form (REQ-3.4). Extension fields
// in Ext are merged at the top level; a key that collides with a canonical field
// is dropped so a canonical field is never shadowed. Output key order is
// deterministic (encoding/json sorts map keys) so two identical events serialize
// to byte-identical lines.
func (e Event) MarshalJSON() ([]byte, error) {
	type alias Event // alias drops the MarshalJSON method and (via json:"-") Ext.
	base, err := json.Marshal(alias(e))
	if err != nil {
		return nil, err
	}
	if len(e.Ext) == 0 {
		return base, nil
	}
	var merged map[string]json.RawMessage
	if err := json.Unmarshal(base, &merged); err != nil {
		return nil, err
	}
	for k, v := range e.Ext {
		if _, isCanonical := knownEventKeys[k]; isCanonical {
			continue // never let an extension key shadow a canonical field.
		}
		merged[k] = v
	}
	return json.Marshal(merged)
}

// UnmarshalJSON is tolerant (REQ-3.3): unknown optional fields never fail the
// parse; they are captured in Ext and survive a re-marshal. Known fields are
// decoded normally.
func (e *Event) UnmarshalJSON(data []byte) error {
	type alias Event
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*e = Event(a)
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for k := range knownEventKeys {
		delete(raw, k)
	}
	if len(raw) > 0 {
		e.Ext = raw
	} else {
		e.Ext = nil
	}
	return nil
}

// SetExt stores one extension field, marshaling v to JSON. A key that collides
// with a canonical field name is refused (it would be dropped on marshal anyway).
func (e *Event) SetExt(key string, v any) error {
	if _, isCanonical := knownEventKeys[key]; isCanonical {
		return fmt.Errorf("%w: extension key %q collides with a canonical field", ErrInvalidEvent, key)
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("auditevent: marshal ext %q: %w", key, err)
	}
	if e.Ext == nil {
		e.Ext = make(map[string]json.RawMessage, 1)
	}
	e.Ext[key] = raw
	return nil
}
