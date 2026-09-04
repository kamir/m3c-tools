package auditevent

// taxonomy.go: the SPEC-0403 §4 event taxonomy: stable, hierarchical event-type
// names, plus the outcome and severity vocabularies. Event semantics MUST NOT
// change silently within a schema version (REQ-4.2). The types below reuse
// already-defined decision vocabularies and DO NOT invent a second one (REQ-4.3):
// policy.* ↔ SPEC-0247/SPEC-0255, capability.* ↔ SPEC-0402 §3/§7, reference.* ↔
// SPEC-0401 §3 + SPEC-0402 §5, evidence.* ↔ SPEC-0402 §6, revocation.* ↔
// FR-0045/SPEC-0279.

// TaxonomyVersion tracks the taxonomy independently of the wire schema tag so an
// additive taxonomy revision is a visible bump, not a silent redefinition
// (REQ-4.2). It is "1" while SchemaV1 is in force; adding a new event type is a
// minor, semantics-preserving change.
const TaxonomyVersion = "1"

// EventType is a hierarchical, dotted taxonomy name (REQ-4.1). It is a distinct
// string type so a typo in a producer is a compile error against the constants
// below, not a silent unknown type.
type EventType string

// The initial taxonomy (REQ-4.1). Grouped by domain. These string values are a
// STABLE contract pinned by a test; renaming one is a breaking change requiring
// a schema-version bump.
const (
	// skill lifecycle.
	EventSkillVerify  EventType = "skill.verify"
	EventSkillInstall EventType = "skill.install"
	EventSkillRemove  EventType = "skill.remove"
	EventSkillExecute EventType = "skill.execute"

	// signature verification.
	EventSignatureVerify EventType = "signature.verify"
	EventSignatureReject EventType = "signature.reject"

	// provenance verification.
	EventProvenanceVerify EventType = "provenance.verify"
	EventProvenanceReject EventType = "provenance.reject"

	// revocation (↔ FR-0045/SPEC-0279).
	EventRevocationCheck  EventType = "revocation.check"
	EventRevocationDetect EventType = "revocation.detect"

	// trust roots.
	EventTrustrootLoad   EventType = "trustroot.load"
	EventTrustrootChange EventType = "trustroot.change"

	// policy (↔ SPEC-0247/SPEC-0255).
	EventPolicyEvaluate EventType = "policy.evaluate"
	EventPolicyAllow    EventType = "policy.allow"
	EventPolicyDeny     EventType = "policy.deny"

	// capability (↔ SPEC-0402 §3/§7).
	EventCapabilityRequest EventType = "capability.request"
	EventCapabilityGrant   EventType = "capability.grant"
	EventCapabilityDeny    EventType = "capability.deny"
	EventCapabilityDrift   EventType = "capability.drift"

	// reference binding (↔ SPEC-0401 §3 + SPEC-0402 §5).
	EventReferenceBind    EventType = "reference.bind"
	EventReferenceResolve EventType = "reference.resolve"
	EventReferenceReject  EventType = "reference.reject"

	// invocation lifecycle.
	EventInvocationStart    EventType = "invocation.start"
	EventInvocationComplete EventType = "invocation.complete"
	EventInvocationFail     EventType = "invocation.fail"

	// evidence (↔ SPEC-0402 §6).
	EventEvidenceCreate EventType = "evidence.create"
	EventEvidenceExport EventType = "evidence.export"

	// the audit subsystem's own health (REQ-8.1; emission wired in FR-0111).
	EventAuditSinkConnect  EventType = "audit.sink.connect"
	EventAuditSinkFail     EventType = "audit.sink.fail"
	EventAuditQueueEnqueue EventType = "audit.queue.enqueue"
	EventAuditQueueFlush   EventType = "audit.queue.flush"

	// configuration.
	EventConfigChange EventType = "config.change"
)

// knownEventTypes is the closed set for the current TaxonomyVersion. Validate
// and IsKnownEventType consult it so an unknown type fails closed (REQ-4.1/4.2).
var knownEventTypes = map[EventType]struct{}{
	EventSkillVerify: {}, EventSkillInstall: {}, EventSkillRemove: {}, EventSkillExecute: {},
	EventSignatureVerify: {}, EventSignatureReject: {},
	EventProvenanceVerify: {}, EventProvenanceReject: {},
	EventRevocationCheck: {}, EventRevocationDetect: {},
	EventTrustrootLoad: {}, EventTrustrootChange: {},
	EventPolicyEvaluate: {}, EventPolicyAllow: {}, EventPolicyDeny: {},
	EventCapabilityRequest: {}, EventCapabilityGrant: {}, EventCapabilityDeny: {}, EventCapabilityDrift: {},
	EventReferenceBind: {}, EventReferenceResolve: {}, EventReferenceReject: {},
	EventInvocationStart: {}, EventInvocationComplete: {}, EventInvocationFail: {},
	EventEvidenceCreate: {}, EventEvidenceExport: {},
	EventAuditSinkConnect: {}, EventAuditSinkFail: {}, EventAuditQueueEnqueue: {}, EventAuditQueueFlush: {},
	EventConfigChange: {},
}

// IsKnownEventType reports whether t is part of the current taxonomy version.
func IsKnownEventType(t EventType) bool {
	_, ok := knownEventTypes[t]
	return ok
}

// KnownEventTypes returns every event type in the current taxonomy version. The
// returned slice is a copy the caller may sort or mutate freely.
func KnownEventTypes() []EventType {
	out := make([]EventType, 0, len(knownEventTypes))
	for t := range knownEventTypes {
		out = append(out, t)
	}
	return out
}

// Outcome describes how the audited action resolved (mandatory, REQ-3.1).
type Outcome string

// The outcome vocabulary. deny is distinct from failure so a policy denial (a
// working system refusing an action) is not confused with an operation that
// failed, and error marks an internal/transport fault (e.g. audit.sink.fail).
const (
	OutcomeSuccess Outcome = "success" // the action completed / verified.
	OutcomeFailure Outcome = "failure" // a verification or operation failed (e.g. signature.reject).
	OutcomeDeny    Outcome = "deny"    // a policy/capability decision to refuse.
	OutcomeError   Outcome = "error"   // an internal or transport fault.
)

var knownOutcomes = map[Outcome]struct{}{
	OutcomeSuccess: {}, OutcomeFailure: {}, OutcomeDeny: {}, OutcomeError: {},
}

// IsKnownOutcome reports whether o is part of the outcome vocabulary.
func IsKnownOutcome(o Outcome) bool {
	_, ok := knownOutcomes[o]
	return ok
}

// Severity ranks the operational importance of an event (mandatory, REQ-3.1).
type Severity string

// The severity vocabulary, low to high.
const (
	SeverityInfo     Severity = "info"
	SeverityNotice   Severity = "notice"
	SeverityWarning  Severity = "warning"
	SeverityError    Severity = "error"
	SeverityCritical Severity = "critical"
)

var knownSeverities = map[Severity]struct{}{
	SeverityInfo: {}, SeverityNotice: {}, SeverityWarning: {}, SeverityError: {}, SeverityCritical: {},
}

// IsKnownSeverity reports whether s is part of the severity vocabulary.
func IsKnownSeverity(s Severity) bool {
	_, ok := knownSeverities[s]
	return ok
}
