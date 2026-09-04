package auditevent

import "testing"

// TestTaxonomyStringsPinned pins the exact string value of every taxonomy
// constant (REQ-4.2: event semantics MUST NOT change silently within a schema
// version). A rename or typo of any wire value fails this test loudly.
func TestTaxonomyStringsPinned(t *testing.T) {
	want := map[EventType]string{
		EventSkillVerify:        "skill.verify",
		EventSkillInstall:       "skill.install",
		EventSkillRemove:        "skill.remove",
		EventSkillExecute:       "skill.execute",
		EventSignatureVerify:    "signature.verify",
		EventSignatureReject:    "signature.reject",
		EventProvenanceVerify:   "provenance.verify",
		EventProvenanceReject:   "provenance.reject",
		EventRevocationCheck:    "revocation.check",
		EventRevocationDetect:   "revocation.detect",
		EventTrustrootLoad:      "trustroot.load",
		EventTrustrootChange:    "trustroot.change",
		EventPolicyEvaluate:     "policy.evaluate",
		EventPolicyAllow:        "policy.allow",
		EventPolicyDeny:         "policy.deny",
		EventCapabilityRequest:  "capability.request",
		EventCapabilityGrant:    "capability.grant",
		EventCapabilityDeny:     "capability.deny",
		EventCapabilityDrift:    "capability.drift",
		EventReferenceBind:      "reference.bind",
		EventReferenceResolve:   "reference.resolve",
		EventReferenceReject:    "reference.reject",
		EventInvocationStart:    "invocation.start",
		EventInvocationComplete: "invocation.complete",
		EventInvocationFail:     "invocation.fail",
		EventEvidenceCreate:     "evidence.create",
		EventEvidenceExport:     "evidence.export",
		EventAuditSinkConnect:   "audit.sink.connect",
		EventAuditSinkFail:      "audit.sink.fail",
		EventAuditQueueEnqueue:  "audit.queue.enqueue",
		EventAuditQueueFlush:    "audit.queue.flush",
		EventConfigChange:       "config.change",
	}
	for c, s := range want {
		if string(c) != s {
			t.Errorf("taxonomy value drift: got %q want %q", string(c), s)
		}
		if !IsKnownEventType(c) {
			t.Errorf("%q not reported as known", s)
		}
	}
	// The whole §4 initial taxonomy is present and nothing extra slipped in.
	if got := len(KnownEventTypes()); got != len(want) {
		t.Fatalf("taxonomy size drift: got %d want %d (update REQ-4.1 + this test together)", got, len(want))
	}
}

// TestTaxonomyVersionPinned pins the taxonomy version and schema tag together.
func TestTaxonomyVersionPinned(t *testing.T) {
	if TaxonomyVersion != "1" {
		t.Errorf("TaxonomyVersion drift: %q", TaxonomyVersion)
	}
	if SchemaV1 != "skillctl.audit.v1" {
		t.Errorf("SchemaV1 drift: %q", SchemaV1)
	}
}

// TestUnknownTaxonomyRejected proves the closed set fails closed.
func TestUnknownTaxonomyRejected(t *testing.T) {
	if IsKnownEventType("skill.teleport") {
		t.Errorf("unknown event type reported known")
	}
	if IsKnownOutcome("maybe") {
		t.Errorf("unknown outcome reported known")
	}
	if IsKnownSeverity("loud") {
		t.Errorf("unknown severity reported known")
	}
}

// TestOutcomeAndSeverityPinned pins the two other controlled vocabularies.
func TestOutcomeAndSeverityPinned(t *testing.T) {
	outcomes := map[Outcome]string{
		OutcomeSuccess: "success", OutcomeFailure: "failure",
		OutcomeDeny: "deny", OutcomeError: "error",
	}
	for c, s := range outcomes {
		if string(c) != s {
			t.Errorf("outcome drift: got %q want %q", string(c), s)
		}
		if !IsKnownOutcome(c) {
			t.Errorf("outcome %q not known", s)
		}
	}
	sevs := map[Severity]string{
		SeverityInfo: "info", SeverityNotice: "notice", SeverityWarning: "warning",
		SeverityError: "error", SeverityCritical: "critical",
	}
	for c, s := range sevs {
		if string(c) != s {
			t.Errorf("severity drift: got %q want %q", string(c), s)
		}
		if !IsKnownSeverity(c) {
			t.Errorf("severity %q not known", s)
		}
	}
}
