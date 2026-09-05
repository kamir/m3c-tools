package auditevent

// lifecyclemap.go: the SECOND producer mapping onto the shared skillctl.audit.v1
// envelope, next to gatemap.go.
//
// WHY THIS EXISTS. SPEC-0403 defined the envelope and the taxonomy, and exactly
// one producer used them: the SPEC-0255 gate. `skillctl install` and
// `skillctl verify` made trust decisions and emitted nothing, which made
// SPEC-0406 AC-07 ("security-relevant refusals leave an audit event")
// unsatisfiable and its matrix row T15 permanently red. This file closes that
// gap for the install/verify lifecycle.
//
// THE DESIGN RULE, and it is the same one gatemap.go follows: the taxonomy
// CLASSIFIES, the source vocabulary is PRESERVED. `event_type` says which family
// a refusal belongs to; `error.code` carries the exact reason the verifier
// named, and `ext` carries the SPEC-0188 §11 numbered exit code verbatim. A
// reader who only knows the taxonomy learns the shape; a reader who knows
// skillctl learns the precise cause. Neither is derived from the other after the
// fact.
//
// WHY THE REASON CODE IS A STRING AND NOT AN ERROR. This package is a leaf: it
// must not import pkg/skillctl/verify, or the audit layer would depend on the
// trust layer it audits. The caller resolves its typed sentinel into one of the
// stable ReasonCode constants below and passes that. The mapping from sentinel
// to code lives with the caller (cmd/skillctl/lifecycle_audit.go), the mapping
// from code to taxonomy lives here, and a test pins both ends.

import (
	"fmt"
	"time"
)

// LifecycleOp is the lifecycle verb an event describes. It is deliberately not
// the whole CLI surface: only the two verbs that run the SPEC-0188 §7 trust
// chain and therefore make a trust decision worth auditing.
type LifecycleOp string

const (
	OpInstall LifecycleOp = "install"
	OpVerify  LifecycleOp = "verify"
)

// ReasonCode is the stable, machine-readable cause of a lifecycle outcome. These
// strings are a CONTRACT: they appear in audit records that outlive the binary
// that wrote them, so renaming one is a breaking change and needs a schema
// version bump, exactly like an event type (REQ-4.2).
//
// They are also the answer to SPEC-0406 AC-16 for this surface: a stable code a
// machine can match on, paired with a message a human can read. Neither replaces
// the other.
type ReasonCode string

const (
	// ReasonOK marks a completed operation. It is a value rather than the empty
	// string so "the operation succeeded" and "nobody set a reason" are
	// distinguishable in a stored record.
	ReasonOK ReasonCode = "ok"

	// Integrity and signature: the artifact is not what the signed statement says.
	ReasonDigestMismatch      ReasonCode = "digest_mismatch"
	ReasonAuthorSigInvalid    ReasonCode = "author_signature_invalid"
	ReasonLogInclusionMissing ReasonCode = "log_inclusion_missing"

	// Provenance: the artifact may be intact, but its origin does not check out.
	ReasonRegistryNotTrusted ReasonCode = "registry_not_trusted"
	ReasonBlobMissing        ReasonCode = "blob_missing"
	ReasonIdentityMismatch   ReasonCode = "identity_mismatch"

	// Policy: the chain verified, and a rule still says no.
	ReasonGovernanceBelowMin ReasonCode = "governance_below_minimum"
	ReasonDepsUnsatisfied    ReasonCode = "deps_unsatisfied"
	ReasonTenantBlocked      ReasonCode = "tenant_blocked"
	ReasonIntentInconsistent ReasonCode = "intent_inconsistent"
	ReasonSelfAttested       ReasonCode = "self_attested"
	ReasonDataSourceDenied   ReasonCode = "data_source_denied"

	// Revocation: someone pulled the brake, or we cannot prove nobody did.
	ReasonIdentityRevoked ReasonCode = "identity_revoked"
	ReasonRevocationStale ReasonCode = "revocation_stale"

	// ReasonInternalError is the catch-all for a non-trust failure (a broken
	// config file, an unreachable registry). It is deliberately NOT folded into
	// a refusal reason: "we refused you" and "we broke" are different events,
	// and conflating them is how an outage gets read as an attack.
	ReasonInternalError ReasonCode = "internal_error"
)

// lifecycleClass is the taxonomy + outcome + severity a reason maps to.
type lifecycleClass struct {
	refusalType EventType
	outcome     Outcome
	severity    Severity
	category    string // error.category: the coarse grouping a dashboard filters on.
}

// reasonClasses is the closed mapping from reason to classification. Keeping it
// as data rather than a switch is deliberate: a test iterates it to prove every
// declared ReasonCode has a class and every class names a KNOWN event type, so a
// new reason cannot be added without also being classified.
//
// On the choice of event_type for the integrity family: the taxonomy has no
// `integrity.reject`, and adding one is a taxonomy change that would need its
// own decision. A digest mismatch IS a failure of the signed statement about the
// bytes, so signature.reject is the honest family for it, and error.code says
// digest_mismatch so nothing is lost. SPEC-0406 §Phase 9 names exactly this pair.
var reasonClasses = map[ReasonCode]lifecycleClass{
	ReasonDigestMismatch:      {EventSignatureReject, OutcomeFailure, SeverityError, "integrity"},
	ReasonAuthorSigInvalid:    {EventSignatureReject, OutcomeFailure, SeverityError, "signature"},
	ReasonLogInclusionMissing: {EventSignatureReject, OutcomeFailure, SeverityError, "transparency_log"},

	ReasonRegistryNotTrusted: {EventProvenanceReject, OutcomeFailure, SeverityError, "provenance"},
	ReasonBlobMissing:        {EventProvenanceReject, OutcomeFailure, SeverityError, "provenance"},
	ReasonIdentityMismatch:   {EventProvenanceReject, OutcomeFailure, SeverityError, "provenance"},

	ReasonGovernanceBelowMin: {EventPolicyDeny, OutcomeDeny, SeverityWarning, "governance"},
	ReasonDepsUnsatisfied:    {EventPolicyDeny, OutcomeDeny, SeverityWarning, "dependencies"},
	ReasonTenantBlocked:      {EventPolicyDeny, OutcomeDeny, SeverityWarning, "tenancy"},
	ReasonIntentInconsistent: {EventPolicyDeny, OutcomeDeny, SeverityWarning, "intent"},
	ReasonSelfAttested:       {EventPolicyDeny, OutcomeDeny, SeverityWarning, "governance"},
	ReasonDataSourceDenied:   {EventPolicyDeny, OutcomeDeny, SeverityWarning, "data_source"},

	// A detected revocation is critical: it is the one refusal that says an
	// artifact which once passed must now be treated as hostile.
	ReasonIdentityRevoked: {EventRevocationDetect, OutcomeDeny, SeverityCritical, "revocation"},
	// A stale snapshot is a refusal because we cannot SEE a revocation, which is
	// a weaker statement than having seen one. Warning, not critical.
	ReasonRevocationStale: {EventPolicyDeny, OutcomeDeny, SeverityWarning, "revocation_freshness"},
}

// KnownReasonCodes returns every declared reason code. The returned slice is a
// copy the caller may sort or mutate.
func KnownReasonCodes() []ReasonCode {
	out := make([]ReasonCode, 0, len(reasonClasses)+2)
	out = append(out, ReasonOK, ReasonInternalError)
	for r := range reasonClasses {
		out = append(out, r)
	}
	return out
}

// LifecycleEvent is the flat record an install/verify run hands to the mapper.
// It mirrors GateEvent: a plain struct with no behaviour, so the producer stays
// free of taxonomy knowledge and the mapper stays free of CLI knowledge.
type LifecycleEvent struct {
	Ts        string      // RFC3339 UTC. Filled by the caller if empty.
	Op        LifecycleOp // install | verify
	Skill     string
	Version   string
	Digest    string     // sha256:<hex> when known.
	Reason    ReasonCode // ReasonOK on success.
	ExitCode  int        // the SPEC-0188 §11 numbered code, verbatim.
	SessionID string
	Message   string // short human-readable note. Never a full error string with a path (REQ-5.4).
}

// FromLifecycleEvent maps one install/verify outcome onto the shared envelope.
//
// A success becomes skill.install / skill.verify with outcome success. A refusal
// becomes the family its reason belongs to (signature.reject, provenance.reject,
// policy.deny, revocation.detect) so a reader filtering on "why do installs get
// refused here" gets an answer without knowing skillctl's exit codes. In BOTH
// cases the exit code and the reason travel with the event.
//
// An unknown reason is an error rather than a silent "other": a reason nobody
// classified is a gap in this table, and returning it lets the caller drop the
// event instead of writing a misleading one. The caller is fire-and-forget, so a
// gap costs a missing line, never a changed decision.
func FromLifecycleEvent(l LifecycleEvent, producer string) (*Event, error) {
	if l.Op != OpInstall && l.Op != OpVerify {
		return nil, fmt.Errorf("%w: unknown lifecycle op %q", ErrInvalidEvent, l.Op)
	}
	ts := l.Ts
	if ts == "" {
		ts = time.Now().UTC().Format(time.RFC3339)
	}

	e := &Event{
		Schema:    SchemaV1,
		Timestamp: ts,
		EventID:   NewEventID(),
		Producer:  producer,
		SessionID: l.SessionID,
		Actor:     &ActorRef{Type: "workload", ID: "skillctl/" + string(l.Op)},
	}
	if l.Skill != "" || l.Version != "" || l.Digest != "" {
		e.Skill = &SkillRef{Name: l.Skill, Version: l.Version, Digest: l.Digest}
	}
	if l.Message != "" {
		e.Message = l.Message
	}

	switch l.Reason {
	case ReasonOK:
		e.EventType = successTypeFor(l.Op)
		e.Outcome = OutcomeSuccess
		e.Severity = SeverityInfo

	case ReasonInternalError:
		// Not a refusal. The operation did not reach a verdict, and saying
		// otherwise would let an outage read as a wall of denials.
		e.EventType = successTypeFor(l.Op)
		e.Outcome = OutcomeError
		e.Severity = SeverityError
		e.Error = &ErrorRef{Code: string(ReasonInternalError), Category: "internal"}

	default:
		cls, ok := reasonClasses[l.Reason]
		if !ok {
			return nil, fmt.Errorf("%w: unclassified lifecycle reason %q", ErrInvalidEvent, l.Reason)
		}
		e.EventType = cls.refusalType
		e.Outcome = cls.outcome
		e.Severity = cls.severity
		e.Error = &ErrorRef{Code: string(l.Reason), Category: cls.category}
		// Preserve the source vocabulary alongside the classification, the same
		// way FromGateEvent keeps policy.decision: a policy refusal also carries
		// the deny verdict in the field a SPEC-0247 reader already looks at.
		if cls.outcome == OutcomeDeny {
			e.Policy = &PolicyRef{Decision: "deny"}
		}
	}

	// The numbered exit code is the operator's primary handle (it is what a
	// script branched on) and it is NOT derivable from the taxonomy, so it
	// travels verbatim. Prefixed to avoid colliding with a canonical field.
	_ = e.SetExt("lifecycle.exit_code", l.ExitCode) //nolint:errcheck // marshaling an int cannot fail.
	_ = e.SetExt("lifecycle.op", string(l.Op))      //nolint:errcheck // marshaling a string cannot fail.

	if err := e.Validate(); err != nil {
		return nil, err
	}
	return e, nil
}

// successTypeFor is the taxonomy family a lifecycle op belongs to when it is not
// reporting a refusal.
func successTypeFor(op LifecycleOp) EventType {
	if op == OpInstall {
		return EventSkillInstall
	}
	return EventSkillVerify
}
