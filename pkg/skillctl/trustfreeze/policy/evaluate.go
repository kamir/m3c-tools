package policy

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/compare"
)

// SchemaVerdict is the schema id of a verdict document.
const SchemaVerdict = "trust-freeze/verdict/v1"

// VerdictFile is the path of the verdict document inside a diff bundle.
const VerdictFile = "verdict.json"

// ErrInvalidVerdict is wrapped when a verdict document breaks its contract.
var ErrInvalidVerdict = errors.New("policy: invalid verdict document")

// Verdict is the outcome of Evaluate. It carries no timestamp, so the same diff
// and policy give byte-identical verdicts (SPEC-0469 R9).
type Verdict struct {
	SchemaVersion string    `json:"schema_version"`
	Policy        PolicyRef `json:"policy"`
	// DiffDigest binds the verdict to the diff it judged (compare.DiffDigest).
	DiffDigest string `json:"diff_digest"`
	// HighestSeverity is the highest finding severity; omitted when there
	// are no findings.
	HighestSeverity trustfreeze.Severity `json:"highest_severity,omitempty"`
	// FailOn is the threshold that was applied, and ThresholdExceeded whether
	// HighestSeverity is at or above it. They are the only fields a different
	// threshold changes (SPEC-0469 R8).
	FailOn            Threshold `json:"fail_on"`
	ThresholdExceeded bool      `json:"threshold_exceeded"`
	// Counts holds the number of findings per severity; every severity is
	// present, zero included.
	Counts map[string]int `json:"counts"`
	// Findings has one entry per diff change, in diff order.
	Findings []trustfreeze.Finding `json:"findings"`
}

// Evaluate judges d with p. It validates both, gives every change exactly one
// finding (the highest severity of all matching rules, ties to the earlier
// rule; the default severity when none matches) and applies p.FailOn. It
// neither reads nor changes anything outside its arguments.
func Evaluate(ctx context.Context, d compare.Diff, p Policy) (Verdict, error) {
	if err := ctx.Err(); err != nil {
		return Verdict{}, err
	}
	if err := p.Validate(); err != nil {
		return Verdict{}, err
	}
	if err := d.Validate(); err != nil {
		return Verdict{}, err
	}
	rulesDigest, err := p.RulesDigest()
	if err != nil {
		return Verdict{}, err
	}
	diffDigest, err := compare.DiffDigest(d)
	if err != nil {
		return Verdict{}, err
	}
	v := Verdict{
		SchemaVersion: SchemaVerdict,
		Policy:        PolicyRef{ID: p.ID, RulesDigest: rulesDigest},
		DiffDigest:    diffDigest,
		FailOn:        p.FailOn,
		Findings:      make([]trustfreeze.Finding, 0, len(d.Changes)),
	}
	for _, c := range d.Changes {
		sev, ruleID := p.DefaultSeverity, DefaultSeverityRuleID
		best := 0
		for _, r := range p.Rules {
			if r.matches(c) && r.Severity.Rank() > best {
				best, sev, ruleID = r.Severity.Rank(), r.Severity, r.ID
			}
		}
		v.Findings = append(v.Findings, trustfreeze.Finding{
			ID:         findingID(c),
			Kind:       string(c.Kind),
			Severity:   sev,
			ArtifactID: c.ArtifactID,
			ProbeID:    c.ProbeID,
			RuleID:     ruleID,
			Message:    message(c),
		})
		if sev.Rank() > v.HighestSeverity.Rank() {
			v.HighestSeverity = sev
		}
	}
	v.Counts = countSeverities(v.Findings)
	v.ThresholdExceeded = p.FailOn.Exceeded(v.HighestSeverity)
	return v, nil
}

// ParseVerdict decodes a verdict document in canonical file form and checks
// that it is internally consistent (highest severity, counts, threshold).
func ParseVerdict(b []byte) (Verdict, error) {
	var v Verdict
	if err := trustfreeze.UnmarshalCanonicalFile(b, &v); err != nil {
		return Verdict{}, fmt.Errorf("%w: %w", ErrInvalidVerdict, err)
	}
	if err := v.Validate(); err != nil {
		return Verdict{}, err
	}
	return v, nil
}

// Validate checks the verdict's own arithmetic. It does not re-evaluate: that
// needs the diff and the policy.
func (v Verdict) Validate() error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalidVerdict, fmt.Sprintf(format, a...))
	}
	if err := trustfreeze.CheckSchema(v.SchemaVersion, SchemaVerdict); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidVerdict, err)
	}
	if v.Policy.ID == "" || v.Policy.RulesDigest == "" || v.DiffDigest == "" {
		return bad("policy reference or diff digest missing")
	}
	if !v.FailOn.Valid() {
		return bad("fail_on %q is not a threshold", v.FailOn)
	}
	if v.Findings == nil {
		return bad("findings list missing")
	}
	var highest trustfreeze.Severity
	ids := map[string]bool{}
	for i, f := range v.Findings {
		if !f.Severity.Valid() {
			return bad("finding %d has severity %q", i, f.Severity)
		}
		if f.ID == "" || ids[f.ID] {
			return bad("finding %d has an empty or duplicate id %q", i, f.ID)
		}
		ids[f.ID] = true
		if f.Severity.Rank() > highest.Rank() {
			highest = f.Severity
		}
	}
	if highest != v.HighestSeverity {
		return bad("highest_severity %q, findings say %q", v.HighestSeverity, highest)
	}
	if !maps.Equal(v.Counts, countSeverities(v.Findings)) {
		return bad("counts do not match the findings")
	}
	if v.ThresholdExceeded != v.FailOn.Exceeded(highest) {
		return bad("threshold_exceeded does not follow from fail_on and highest_severity")
	}
	return nil
}

func countSeverities(fs []trustfreeze.Finding) map[string]int {
	out := map[string]int{}
	for _, s := range trustfreeze.Severities() {
		out[string(s)] = 0
	}
	for _, f := range fs {
		out[string(f.Severity)]++
	}
	return out
}

// findingID is stable across runs: the change kind and the artifact id, the
// probe id (collection_gap, applicability_changed) or the current subject id
// (subject_changed), for example "changed:device/os" or
// "collection_gap:common.identity".
func findingID(c compare.Change) string {
	key := c.ArtifactID
	switch {
	case c.Kind == compare.ChangeCollectionGap, c.Kind == compare.ChangeApplicabilityChanged:
		key = c.ProbeID
	case c.Kind == compare.ChangeSubjectChanged:
		key = c.AfterSubjectID
	case c.Kind.IsCapability():
		key = c.CapabilityID
	}
	return string(c.Kind) + ":" + key
}

// privilegeSuffix names the privilege of a capability, or nothing when the
// capability carries none.
func privilegeSuffix(p string) string {
	if p == "" {
		return ""
	}
	return " (privilege " + p + ")"
}

// message is a deterministic English sentence. It names ids, attribute keys,
// fields, states and statuses, never attribute values.
func message(c compare.Change) string {
	switch c.Kind {
	case compare.ChangeSubjectChanged:
		msg := fmt.Sprintf("the baseline describes device %s, the current bundle device %s", c.BeforeSubjectID, c.AfterSubjectID)
		if c.SubjectMismatchAllowed {
			msg += " (the mismatch was allowed explicitly)"
		}
		return msg
	case compare.ChangeNotObserved:
		if c.AfterDigest != "" {
			return fmt.Sprintf("attributes %s of artifact %s (%s) were not observed: source probe %s was not captured",
				strings.Join(c.UnobservedAttributes, ", "), c.ArtifactID, c.ArtifactType, c.ProbeID)
		}
		return fmt.Sprintf("artifact %s (%s) was not observed: source probe %s was not captured", c.ArtifactID, c.ArtifactType, c.ProbeID)
	case compare.ChangeApplicabilityChanged:
		return fmt.Sprintf("probe %s moved from %s to %s", c.ProbeID, c.BeforeStatus, c.AfterStatus)
	case compare.ChangeAdded:
		return fmt.Sprintf("artifact %s (%s) was added", c.ArtifactID, c.ArtifactType)
	case compare.ChangeRemoved:
		return fmt.Sprintf("artifact %s (%s) was removed", c.ArtifactID, c.ArtifactType)
	case compare.ChangeChanged:
		var parts []string
		if len(c.ChangedAttributes) > 0 {
			parts = append(parts, "attributes "+strings.Join(c.ChangedAttributes, ", "))
		}
		if len(c.ChangedFields) > 0 {
			parts = append(parts, "fields "+strings.Join(c.ChangedFields, ", "))
		}
		return fmt.Sprintf("artifact %s (%s) changed: %s", c.ArtifactID, c.ArtifactType, strings.Join(parts, "; "))
	case compare.ChangeConfidenceChanged:
		return fmt.Sprintf("artifact %s confidence changed from %s to %s", c.ArtifactID, c.BeforeConfidence, c.AfterConfidence)
	case compare.ChangeBecameEffective:
		return fmt.Sprintf("artifact %s became effective (state %s to %s)", c.ArtifactID, c.BeforeState, c.AfterState)
	case compare.ChangeBecameIneffective:
		return fmt.Sprintf("artifact %s became ineffective (state %s to %s)", c.ArtifactID, c.BeforeState, c.AfterState)
	case compare.ChangeCapabilityAdded:
		return fmt.Sprintf("capability %s was added%s", c.CapabilityID, privilegeSuffix(c.AfterPrivilege))
	case compare.ChangeCapabilityRemoved:
		return fmt.Sprintf("capability %s was removed%s", c.CapabilityID, privilegeSuffix(c.BeforePrivilege))
	case compare.ChangeCapabilityNotObserved:
		return fmt.Sprintf("capability %s%s was not observed: an artifact it rests on was not captured", c.CapabilityID, privilegeSuffix(c.BeforePrivilege))
	case compare.ChangeCapabilityChanged:
		return fmt.Sprintf("capability %s changed: fields %s", c.CapabilityID, strings.Join(c.ChangedFields, ", "))
	case compare.ChangeCoverageIncreased:
		return fmt.Sprintf("capability %s%s is in the current bundle and could not have been in the baseline: probe %s was not captured there",
			c.CapabilityID, privilegeSuffix(c.AfterPrivilege), strings.Join(c.BaselineGapProbes, ", "))
	case compare.ChangeCollectionGap:
		kind := "optional"
		if c.Gap.Required {
			kind = "required"
		}
		verb := "was not collected"
		if c.Gap.Cause == trustfreeze.GapNotApplicable {
			verb = "is not applicable"
		}
		msg := fmt.Sprintf("%s probe %s %s (%s", kind, c.ProbeID, verb, c.Gap.Cause)
		if c.Gap.Status != "" {
			msg += ", status " + string(c.Gap.Status)
		}
		if c.Gap.Reason != "" {
			msg += ", reason " + c.Gap.Reason
		}
		return msg + ")"
	}
	return string(c.Kind)
}
