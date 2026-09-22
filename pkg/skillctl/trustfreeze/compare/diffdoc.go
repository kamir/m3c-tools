package compare

import (
	"fmt"
	"maps"
	"slices"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
)

// ParseDiff decodes a diff document in canonical file form (the form a diff
// bundle stores) and validates it.
func ParseDiff(b []byte) (Diff, error) {
	var d Diff
	if err := trustfreeze.UnmarshalCanonicalFile(b, &d); err != nil {
		return Diff{}, fmt.Errorf("%w: %w", ErrInvalidDiff, err)
	}
	if err := d.Validate(); err != nil {
		return Diff{}, err
	}
	return d, nil
}

// DiffDigest returns "sha256:<hex>" over the canonical JSON of d. A verdict
// records it to bind itself to the diff it judged.
func DiffDigest(d Diff) (string, error) {
	b, err := trustfreeze.MarshalCanonical(d)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidDiff, err)
	}
	return trustfreeze.Digest(b), nil
}

// Validate checks d against the diff/v1 contract: schema id, kind, a known
// normalization rule set with a matching digest, input kinds, well-formed
// entries in strict sort order without duplicates, exactly one
// subject_changed entry when (and only when) the input subjects differ, and
// counts that match the entries.
func (d Diff) Validate() error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalidDiff, fmt.Sprintf(format, a...))
	}
	if err := trustfreeze.CheckSchema(d.SchemaVersion, trustfreeze.SchemaDiff); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidDiff, err)
	}
	if d.Kind != trustfreeze.KindDiff {
		return bad("kind %q, want %q", d.Kind, trustfreeze.KindDiff)
	}
	rs, err := LoadRuleSet(d.Normalization.ID)
	if err != nil || d.Normalization.ID == "" {
		return bad("normalization rule set %q is not known", d.Normalization.ID)
	}
	if want, err := rs.Digest(); err != nil || want != d.Normalization.Digest {
		return bad("normalization digest %q does not match rule set %s", d.Normalization.Digest, rs.ID)
	}
	if d.Baseline.Kind != trustfreeze.KindBaseline {
		return bad("baseline input is kind %q", d.Baseline.Kind)
	}
	if d.Current.Kind != trustfreeze.KindCapture && d.Current.Kind != trustfreeze.KindBaseline {
		return bad("current input is kind %q", d.Current.Kind)
	}
	if d.Baseline.ContentDigest == "" || d.Current.ContentDigest == "" {
		return bad("an input content digest is empty")
	}
	if d.Changes == nil {
		return bad("changes list missing")
	}
	subjectChanges := 0
	for i, c := range d.Changes {
		if err := validateChange(c); err != nil {
			return bad("change %d: %v", i, err)
		}
		if i > 0 && compareChanges(d.Changes[i-1], c) >= 0 {
			return bad("change %d is out of order or duplicate", i)
		}
		if c.Kind == ChangeSubjectChanged {
			subjectChanges++
			if c.BeforeSubjectID != d.Baseline.Subject.ID || c.AfterSubjectID != d.Current.Subject.ID {
				return bad("subject_changed names %s and %s, the inputs are %s and %s", c.BeforeSubjectID, c.AfterSubjectID, d.Baseline.Subject.ID, d.Current.Subject.ID)
			}
			if c.SubjectMismatchAllowed != d.AllowSubjectMismatch {
				return bad("subject_changed and the diff disagree about allow_subject_mismatch")
			}
		}
	}
	if differ := d.Baseline.Subject.ID != d.Current.Subject.ID; differ != (subjectChanges == 1) {
		return bad("the input subjects differ: %v, subject_changed entries: %d", differ, subjectChanges)
	}
	if !maps.Equal(d.Counts, countChanges(d.Changes)) {
		return bad("counts do not match the changes")
	}
	return nil
}

func validateChange(c Change) error {
	if !c.Kind.Valid() {
		return fmt.Errorf("unknown kind %q", c.Kind)
	}
	// Fields that belong to one kind only.
	switch {
	case c.Kind != ChangeSubjectChanged && (c.BeforeSubjectID != "" || c.AfterSubjectID != "" || c.SubjectMismatchAllowed):
		return fmt.Errorf("%s entry must not carry subject fields", c.Kind)
	case c.Kind != ChangeApplicabilityChanged && (c.BeforeStatus != "" || c.AfterStatus != ""):
		return fmt.Errorf("%s entry must not carry probe statuses", c.Kind)
	case c.Kind != ChangeNotObserved && len(c.UnobservedAttributes) > 0:
		return fmt.Errorf("%s entry must not carry unobserved attributes", c.Kind)
	case c.Kind != ChangeCollectionGap && c.Gap != nil:
		return fmt.Errorf("%s entry must not carry a gap", c.Kind)
	}
	switch c.Kind {
	case ChangeSubjectChanged:
		if c.ArtifactID != "" || c.ProbeID != "" {
			return fmt.Errorf("subject_changed must not carry an artifact or probe id")
		}
		if c.BeforeSubjectID == "" || c.AfterSubjectID == "" || c.BeforeSubjectID == c.AfterSubjectID {
			return fmt.Errorf("subject_changed needs two different subject ids")
		}
		return nil
	case ChangeCollectionGap:
		if c.ArtifactID != "" || c.Gap == nil {
			return fmt.Errorf("collection_gap needs a probe id and a gap and no artifact id")
		}
		if err := trustfreeze.ValidateProbeID(c.ProbeID); err != nil {
			return err
		}
		if !slices.Contains(trustfreeze.GapReasons(), c.Gap.Cause) {
			return fmt.Errorf("collection_gap %s has cause %q", c.ProbeID, c.Gap.Cause)
		}
		return nil
	case ChangeApplicabilityChanged:
		if c.ArtifactID != "" {
			return fmt.Errorf("applicability_changed must not carry an artifact id")
		}
		if err := trustfreeze.ValidateProbeID(c.ProbeID); err != nil {
			return err
		}
		na, cp := trustfreeze.StatusNotApplicable, trustfreeze.StatusCaptured
		if !(c.BeforeStatus == cp && c.AfterStatus == na) && !(c.BeforeStatus == na && c.AfterStatus == cp) {
			return fmt.Errorf("applicability_changed %s is not a move between captured and not_applicable", c.ProbeID)
		}
		return nil
	}
	if c.Kind != ChangeNotObserved && c.ProbeID != "" {
		return fmt.Errorf("%s entry must not carry a probe id", c.Kind)
	}
	if err := trustfreeze.ValidateArtifactID(c.ArtifactID); err != nil {
		return err
	}
	switch c.Kind {
	case ChangeNotObserved:
		if err := trustfreeze.ValidateProbeID(c.ProbeID); err != nil {
			return err
		}
		if c.BeforeDigest == "" {
			return fmt.Errorf("not_observed %s has no before digest", c.ArtifactID)
		}
		if !slices.IsSorted(c.UnobservedAttributes) {
			return fmt.Errorf("not_observed %s attributes are not sorted", c.ArtifactID)
		}
		if c.AfterDigest != "" && len(c.UnobservedAttributes) == 0 {
			return fmt.Errorf("not_observed %s is in the current bundle but names no unobserved attribute", c.ArtifactID)
		}
	case ChangeAdded:
		if c.AfterDigest == "" {
			return fmt.Errorf("added %s has no after digest", c.ArtifactID)
		}
	case ChangeRemoved:
		if c.BeforeDigest == "" {
			return fmt.Errorf("removed %s has no before digest", c.ArtifactID)
		}
	case ChangeChanged:
		if len(c.ChangedFields) == 0 && len(c.ChangedAttributes) == 0 {
			return fmt.Errorf("changed %s names nothing that changed", c.ArtifactID)
		}
		if c.BeforeDigest == "" || c.AfterDigest == "" {
			return fmt.Errorf("changed %s lacks a digest", c.ArtifactID)
		}
		if !slices.IsSorted(c.ChangedFields) || !slices.IsSorted(c.ChangedAttributes) {
			return fmt.Errorf("changed %s lists are not sorted", c.ArtifactID)
		}
	case ChangeConfidenceChanged:
		if c.BeforeConfidence == c.AfterConfidence {
			return fmt.Errorf("confidence_changed %s has equal confidences", c.ArtifactID)
		}
	case ChangeBecameEffective:
		if c.AfterState != trustfreeze.StateObserved || c.BeforeState == trustfreeze.StateObserved {
			return fmt.Errorf("became_effective %s is not a transition to observed", c.ArtifactID)
		}
	case ChangeBecameIneffective:
		if c.BeforeState != trustfreeze.StateObserved || c.AfterState == trustfreeze.StateObserved {
			return fmt.Errorf("became_ineffective %s is not a transition from observed", c.ArtifactID)
		}
	}
	return nil
}
