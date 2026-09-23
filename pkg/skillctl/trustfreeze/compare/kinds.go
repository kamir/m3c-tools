package compare

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
)

// ChangeKind is the kind of one diff entry (SPEC-0469 R3). It is a closed
// enum. The declaration order below is the primary sort key of Diff.Changes.
type ChangeKind string

// Change kinds.
const (
	// ChangeSubjectChanged: the baseline and the current bundle describe
	// different devices (subject ids differ). It is reported even when the
	// comparison was asked for on purpose (CompareOptions.AllowSubjectMismatch).
	ChangeSubjectChanged ChangeKind = "subject_changed"
	// ChangeAdded: the artifact exists only in the current bundle.
	ChangeAdded ChangeKind = "added"
	// ChangeRemoved: the artifact exists only in the baseline, and its source
	// probe was captured (or is not applicable with a reason) in the current
	// bundle, so its absence was observed.
	ChangeRemoved ChangeKind = "removed"
	// ChangeChanged: compared fields, or attributes observed on both sides,
	// differ.
	ChangeChanged ChangeKind = "changed"
	// ChangeNotObserved: the source probe of a baseline artifact was not
	// captured in the current bundle, so the artifact, or some of its
	// attributes, could not be observed. Never reported as removed or changed.
	ChangeNotObserved ChangeKind = "not_observed"
	// ChangeConfidenceChanged: the provenance confidence differs.
	ChangeConfidenceChanged ChangeKind = "confidence_changed"
	// ChangeBecameEffective: the state moved to observed.
	ChangeBecameEffective ChangeKind = "became_effective"
	// ChangeBecameIneffective: the state moved away from observed.
	ChangeBecameIneffective ChangeKind = "became_ineffective"
	// ChangeCapabilityAdded: the capability exists only in the current
	// bundle. Capabilities are compared separately from artifacts
	// (SPEC-0469 R2) and only when the baseline carries a capabilities
	// document.
	ChangeCapabilityAdded ChangeKind = "capability_added"
	// ChangeCapabilityRemoved: the capability exists only in the baseline,
	// and every artifact it rests on was observed in the current bundle, so
	// its absence was observed too.
	ChangeCapabilityRemoved ChangeKind = "capability_removed"
	// ChangeCapabilityChanged: a field of the capability differs.
	ChangeCapabilityChanged ChangeKind = "capability_changed"
	// ChangeCapabilityNotObserved: a baseline capability could not be
	// observed in the current bundle, because an artifact it rests on is
	// missing there or no resolver ran. Never reported as removed.
	ChangeCapabilityNotObserved ChangeKind = "capability_not_observed"
	// ChangeCoverageIncreased: the capability exists only in the current
	// bundle, and the probe that produced a source it rests on was not
	// captured in the baseline. The baseline was blind there, so the
	// capability is not new; what is new is that somebody looked. The mirror
	// of ChangeCapabilityNotObserved (SPEC-0469 R2).
	ChangeCoverageIncreased ChangeKind = "coverage_increased"
	// ChangeApplicabilityChanged: a probe moved between captured and
	// not_applicable (with a reason), in either direction: a real change of
	// the host, not a collection problem.
	ChangeApplicabilityChanged ChangeKind = "applicability_changed"
	// ChangeCollectionGap: a probe of the current bundle was not captured.
	// A gap is never read as "no drift" (SPEC-0469 R7).
	ChangeCollectionGap ChangeKind = "collection_gap"
)

var changeKindValues = []ChangeKind{
	ChangeSubjectChanged, ChangeAdded, ChangeRemoved, ChangeChanged, ChangeNotObserved,
	ChangeConfidenceChanged, ChangeBecameEffective, ChangeBecameIneffective,
	ChangeCapabilityAdded, ChangeCapabilityRemoved, ChangeCapabilityChanged, ChangeCapabilityNotObserved,
	ChangeCoverageIncreased, ChangeApplicabilityChanged, ChangeCollectionGap,
}

// capabilityKinds are the change kinds that carry a capability id instead of
// an artifact id.
var capabilityKinds = []ChangeKind{
	ChangeCapabilityAdded, ChangeCapabilityRemoved, ChangeCapabilityChanged, ChangeCapabilityNotObserved,
	ChangeCoverageIncreased,
}

// IsCapability reports whether k describes a capability instead of an
// artifact or a probe.
func (k ChangeKind) IsCapability() bool { return slices.Contains(capabilityKinds, k) }

// ChangeKinds returns every change kind in sort order.
func ChangeKinds() []ChangeKind { return slices.Clone(changeKindValues) }

// rank is the 1-based sort position of k, 0 for an unknown kind.
func (k ChangeKind) rank() int {
	return slices.Index(changeKindValues, k) + 1
}

// Valid reports whether k is a known change kind.
func (k ChangeKind) Valid() bool { return k.rank() > 0 }

// ParseChangeKind parses a change kind strictly (case-sensitive, no trimming).
func ParseChangeKind(s string) (ChangeKind, error) {
	k := ChangeKind(s)
	if !k.Valid() {
		return "", fmt.Errorf("%w: change kind %q", trustfreeze.ErrInvalidEnum, s)
	}
	return k, nil
}

// MarshalText refuses an empty or unknown kind, so an invalid value is never
// written.
func (k ChangeKind) MarshalText() ([]byte, error) {
	if !k.Valid() {
		return nil, fmt.Errorf("%w: refusing to write change kind %q", trustfreeze.ErrInvalidEnum, string(k))
	}
	return []byte(k), nil
}

// UnmarshalText parses a change kind strictly.
func (k *ChangeKind) UnmarshalText(b []byte) error {
	v, err := ParseChangeKind(string(b))
	if err != nil {
		return err
	}
	*k = v
	return nil
}

// UnmarshalJSON accepts only a JSON string holding a known kind; null is
// refused.
func (k *ChangeKind) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || b[0] != '"' {
		return fmt.Errorf("%w: change kind must be a JSON string", trustfreeze.ErrInvalidEnum)
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("%w: change kind: %w", trustfreeze.ErrInvalidEnum, err)
	}
	return k.UnmarshalText([]byte(s))
}
