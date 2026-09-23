package compare

import (
	"fmt"
	"slices"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
)

// Capability entries are the second half of the diff (SPEC-0469 R2): they say
// who may do what, where the artifact entries say what the host looks like. A
// capability is resolved from artifacts by a platform resolver and stored in
// state/capabilities.json (SPEC-0466 section 5.7).
//
// What a capability entry may claim depends on what both bundles carry:
//
//   - The baseline has no capabilities document: no capability entry is
//     emitted at all. Nobody resolved capabilities when the baseline was
//     taken, so nothing in the current bundle can be called new.
//   - The baseline has one and the current bundle has none: every baseline
//     capability is capability_not_observed. The absence of the document is
//     not an observation that the capability is gone.
//   - Both have one: a capability the current bundle resolved and the
//     baseline did not is coverage_increased when EVERY probe behind its
//     sources was blind in the baseline (the baseline covered none of the
//     ground this capability stands on, so the capability is not new:
//     somebody looked where nobody had looked before), and capability_added
//     otherwise; a baseline capability the current bundle did not resolve is
//     capability_removed when every artifact it rests on was observed there,
//     and capability_not_observed otherwise (the privilege probe was blocked,
//     so nobody could see it); a capability both sides resolved with
//     differing fields is capability_changed.
//
// The added and the removed direction are guarded alike: neither side is
// called new or gone over a probe the other side never ran (R-T1).
//
// Blind is narrower than "not captured". A baseline probe that reported
// partially did look and did report, and so did a baseline that covered one
// of several sources; a capability that is new on ground the baseline covered
// stays capability_added at its normal severity. Such an entry carries
// coverage_caveat_probes instead, naming the partial and the blind probes
// behind its sources, so a reader sees the uncertainty without the finding
// dropping to info.
//
// Capability values are not attributes, so nothing here is normalized: the
// resolver derives them from artifacts the rule set already normalized.

// capabilityFieldValues are the fields a capability_changed entry can name,
// spelled like the JSON keys of trustfreeze.Capability and in this order.
var capabilityFieldValues = []string{
	"subject_id", "action", "resource", "effect", "state", "scope",
	"exposure", "privilege", "attributes", "sources", "confidence",
}

// CapabilityFields returns the capability fields a capability_changed entry
// can name, in sort order.
func CapabilityFields() []string { return slices.Clone(capabilityFieldValues) }

// capabilityChanges compares the capability documents of the two bundles.
// afterArtifacts is the artifact index of the current bundle: it decides
// whether the absence of a baseline capability was observed. beforeProbes is
// the probe index of the baseline: it decides whether a capability only the
// current bundle carries could have been seen there at all.
func capabilityChanges(baseline, current *trustfreeze.Bundle, afterArtifacts map[string]trustfreeze.Artifact, beforeProbes probeIndex) ([]Change, error) {
	if baseline.Capabilities == nil {
		return nil, nil
	}
	before, err := indexCapabilities("baseline", baseline.Capabilities)
	if err != nil {
		return nil, err
	}
	after := map[string]trustfreeze.Capability{}
	resolved := current.Capabilities != nil
	if resolved {
		if after, err = indexCapabilities("current", current.Capabilities); err != nil {
			return nil, err
		}
	}

	ids := make([]string, 0, len(before)+len(after))
	for id := range before {
		ids = append(ids, id)
	}
	for id := range after {
		if _, ok := before[id]; !ok {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)

	var out []Change
	for _, id := range ids {
		b, inBefore := before[id]
		a, inAfter := after[id]
		switch {
		case !inBefore:
			d, err := capabilityDigest(a)
			if err != nil {
				return nil, err
			}
			cov := capabilityBaselineCoverage(a, afterArtifacts, beforeProbes)
			ch := Change{
				Kind: ChangeCapabilityAdded, CapabilityID: id,
				CoverageCaveatProbes: cov.caveat(),
				AfterPrivilege:       a.Privilege, AfterDigest: d,
				AfterState: a.State, AfterConfidence: a.Confidence,
			}
			if cov.allBlind() {
				ch.Kind, ch.BaselineGapProbes, ch.CoverageCaveatProbes = ChangeCoverageIncreased, cov.blind, nil
			}
			out = append(out, ch)
		case !inAfter:
			d, err := capabilityDigest(b)
			if err != nil {
				return nil, err
			}
			kind := ChangeCapabilityNotObserved
			if resolved && capabilitySourcesObserved(b, afterArtifacts) {
				kind = ChangeCapabilityRemoved
			}
			out = append(out, Change{
				Kind: kind, CapabilityID: id,
				BeforePrivilege: b.Privilege, BeforeDigest: d,
				BeforeState: b.State, BeforeConfidence: b.Confidence,
			})
		default:
			c, err := compareCapability(b, a)
			if err != nil {
				return nil, err
			}
			if c != nil {
				out = append(out, *c)
			}
		}
	}
	return out, nil
}

// compareCapability returns the capability_changed entry of two capabilities
// with the same id, or nil when they are equal.
func compareCapability(b, a trustfreeze.Capability) (*Change, error) {
	var fields []string
	for _, f := range capabilityFieldValues {
		if capabilityField(b, f) != capabilityField(a, f) {
			fields = append(fields, f)
		}
	}
	if len(fields) == 0 {
		return nil, nil
	}
	slices.Sort(fields)
	bd, err := capabilityDigest(b)
	if err != nil {
		return nil, err
	}
	ad, err := capabilityDigest(a)
	if err != nil {
		return nil, err
	}
	return &Change{
		Kind: ChangeCapabilityChanged, CapabilityID: b.ID, ChangedFields: fields,
		BeforePrivilege: b.Privilege, AfterPrivilege: a.Privilege,
		BeforeDigest: bd, AfterDigest: ad,
		BeforeState: b.State, AfterState: a.State,
		BeforeConfidence: b.Confidence, AfterConfidence: a.Confidence,
	}, nil
}

// capabilityField returns one field of c as a comparable string. Sources are
// joined with a NUL, which no id contains, so two different lists never
// compare equal.
func capabilityField(c trustfreeze.Capability, name string) string {
	switch name {
	case "subject_id":
		return c.SubjectID
	case "action":
		return c.Action
	case "resource":
		return c.Resource
	case "effect":
		return c.Effect
	case "state":
		return string(c.State)
	case "scope":
		return c.Scope
	case "exposure":
		return c.Exposure
	case "privilege":
		return c.Privilege
	case "attributes":
		keys := make([]string, 0, len(c.Attributes))
		for k := range c.Attributes {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		out := ""
		for _, k := range keys {
			out += k + "\x00" + c.Attributes[k] + "\x00"
		}
		return out
	case "sources":
		out := ""
		for _, s := range c.Sources {
			out += s + "\x00"
		}
		return out
	case "confidence":
		return string(c.Confidence)
	}
	return ""
}

// baselineCoverage is what the baseline knew about the probes behind the
// sources of one capability: blind holds the probes that produced no usable
// observation there, partial the probes that reported partially, and tied the
// number of source probes that could be tied to a probe at all.
type baselineCoverage struct {
	blind   []string
	partial []string
	tied    int
}

// allBlind reports whether the baseline covered none of the ground the
// capability stands on: every source probe that could be tied to a probe was
// blind, and there was at least one. Only then is the capability not called
// new (R-T1 (b)): one covered source is enough to make the current bundle's
// finding a statement about the host.
func (c baselineCoverage) allBlind() bool { return c.tied > 0 && len(c.blind) == c.tied }

// caveat is the sorted list of probes a capability_added entry names as thin
// baseline coverage: every blind probe plus every partial one.
func (c baselineCoverage) caveat() []string {
	if len(c.blind) == 0 && len(c.partial) == 0 {
		return nil
	}
	out := append(slices.Clone(c.blind), c.partial...)
	slices.Sort(out)
	return slices.Compact(out)
}

// capabilityBaselineCoverage measures what the baseline saw of the probes
// behind the sources of c. A source is tied to a probe through the artifact it
// names in the current bundle, which is where that artifact exists; a source
// that names no artifact of this bundle (a file, a tool, or an artifact this
// capture did not persist) ties to no probe and is counted nowhere, so the
// guard never invents a gap it did not measure.
func capabilityBaselineCoverage(c trustfreeze.Capability, artifacts map[string]trustfreeze.Artifact, beforeProbes probeIndex) baselineCoverage {
	var out baselineCoverage
	seen := map[string]bool{}
	for _, s := range c.Sources {
		if trustfreeze.ValidateArtifactID(s) != nil {
			continue
		}
		a, ok := artifacts[s]
		if !ok || trustfreeze.ValidateProbeID(a.Source) != nil || seen[a.Source] {
			continue
		}
		seen[a.Source] = true
		out.tied++
		switch {
		case beforeProbes.blind(a.Source):
			out.blind = append(out.blind, a.Source)
		case beforeProbes.reportedPartially(a.Source):
			out.partial = append(out.partial, a.Source)
		}
	}
	slices.Sort(out.blind)
	slices.Sort(out.partial)
	return out
}

// capabilitySourcesObserved reports whether every source of c that names an
// artifact is present in the current bundle. A source that is not an artifact
// id (a file or a tool) cannot be checked here and does not block the answer.
func capabilitySourcesObserved(c trustfreeze.Capability, artifacts map[string]trustfreeze.Artifact) bool {
	for _, s := range c.Sources {
		if trustfreeze.ValidateArtifactID(s) != nil {
			continue
		}
		if _, ok := artifacts[s]; !ok {
			return false
		}
	}
	return true
}

// capabilityDigest is "sha256:<hex>" over the canonical JSON of c.
func capabilityDigest(c trustfreeze.Capability) (string, error) {
	b, err := trustfreeze.MarshalCanonical(c)
	if err != nil {
		return "", fmt.Errorf("%w: capability %q cannot be encoded: %w", ErrInvalidInput, c.ID, err)
	}
	return trustfreeze.Digest(b), nil
}

// validateCapabilityChange checks one capability entry of a diff document.
// Every entry names its capability and carries the digest of each side it
// saw, so no entry claims more than it observed.
func validateCapabilityChange(c Change) error {
	switch {
	case c.CapabilityID == "":
		return fmt.Errorf("%s has no capability id", c.Kind)
	case c.ArtifactID != "" || c.ArtifactType != "" || c.ProbeID != "":
		return fmt.Errorf("%s %s must not carry an artifact or probe id", c.Kind, c.CapabilityID)
	case len(c.ChangedAttributes) > 0:
		return fmt.Errorf("%s %s must not carry attribute names", c.Kind, c.CapabilityID)
	}
	switch c.Kind {
	case ChangeCapabilityAdded:
		if c.AfterDigest == "" || c.BeforeDigest != "" {
			return fmt.Errorf("capability_added %s needs an after digest and no before digest", c.CapabilityID)
		}
		if !slices.IsSorted(c.CoverageCaveatProbes) {
			return fmt.Errorf("capability_added %s coverage caveat probes are not sorted", c.CapabilityID)
		}
		for _, p := range c.CoverageCaveatProbes {
			if err := trustfreeze.ValidateProbeID(p); err != nil {
				return fmt.Errorf("capability_added %s: %w", c.CapabilityID, err)
			}
		}
	case ChangeCoverageIncreased:
		if c.AfterDigest == "" || c.BeforeDigest != "" {
			return fmt.Errorf("coverage_increased %s needs an after digest and no before digest", c.CapabilityID)
		}
		if len(c.BaselineGapProbes) == 0 {
			return fmt.Errorf("coverage_increased %s names no probe the baseline was blind to", c.CapabilityID)
		}
		if !slices.IsSorted(c.BaselineGapProbes) {
			return fmt.Errorf("coverage_increased %s probes are not sorted", c.CapabilityID)
		}
		for _, p := range c.BaselineGapProbes {
			if err := trustfreeze.ValidateProbeID(p); err != nil {
				return fmt.Errorf("coverage_increased %s: %w", c.CapabilityID, err)
			}
		}
	case ChangeCapabilityRemoved, ChangeCapabilityNotObserved:
		if c.BeforeDigest == "" || c.AfterDigest != "" {
			return fmt.Errorf("%s %s needs a before digest and no after digest", c.Kind, c.CapabilityID)
		}
	case ChangeCapabilityChanged:
		if c.BeforeDigest == "" || c.AfterDigest == "" {
			return fmt.Errorf("capability_changed %s lacks a digest", c.CapabilityID)
		}
		if len(c.ChangedFields) == 0 {
			return fmt.Errorf("capability_changed %s names no changed field", c.CapabilityID)
		}
		if !slices.IsSorted(c.ChangedFields) {
			return fmt.Errorf("capability_changed %s fields are not sorted", c.CapabilityID)
		}
		for _, f := range c.ChangedFields {
			if !slices.Contains(capabilityFieldValues, f) {
				return fmt.Errorf("capability_changed %s names unknown field %q", c.CapabilityID, f)
			}
		}
	}
	return nil
}

// indexCapabilities keys the capabilities of one bundle by id and refuses a
// document compare cannot read unambiguously.
func indexCapabilities(role string, doc *trustfreeze.CapabilitiesDoc) (map[string]trustfreeze.Capability, error) {
	out := map[string]trustfreeze.Capability{}
	for _, c := range doc.Capabilities {
		switch {
		case c.ID == "":
			return nil, fmt.Errorf("%w: %s: a capability has no id", ErrInvalidInput, role)
		case !c.State.Valid() || !c.Confidence.Valid():
			return nil, fmt.Errorf("%w: %s: capability %q has an unknown state or confidence", ErrInvalidInput, role, c.ID)
		}
		if _, dup := out[c.ID]; dup {
			return nil, fmt.Errorf("%w: %s: capability id %q appears more than once", ErrInvalidInput, role, c.ID)
		}
		out[c.ID] = c
	}
	return out, nil
}
