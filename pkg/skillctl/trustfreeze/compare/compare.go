// Package compare computes the structural diff between a Trust Freeze
// baseline and a current bundle (SPEC-0469, TF-04). It compares; it does not
// judge. Severities and the exit decision belong to the policy package.
//
// Compare works on bundles that are already verified. Checking the manifest
// integrity, the baseline signature and the trust policy is the duty of the
// caller: the skillctl CLI verifies both inputs and refuses to compare when
// either fails (SPEC-0469 R1). Compare only re-checks what the loaded values
// themselves say (integrity flag, kinds, capture document present).
//
// The result is deterministic: it does not depend on the order of the input
// artifacts, on map iteration order or on any clock, and volatile values are
// removed only through a versioned normalization rule set (SPEC-0469 R4, R9).
package compare

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
)

// DiffFile is the path of the diff document inside a diff bundle.
const DiffFile = "diff.json"

// Errors.
var (
	// ErrNotVerified: an input does not carry a passed integrity check.
	ErrNotVerified = errors.New("compare: input bundle is not verified")
	// ErrInputKind: an input has a bundle kind compare does not accept there.
	ErrInputKind = errors.New("compare: input bundle has the wrong kind")
	// ErrInvalidInput: an input holds values compare cannot compare
	// unambiguously (duplicate or invalid artifact id, unknown enum value).
	ErrInvalidInput = errors.New("compare: invalid input")
	// ErrInvalidDiff: a diff document breaks the diff/v1 contract.
	ErrInvalidDiff = errors.New("compare: invalid diff document")
)

// CompareOptions configures Compare.
type CompareOptions struct {
	// RuleSetID selects the normalization rule set; empty means
	// DefaultRuleSetID.
	RuleSetID string
	// AllowSubjectMismatch records that comparing two different devices is
	// intended (a golden image or fleet baseline). The subject_changed entry
	// is still emitted and carries the flag, so a policy can rate it; the
	// diff records the opt-in either way (SPEC-0469 section 4.2).
	AllowSubjectMismatch bool
}

// Diff is the diff document (schema trust-freeze/diff/v1, kind diff). It
// references both inputs by content digest and carries no timestamp of its
// own, so identical inputs give byte-identical diffs (SPEC-0469 R9).
type Diff struct {
	SchemaVersion string           `json:"schema_version"`
	Kind          trustfreeze.Kind `json:"kind"`
	Normalization RuleSetRef       `json:"normalization"`
	Baseline      InputRef         `json:"baseline"`
	Current       InputRef         `json:"current"`
	// AllowSubjectMismatch records the opt-in of CompareOptions, also when
	// both subjects are equal.
	AllowSubjectMismatch bool `json:"allow_subject_mismatch"`
	// Counts holds the number of changes per change kind; every kind is
	// present, zero included.
	Counts map[string]int `json:"counts"`
	// Changes are sorted by (change kind in ChangeKinds order, artifact id,
	// probe id).
	Changes []Change `json:"changes"`
}

// RuleSetRef identifies the normalization rule set a diff was computed with.
type RuleSetRef struct {
	ID     string `json:"id"`
	Digest string `json:"digest"`
}

// InputRef identifies one compared bundle.
type InputRef struct {
	Kind          trustfreeze.Kind       `json:"kind"`
	BundleID      string                 `json:"bundle_id"`
	ContentDigest string                 `json:"content_digest"`
	Subject       trustfreeze.Subject    `json:"subject"`
	Profile       trustfreeze.ProfileRef `json:"profile"`
}

// Change is one diff entry. Artifact entries carry ArtifactID (a
// not_observed entry also the ProbeID of the artifact's source probe); a
// capability entry carries CapabilityID and the privilege of each side; a
// collection_gap entry carries ProbeID and Gap, an applicability_changed
// entry ProbeID and the two probe statuses, a subject_changed entry the two
// subject ids. Attribute values never appear in a diff: a changed entry names
// the changed attribute keys and gives digests of the normalized attribute
// maps.
type Change struct {
	Kind         ChangeKind `json:"kind"`
	ArtifactID   string     `json:"artifact_id,omitempty"`
	ArtifactType string     `json:"artifact_type,omitempty"`
	ProbeID      string     `json:"probe_id,omitempty"`
	// CapabilityID names the capability of a capability entry; those entries
	// carry no artifact id.
	CapabilityID string `json:"capability_id,omitempty"`
	// BeforePrivilege and AfterPrivilege are the privilege of a capability
	// entry on each side, empty where that side has no capability. A policy
	// rates a root capability by them (SPEC-0469 AC3).
	BeforePrivilege string `json:"before_privilege,omitempty"`
	AfterPrivilege  string `json:"after_privilege,omitempty"`
	// ChangedFields names compared artifact fields that differ (see
	// ComparedFields), sorted. Only for changed, and for capability_changed,
	// where it names capability fields (see CapabilityFields).
	ChangedFields []string `json:"changed_fields,omitempty"`
	// ChangedAttributes names attribute keys that differ, after
	// normalization, sorted. A key counts only when it was observed on both
	// sides: present there, or absent from a side whose source probe was
	// observed (captured, or not_applicable with a reason). Only for changed.
	ChangedAttributes []string `json:"changed_attributes,omitempty"`
	// UnobservedAttributes names the baseline attribute keys the current
	// bundle did not observe, sorted. Only for not_observed.
	UnobservedAttributes []string `json:"unobserved_attributes,omitempty"`
	// BaselineGapProbes names the probes that produced the sources of a
	// capability and were blind in the baseline, sorted. Only for
	// coverage_increased, where it says why the capability is not called new.
	BaselineGapProbes []string `json:"baseline_gap_probes,omitempty"`
	// CoverageCaveatProbes names the probes behind the sources of a
	// capability_added entry whose baseline coverage was thinner than the
	// current one, sorted: a probe that only reported partially there, and a
	// probe that was blind there while another source was covered. The entry
	// stays capability_added at its normal severity, because the baseline did
	// look at ground this capability stands on; the list says where the
	// comparison rests on less than a full baseline (R-T1).
	CoverageCaveatProbes []string `json:"coverage_caveat_probes,omitempty"`
	// BeforeDigest and AfterDigest are "sha256:<hex>" over the canonical JSON
	// of the normalized attribute map on each side. A not_observed entry has
	// an AfterDigest only when the artifact itself is in the current bundle.
	BeforeDigest     string                    `json:"before_digest,omitempty"`
	AfterDigest      string                    `json:"after_digest,omitempty"`
	BeforeState      trustfreeze.EvidenceState `json:"before_state,omitempty"`
	AfterState       trustfreeze.EvidenceState `json:"after_state,omitempty"`
	BeforeConfidence trustfreeze.Confidence    `json:"before_confidence,omitempty"`
	AfterConfidence  trustfreeze.Confidence    `json:"after_confidence,omitempty"`
	// BeforeStatus and AfterStatus are the probe statuses of an
	// applicability_changed entry.
	BeforeStatus trustfreeze.ProbeStatus `json:"before_status,omitempty"`
	AfterStatus  trustfreeze.ProbeStatus `json:"after_status,omitempty"`
	// BeforeSubjectID and AfterSubjectID are the subject ids of a
	// subject_changed entry, and SubjectMismatchAllowed the opt-in.
	BeforeSubjectID        string `json:"before_subject_id,omitempty"`
	AfterSubjectID         string `json:"after_subject_id,omitempty"`
	SubjectMismatchAllowed bool   `json:"subject_mismatch_allowed,omitempty"`
	Gap                    *Gap   `json:"gap,omitempty"`
}

// Gap describes a collection gap of the current bundle.
type Gap struct {
	// Required is true when the probe is in the capture's required list.
	Required bool `json:"required"`
	// Status is the recorded probe status; empty when the probe has no single
	// valid result.
	Status trustfreeze.ProbeStatus `json:"status,omitempty"`
	// Cause is one of the core gap reasons (trustfreeze.GapReasons):
	// no_result, duplicate_result, invalid_status,
	// not_applicable_without_reason, not_captured, or not_applicable for a
	// probe that is not applicable with a reason.
	Cause string `json:"cause"`
	// Reason is the probe's own reason, when it gave one.
	Reason string `json:"reason,omitempty"`
}

// Compare returns the diff from baseline to current. baseline must be a
// baseline bundle; current a capture or a baseline bundle. Both must be
// verified by the caller (see the package documentation).
//
// Different subject ids yield one subject_changed entry. Artifacts are keyed
// by id and compared after normalization. The source probe of an artifact is
// the probe its source field names; its artifacts count as observed in a
// bundle where that probe has exactly one result that is captured, or
// not_applicable with a reason (an artifact whose source is no probe id
// counts as observed):
//   - added: the id exists only in the current bundle;
//   - removed: the id exists only in the baseline and its source probe is
//     observed in the current bundle;
//   - not_observed: the id exists only in the baseline, or baseline
//     attributes are missing from it, and its source probe is not observed
//     in the current bundle (never removed or changed);
//   - changed: a compared field differs, or an attribute observed on both
//     sides differs;
//   - confidence_changed: Provenance.Confidence differs;
//   - became_effective, became_ineffective: the state moves to or away from
//     observed.
//
// One artifact can yield several entries (for example changed and
// became_effective). Capabilities are compared separately, by capability id,
// and only as far as both bundles resolved them (see capability.go). A probe
// that moves between captured and not_applicable
// (with a reason) yields applicability_changed. Every probe of the current
// bundle that is not captured, and every required probe without a result,
// yields a collection_gap; a probe that is not_applicable with a reason is a
// gap of its own cause, not_applicable (SPEC-0469 section 4.2).
func Compare(ctx context.Context, baseline, current *trustfreeze.Bundle, opts CompareOptions) (Diff, error) {
	if err := ctx.Err(); err != nil {
		return Diff{}, err
	}
	rs, err := LoadRuleSet(opts.RuleSetID)
	if err != nil {
		return Diff{}, err
	}
	rsDigest, err := rs.Digest()
	if err != nil {
		return Diff{}, err
	}
	if err := checkInput("baseline", baseline, trustfreeze.KindBaseline); err != nil {
		return Diff{}, err
	}
	if err := checkInput("current", current, trustfreeze.KindCapture, trustfreeze.KindBaseline); err != nil {
		return Diff{}, err
	}
	before, err := indexArtifacts("baseline", baseline)
	if err != nil {
		return Diff{}, err
	}
	after, err := indexArtifacts("current", current)
	if err != nil {
		return Diff{}, err
	}

	beforeProbes, afterProbes := indexProbes(baseline.Capture), indexProbes(current.Capture)

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

	changes := []Change{}
	if bs, as := baseline.Manifest.Subject.ID, current.Manifest.Subject.ID; bs != as {
		changes = append(changes, Change{
			Kind: ChangeSubjectChanged, BeforeSubjectID: bs, AfterSubjectID: as,
			SubjectMismatchAllowed: opts.AllowSubjectMismatch,
		})
	}
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return Diff{}, err
		}
		b, inBefore := before[id]
		a, inAfter := after[id]
		switch {
		case !inBefore:
			changes = append(changes, Change{
				Kind: ChangeAdded, ArtifactID: id, ArtifactType: a.Type,
				AfterDigest: attributeDigest(rs.NormalizeAttributes(a.Attributes)),
			})
		case !inAfter:
			nb := rs.NormalizeAttributes(b.Attributes)
			if afterProbes.observes(b.Source) {
				changes = append(changes, Change{
					Kind: ChangeRemoved, ArtifactID: id, ArtifactType: b.Type,
					BeforeDigest: attributeDigest(nb),
				})
				continue
			}
			changes = append(changes, Change{
				Kind: ChangeNotObserved, ArtifactID: id, ArtifactType: b.Type, ProbeID: b.Source,
				UnobservedAttributes: sortedKeys(nb), BeforeDigest: attributeDigest(nb),
			})
		default:
			changes = append(changes, compareArtifact(rs, b, a, beforeProbes.observes(b.Source), afterProbes.observes(a.Source))...)
		}
	}
	capChanges, err := capabilityChanges(baseline, current, after, beforeProbes)
	if err != nil {
		return Diff{}, err
	}
	changes = append(changes, capChanges...)
	gaps, err := collectionGaps(current.Capture)
	if err != nil {
		return Diff{}, err
	}
	changes = append(changes, gaps...)
	changes = append(changes, applicabilityChanges(beforeProbes, afterProbes)...)
	sortChanges(changes)

	d := Diff{
		SchemaVersion:        trustfreeze.SchemaDiff,
		Kind:                 trustfreeze.KindDiff,
		Normalization:        RuleSetRef{ID: rs.ID, Digest: rsDigest},
		Baseline:             inputRef(baseline),
		Current:              inputRef(current),
		AllowSubjectMismatch: opts.AllowSubjectMismatch,
		Counts:               countChanges(changes),
		Changes:              changes,
	}
	if err := d.Validate(); err != nil {
		return Diff{}, err
	}
	return d, nil
}

func checkInput(role string, b *trustfreeze.Bundle, kinds ...trustfreeze.Kind) error {
	switch {
	case b == nil:
		return fmt.Errorf("%w: %s bundle is nil", ErrNotVerified, role)
	case !b.Integrity.OK:
		return fmt.Errorf("%w: %s bundle failed or skipped its integrity check", ErrNotVerified, role)
	case b.Manifest.ContentDigest == "" || b.Integrity.ContentDigest != b.Manifest.ContentDigest:
		return fmt.Errorf("%w: %s bundle content digest is missing or differs from its integrity result", ErrNotVerified, role)
	case !slices.Contains(kinds, b.Manifest.Kind):
		return fmt.Errorf("%w: %s bundle is kind %q, want one of %q", ErrInputKind, role, b.Manifest.Kind, kinds)
	case b.Capture == nil:
		return fmt.Errorf("%w: %s bundle has no capture document", ErrInvalidInput, role)
	}
	return nil
}

func indexArtifacts(role string, b *trustfreeze.Bundle) (map[string]trustfreeze.Artifact, error) {
	out := map[string]trustfreeze.Artifact{}
	if b.State == nil {
		return out, nil
	}
	for _, a := range b.State.Artifacts {
		if err := trustfreeze.ValidateArtifactID(a.ID); err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrInvalidInput, role, err)
		}
		if _, dup := out[a.ID]; dup {
			return nil, fmt.Errorf("%w: %s: artifact id %q appears more than once", ErrInvalidInput, role, a.ID)
		}
		if !a.State.Valid() || !a.Provenance.Confidence.Valid() || !a.Sensitivity.Valid() {
			return nil, fmt.Errorf("%w: %s: artifact %q has an unknown state, confidence or sensitivity", ErrInvalidInput, role, a.ID)
		}
		out[a.ID] = a
	}
	return out, nil
}

func inputRef(b *trustfreeze.Bundle) InputRef {
	return InputRef{
		Kind:          b.Manifest.Kind,
		BundleID:      b.Manifest.BundleID,
		ContentDigest: b.Manifest.ContentDigest,
		Subject:       b.Manifest.Subject,
		Profile:       b.Capture.Capture.Profile,
	}
}

// compareArtifact compares two artifacts with the same id. bObserved and
// aObserved say whether the source probe on that side was observed; an
// attribute missing from a side whose probe was not observed is not a
// change but, on the current side, not_observed.
func compareArtifact(rs RuleSet, b, a trustfreeze.Artifact, bObserved, aObserved bool) []Change {
	var out []Change
	nb, na := rs.NormalizeAttributes(b.Attributes), rs.NormalizeAttributes(a.Attributes)

	var fields []string
	for _, f := range comparedFields {
		if !rs.volatileField(f.name) && f.get(b) != f.get(a) {
			fields = append(fields, f.name)
		}
	}
	bObs, aObs := b.State == trustfreeze.StateObserved, a.State == trustfreeze.StateObserved
	if b.State != a.State && !bObs && !aObs {
		fields = append(fields, "state")
	}
	slices.Sort(fields)
	attrs := changedKeys(nb, na, bObserved, aObserved)
	if len(fields) > 0 || len(attrs) > 0 {
		out = append(out, Change{
			Kind: ChangeChanged, ArtifactID: a.ID, ArtifactType: a.Type,
			ChangedFields: fields, ChangedAttributes: attrs,
			BeforeDigest: attributeDigest(nb), AfterDigest: attributeDigest(na),
		})
	}
	if !aObserved {
		if missing := missingKeys(nb, na); len(missing) > 0 {
			out = append(out, Change{
				Kind: ChangeNotObserved, ArtifactID: a.ID, ArtifactType: a.Type, ProbeID: a.Source,
				UnobservedAttributes: missing,
				BeforeDigest:         attributeDigest(nb), AfterDigest: attributeDigest(na),
			})
		}
	}
	if b.Provenance.Confidence != a.Provenance.Confidence {
		out = append(out, Change{
			Kind: ChangeConfidenceChanged, ArtifactID: a.ID, ArtifactType: a.Type,
			BeforeConfidence: b.Provenance.Confidence, AfterConfidence: a.Provenance.Confidence,
		})
	}
	switch {
	case !bObs && aObs:
		out = append(out, Change{
			Kind: ChangeBecameEffective, ArtifactID: a.ID, ArtifactType: a.Type,
			BeforeState: b.State, AfterState: a.State,
		})
	case bObs && !aObs:
		out = append(out, Change{
			Kind: ChangeBecameIneffective, ArtifactID: a.ID, ArtifactType: a.Type,
			BeforeState: b.State, AfterState: a.State,
		})
	}
	return out
}

// changedKeys returns the sorted keys whose values differ. A key present on
// one side only counts only when the other side observed its absence (its
// source probe was observed there).
func changedKeys(b, a map[string]string, bObserved, aObserved bool) []string {
	var out []string
	for k, bv := range b {
		if av, ok := a[k]; (ok && av != bv) || (!ok && aObserved) {
			out = append(out, k)
		}
	}
	for k := range a {
		if _, ok := b[k]; !ok && bObserved {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

// missingKeys returns the sorted keys of b that a lacks.
func missingKeys(b, a map[string]string) []string {
	var out []string
	for k := range b {
		if _, ok := a[k]; !ok {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

// sortedKeys returns the keys of m, sorted.
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// probeIndex holds the capture.json probe summaries of one bundle by id.
type probeIndex map[string][]trustfreeze.ProbeSummary

func indexProbes(doc *trustfreeze.CaptureDoc) probeIndex {
	out := probeIndex{}
	for _, p := range doc.Probes {
		out[p.ProbeID] = append(out[p.ProbeID], p)
	}
	return out
}

// single returns the one result of probe id, when there is exactly one with
// a known status.
func (x probeIndex) single(id string) (trustfreeze.ProbeSummary, bool) {
	ps := x[id]
	if len(ps) != 1 || !ps[0].Status.Valid() {
		return trustfreeze.ProbeSummary{}, false
	}
	return ps[0], true
}

// observes reports whether the artifacts of probe id were observed in the
// bundle: the probe has exactly one result that is captured, or
// not_applicable with a reason (the probe observed that nothing applies). A
// source that is not a probe id cannot be tied to a gap and counts as
// observed, so compare never hides an absence behind a missing probe.
func (x probeIndex) observes(id string) bool {
	if trustfreeze.ValidateProbeID(id) != nil {
		return true
	}
	p, ok := x.single(id)
	return ok && (p.Status == trustfreeze.StatusCaptured || notApplicableWithReason(p))
}

func notApplicableWithReason(p trustfreeze.ProbeSummary) bool {
	return p.Status == trustfreeze.StatusNotApplicable && strings.TrimSpace(p.Reason) != ""
}

// blindStatuses are the probe statuses under which a probe produced no usable
// observation: whatever it was asked about, it saw nothing a capability could
// rest on. captured and partial are absent on purpose, because a probe that
// reported partially did look and did report (R-T1 (a)). The list is closed,
// so a new status has to be classified here deliberately.
var blindStatuses = []trustfreeze.ProbeStatus{
	trustfreeze.StatusUnsupported, trustfreeze.StatusUnavailable,
	trustfreeze.StatusPermissionDenied, trustfreeze.StatusTimeout,
	trustfreeze.StatusFailed, trustfreeze.StatusNotApplicable,
}

// blind reports whether probe id produced no usable observation in this
// bundle: it left no single result with a known status (absent, duplicated or
// invalid), or that status is one of blindStatuses. A source that is not a
// probe id cannot be tied to a result and is never called blind, so the
// coverage guard never invents a gap it did not measure.
func (x probeIndex) blind(id string) bool {
	if trustfreeze.ValidateProbeID(id) != nil {
		return false
	}
	p, ok := x.single(id)
	return !ok || slices.Contains(blindStatuses, p.Status)
}

// reportedPartially reports whether probe id has exactly one result and it is
// partial: the probe did look and did report, but not completely.
func (x probeIndex) reportedPartially(id string) bool {
	p, ok := x.single(id)
	return ok && p.Status == trustfreeze.StatusPartial
}

// applicabilityChanges lists every probe whose single result moves between
// captured and not_applicable with a reason, in either direction.
func applicabilityChanges(before, after probeIndex) []Change {
	var out []Change
	for id := range after {
		b, bok := before.single(id)
		a, aok := after.single(id)
		if !bok || !aok {
			continue
		}
		if (b.Status == trustfreeze.StatusCaptured && notApplicableWithReason(a)) ||
			(notApplicableWithReason(b) && a.Status == trustfreeze.StatusCaptured) {
			out = append(out, Change{Kind: ChangeApplicabilityChanged, ProbeID: id, BeforeStatus: b.Status, AfterStatus: a.Status})
		}
	}
	return out
}

// attributeDigest is "sha256:<hex>" over the canonical JSON of attrs. The map
// holds only strings with string keys, so encoding cannot fail except on
// invalid UTF-8, which a verified bundle cannot contain; the empty string is
// returned then and Diff.Validate rejects the result.
func attributeDigest(attrs map[string]string) string {
	b, err := trustfreeze.MarshalCanonical(attrs)
	if err != nil {
		return ""
	}
	return trustfreeze.Digest(b)
}

// collectionGaps lists every probe of the capture that is not captured, and
// every required probe without a result.
func collectionGaps(doc *trustfreeze.CaptureDoc) ([]Change, error) {
	required := map[string]bool{}
	for _, id := range doc.Completeness.Required {
		required[id] = true
	}
	byID := map[string][]trustfreeze.ProbeSummary{}
	for _, p := range doc.Probes {
		byID[p.ProbeID] = append(byID[p.ProbeID], p)
	}
	ids := make([]string, 0, len(byID)+len(required))
	for id := range byID {
		ids = append(ids, id)
	}
	for id := range required {
		if _, ok := byID[id]; !ok {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)

	var out []Change
	for _, id := range ids {
		if err := trustfreeze.ValidateProbeID(id); err != nil {
			return nil, fmt.Errorf("%w: current: %w", ErrInvalidInput, err)
		}
		g := Gap{Required: required[id]}
		ps := byID[id]
		switch {
		case len(ps) == 0:
			g.Cause = trustfreeze.GapNoResult
		case len(ps) > 1:
			g.Cause = trustfreeze.GapDuplicateResult
		case !ps[0].Status.Valid():
			g.Cause = trustfreeze.GapInvalidStatus
		case ps[0].Status == trustfreeze.StatusCaptured:
			continue
		case ps[0].Status == trustfreeze.StatusNotApplicable && strings.TrimSpace(ps[0].Reason) == "":
			g.Status, g.Cause = ps[0].Status, trustfreeze.GapNotApplicableNoReason
		case ps[0].Status == trustfreeze.StatusNotApplicable:
			// Not applicable with a reason: complete for the capture, and
			// still visible here as its own cause (SPEC-0469 section 4.2).
			g.Status, g.Cause, g.Reason = ps[0].Status, trustfreeze.GapNotApplicable, ps[0].Reason
		default:
			g.Status, g.Cause, g.Reason = ps[0].Status, trustfreeze.GapNotCaptured, ps[0].Reason
		}
		out = append(out, Change{Kind: ChangeCollectionGap, ProbeID: id, Gap: &g})
	}
	return out, nil
}

func sortChanges(cs []Change) {
	slices.SortStableFunc(cs, compareChanges)
}

// compareChanges orders by (kind rank, artifact id, capability id, probe id).
func compareChanges(x, y Change) int {
	if d := x.Kind.rank() - y.Kind.rank(); d != 0 {
		return d
	}
	if c := strings.Compare(x.ArtifactID, y.ArtifactID); c != 0 {
		return c
	}
	if c := strings.Compare(x.CapabilityID, y.CapabilityID); c != 0 {
		return c
	}
	return strings.Compare(x.ProbeID, y.ProbeID)
}

func countChanges(cs []Change) map[string]int {
	out := make(map[string]int, len(changeKindValues))
	for _, k := range changeKindValues {
		out[string(k)] = 0
	}
	for _, c := range cs {
		out[string(c.Kind)]++
	}
	return out
}
