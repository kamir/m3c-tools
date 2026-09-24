package compare

import (
	"context"
	"errors"
	"maps"
	"reflect"
	"regexp"
	"slices"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
)

// milestoneTerm matches a delivery milestone name (PR-1, PR 2, T-01).
var milestoneTerm = regexp.MustCompile(`\bPR[- ]?[0-9]+\b|\bT-[0-9]{2}\b`)

// O-7: the normalization rule set carries no milestone term; its canonical
// form is digested into every diff.
func TestRuleSetsCarryNoMilestoneTerm(t *testing.T) {
	if !milestoneTerm.MatchString("rules of PR-1") {
		t.Fatal("the scan misses a planted milestone term")
	}
	if len(ruleSetFiles) == 0 {
		t.Fatal("no rule sets")
	}
	for id, b := range ruleSetFiles {
		if m := milestoneTerm.FindString(string(b)); m != "" {
			t.Errorf("rule set %s carries the milestone term %q", id, m)
		}
	}
}

// R-A, SPEC-0469 section 4.2: different subject ids yield one
// subject_changed entry, first in the diff; the opt-in is carried by the entry
// and recorded in the diff, also when the subjects are equal.
func TestCompareSubjectChanged(t *testing.T) {
	a := baseFixture(testTime, 0)
	b := baseFixture(testTime, 0)
	b.host = "host-b.example"
	for _, allow := range []bool{false, true} {
		d, err := Compare(context.Background(), memBundle(t, trustfreeze.KindBaseline, a), memBundle(t, trustfreeze.KindCapture, b), CompareOptions{AllowSubjectMismatch: allow})
		if err != nil {
			t.Fatal(err)
		}
		if d.AllowSubjectMismatch != allow || len(d.Changes) != 1 {
			t.Fatalf("allow %v: diff %+v", allow, d)
		}
		c := d.Changes[0]
		want := Change{Kind: ChangeSubjectChanged, BeforeSubjectID: a.subject().ID, AfterSubjectID: b.subject().ID, SubjectMismatchAllowed: allow}
		if !reflect.DeepEqual(c, want) {
			t.Fatalf("allow %v: change %+v, want %+v", allow, c, want)
		}
		if d.Counts[string(ChangeSubjectChanged)] != 1 {
			t.Fatalf("counts %v", d.Counts)
		}
	}
	d, err := Compare(context.Background(), memBundle(t, trustfreeze.KindBaseline, a), memBundle(t, trustfreeze.KindCapture, a), CompareOptions{AllowSubjectMismatch: true})
	if err != nil || !d.AllowSubjectMismatch || len(d.Changes) != 0 {
		t.Fatalf("same subject with the opt-in: %v %+v", err, d)
	}
}

// withProbe adds a probe result and makes the artifacts with the given ids
// come from that probe.
func withProbe(f fixture, id string, st trustfreeze.ProbeStatus, reason string, artIDs ...string) fixture {
	f.results = append(slices.Clone(f.results), probeResult(id, st, reason, f.at, 1))
	f.arts = slices.Clone(f.arts)
	for i := range f.arts {
		if slices.Contains(artIDs, f.arts[i].ID) {
			f.arts[i].Source = id
		}
	}
	return f
}

func extraArtifact(f fixture, attrs map[string]string) fixture {
	f.arts = append(slices.Clone(f.arts), artifact("extra/x", "extra", trustfreeze.StateObserved, trustfreeze.ConfidenceProven, trustfreeze.FormatTime(f.at), attrs))
	return f
}

// R-B, SPEC-0469 section 4.2: an artifact whose source probe is not observed
// in the current bundle is not_observed, never removed; with its probe
// captured, or not applicable with a reason, it is removed.
func TestCompareNotObservedVersusRemoved(t *testing.T) {
	bl := withProbe(extraArtifact(baseFixture(testTime, 0), map[string]string{"k1": "v", "k2": "w"}), "common.extra", trustfreeze.StatusCaptured, "", "extra/x")
	blB := memBundle(t, trustfreeze.KindBaseline, bl)
	cases := []struct {
		name   string
		status trustfreeze.ProbeStatus
		reason string
		want   []string
	}{
		{"captured", trustfreeze.StatusCaptured, "", []string{"removed:extra/x"}},
		{"not applicable with a reason", trustfreeze.StatusNotApplicable, "gone", []string{"removed:extra/x", "applicability_changed:common.extra", "collection_gap:common.extra"}},
		{"not applicable without a reason", trustfreeze.StatusNotApplicable, "", []string{"not_observed:extra/x", "collection_gap:common.extra"}},
		{"timeout", trustfreeze.StatusTimeout, "slow", []string{"not_observed:extra/x", "collection_gap:common.extra"}},
		{"partial", trustfreeze.StatusPartial, "half", []string{"not_observed:extra/x", "collection_gap:common.extra"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cur := withProbe(baseFixture(testTime, 1), "common.extra", tc.status, tc.reason)
			d := mustCompare(t, blB, memBundle(t, trustfreeze.KindCapture, cur))
			if got := kinds(d); !slices.Equal(got, tc.want) {
				t.Fatalf("changes %q, want %q", got, tc.want)
			}
			if c := d.Changes[0]; c.Kind == ChangeNotObserved {
				if c.ProbeID != "common.extra" || !slices.Equal(c.UnobservedAttributes, []string{"k1", "k2"}) || c.BeforeDigest == "" || c.AfterDigest != "" {
					t.Fatalf("not_observed = %+v", c)
				}
			}
		})
	}
	// The probe is missing from the current bundle altogether (another
	// profile): not observed either.
	d := mustCompare(t, blB, memBundle(t, trustfreeze.KindCapture, baseFixture(testTime, 1)))
	if got := kinds(d); !slices.Equal(got, []string{"not_observed:extra/x"}) {
		t.Fatalf("probe absent: %q", got)
	}
	// An artifact whose source names no probe cannot hide behind a gap.
	noSource := extraArtifact(baseFixture(testTime, 0), map[string]string{"k1": "v"})
	noSource.arts[len(noSource.arts)-1].Source = "not a probe id"
	d = mustCompare(t, memBundle(t, trustfreeze.KindBaseline, noSource), memBundle(t, trustfreeze.KindCapture, baseFixture(testTime, 1)))
	if got := kinds(d); !slices.Equal(got, []string{"removed:extra/x"}) {
		t.Fatalf("source without a probe: %q", got)
	}
}

// R-B: changed names only attributes observed on both sides; a baseline
// attribute the current side did not observe is not_observed.
func TestCompareChangedOnlyForAttributesObservedOnBothSides(t *testing.T) {
	blF := baseFixture(testTime, 0) // device/os from common.identity
	partial := func(f fixture) fixture {
		f.results = []trustfreeze.ProbeResult{probeResult("common.identity", trustfreeze.StatusPartial, "kernel_release not read", f.at, 1)}
		f.arts = slices.Clone(f.arts)
		attrs := maps.Clone(f.arts[0].Attributes)
		delete(attrs, "kernel_release")
		f.arts[0].Attributes = attrs
		return f
	}

	// Current partial: kernel_release unobserved, os_version really changed.
	cur := partial(baseFixture(testTime, 1))
	cur.arts[0].Attributes["os_version"] = "24.10"
	d := mustCompare(t, memBundle(t, trustfreeze.KindBaseline, blF), memBundle(t, trustfreeze.KindCapture, cur))
	if got := kinds(d); !slices.Equal(got, []string{"changed:device/os", "not_observed:device/os", "collection_gap:common.identity"}) {
		t.Fatalf("current partial: %q", got)
	}
	if c := d.Changes[0]; !slices.Equal(c.ChangedAttributes, []string{"os_version"}) {
		t.Fatalf("changed = %+v", c)
	}
	if c := d.Changes[1]; !slices.Equal(c.UnobservedAttributes, []string{"kernel_release"}) || c.AfterDigest == "" || c.ProbeID != "common.identity" {
		t.Fatalf("not_observed = %+v", c)
	}

	// Baseline partial: the attribute the baseline did not observe is no
	// change now; a new attribute beside a captured baseline is one.
	d = mustCompare(t, memBundle(t, trustfreeze.KindBaseline, partial(baseFixture(testTime, 0))), memBundle(t, trustfreeze.KindCapture, baseFixture(testTime, 1)))
	if got := kinds(d); len(got) != 0 {
		t.Fatalf("baseline partial: %q", got)
	}
	grown := baseFixture(testTime, 1)
	grown.arts[0].Attributes["os_codename"] = "noble"
	d = mustCompare(t, memBundle(t, trustfreeze.KindBaseline, blF), memBundle(t, trustfreeze.KindCapture, grown))
	if got := kinds(d); !slices.Equal(got, []string{"changed:device/os"}) || !slices.Equal(d.Changes[0].ChangedAttributes, []string{"os_codename"}) {
		t.Fatalf("new attribute: %q %+v", got, d.Changes)
	}
	shrunk := baseFixture(testTime, 1)
	delete(shrunk.arts[0].Attributes, "kernel_release")
	d = mustCompare(t, memBundle(t, trustfreeze.KindBaseline, blF), memBundle(t, trustfreeze.KindCapture, shrunk))
	if got := kinds(d); !slices.Equal(got, []string{"changed:device/os"}) || !slices.Equal(d.Changes[0].ChangedAttributes, []string{"kernel_release"}) {
		t.Fatalf("attribute gone under a captured probe: %q %+v", got, d.Changes)
	}
}

// R-B: a probe moving between captured and not_applicable (with a reason) is
// reported in both directions; staying, or a reasonless not_applicable, is not.
func TestCompareApplicabilityChanged(t *testing.T) {
	st := func(s trustfreeze.ProbeStatus, reason string) fixture {
		return withProbe(baseFixture(testTime, 0), "common.extra", s, reason)
	}
	cases := []struct {
		name     string
		bl, cur  fixture
		want     []string
		from, to trustfreeze.ProbeStatus
	}{
		{"captured to not applicable", st(trustfreeze.StatusCaptured, ""), st(trustfreeze.StatusNotApplicable, "gone"), []string{"applicability_changed:common.extra", "collection_gap:common.extra"}, trustfreeze.StatusCaptured, trustfreeze.StatusNotApplicable},
		{"not applicable to captured", st(trustfreeze.StatusNotApplicable, "absent"), st(trustfreeze.StatusCaptured, ""), []string{"applicability_changed:common.extra"}, trustfreeze.StatusNotApplicable, trustfreeze.StatusCaptured},
		{"stays not applicable", st(trustfreeze.StatusNotApplicable, "absent"), st(trustfreeze.StatusNotApplicable, "absent"), []string{"collection_gap:common.extra"}, "", ""},
		{"captured to reasonless not applicable", st(trustfreeze.StatusCaptured, ""), st(trustfreeze.StatusNotApplicable, ""), []string{"collection_gap:common.extra"}, "", ""},
		{"timeout to captured", st(trustfreeze.StatusTimeout, "slow"), st(trustfreeze.StatusCaptured, ""), nil, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := mustCompare(t, memBundle(t, trustfreeze.KindBaseline, tc.bl), memBundle(t, trustfreeze.KindCapture, tc.cur))
			if got := kinds(d); !slices.Equal(got, tc.want) {
				t.Fatalf("changes %q, want %q", got, tc.want)
			}
			if tc.from != "" && (d.Changes[0].BeforeStatus != tc.from || d.Changes[0].AfterStatus != tc.to) {
				t.Fatalf("applicability_changed = %+v", d.Changes[0])
			}
		})
	}
}

// The diff contract refuses every inconsistent use of the new kinds.
func TestDiffValidateNewKinds(t *testing.T) {
	b := withProbe(extraArtifact(baseFixture(testTime, 0), map[string]string{"k": "v"}), "common.extra", trustfreeze.StatusCaptured, "", "extra/x")
	other := withProbe(baseFixture(testTime, 1), "common.extra", trustfreeze.StatusNotApplicable, "gone")
	other.host = "host-b.example"
	d, err := Compare(context.Background(), memBundle(t, trustfreeze.KindBaseline, b), memBundle(t, trustfreeze.KindCapture, other), CompareOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"subject_changed:", "removed:extra/x", "applicability_changed:common.extra", "collection_gap:common.extra"}
	if got := kinds(d); !slices.Equal(got, want) {
		t.Fatalf("fixture: %q", got)
	}
	nb, err := Compare(context.Background(), memBundle(t, trustfreeze.KindBaseline, b), memBundle(t, trustfreeze.KindCapture, withProbe(baseFixture(testTime, 1), "common.extra", trustfreeze.StatusTimeout, "slow")), CompareOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := kinds(nb); !slices.Equal(got, []string{"not_observed:extra/x", "collection_gap:common.extra"}) {
		t.Fatalf("fixture: %q", got)
	}
	idx := func(d Diff, k ChangeKind) int {
		for i, c := range d.Changes {
			if c.Kind == k {
				return i
			}
		}
		t.Fatalf("no %s", k)
		return -1
	}
	cases := []struct {
		name string
		base Diff
		mut  func(*Diff)
	}{
		{"subject_changed dropped", d, func(d *Diff) { d.Changes = d.Changes[1:]; d.Counts = countChanges(d.Changes) }},
		{"subject_changed without differing subjects", d, func(d *Diff) { d.Current.Subject = d.Baseline.Subject }},
		{"subject_changed names other ids", d, func(d *Diff) { d.Changes[0].AfterSubjectID = "device/0000000000000000" }},
		{"subject_changed same ids", d, func(d *Diff) { d.Changes[0].AfterSubjectID = d.Changes[0].BeforeSubjectID }},
		{"subject_changed opt-in disagrees", d, func(d *Diff) { d.Changes[0].SubjectMismatchAllowed = true }},
		{"subject_changed with an artifact id", d, func(d *Diff) { d.Changes[0].ArtifactID = "device/os" }},
		{"subject fields on another kind", d, func(d *Diff) { d.Changes[1].BeforeSubjectID = "device/0000000000000000" }},
		{"statuses on another kind", d, func(d *Diff) { d.Changes[1].BeforeStatus = trustfreeze.StatusCaptured }},
		{"applicability_changed wrong move", d, func(d *Diff) { d.Changes[idx(*d, ChangeApplicabilityChanged)].AfterStatus = trustfreeze.StatusTimeout }},
		{"applicability_changed bad probe id", d, func(d *Diff) { d.Changes[idx(*d, ChangeApplicabilityChanged)].ProbeID = "Bad Probe" }},
		{"applicability_changed with an artifact id", d, func(d *Diff) { d.Changes[idx(*d, ChangeApplicabilityChanged)].ArtifactID = "extra/x" }},
		{"gap with unknown cause", d, func(d *Diff) { d.Changes[len(d.Changes)-1].Gap.Cause = "vanished" }},
		{"gap on an artifact entry", d, func(d *Diff) { d.Changes[1].Gap = &Gap{Cause: trustfreeze.GapNoResult} }},
		{"unobserved attributes on removed", d, func(d *Diff) { d.Changes[1].UnobservedAttributes = []string{"k"} }},
		{"probe id on removed", d, func(d *Diff) { d.Changes[1].ProbeID = "common.extra" }},
		{"not_observed bad probe id", nb, func(d *Diff) { d.Changes[0].ProbeID = "" }},
		{"not_observed without before digest", nb, func(d *Diff) { d.Changes[0].BeforeDigest = "" }},
		{"not_observed unsorted", nb, func(d *Diff) { d.Changes[0].UnobservedAttributes = []string{"z", "a"} }},
		{"not_observed present but nothing unobserved", nb, func(d *Diff) {
			d.Changes[0].AfterDigest, d.Changes[0].UnobservedAttributes = d.Changes[0].BeforeDigest, nil
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var c Diff
			if err := trustfreeze.UnmarshalStrict(mustFile(t, tc.base), &c); err != nil {
				t.Fatal(err)
			}
			if err := c.Validate(); err != nil {
				t.Fatalf("control: %v", err)
			}
			tc.mut(&c)
			if err := c.Validate(); !errors.Is(err, ErrInvalidDiff) {
				t.Fatalf("Validate = %v, want ErrInvalidDiff", err)
			}
		})
	}
}
