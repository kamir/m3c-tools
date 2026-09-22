package policy

import (
	"errors"
	"regexp"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/compare"
)

// milestoneTerm matches a delivery milestone name (PR-1, PR 2, T-01).
var milestoneTerm = regexp.MustCompile(`\bPR[- ]?[0-9]+\b|\bT-[0-9]{2}\b`)

// O-7: the built-in policy carries no milestone term. Its description is part
// of the rules digest, so every verdict would pin the planning term.
func TestBuiltinPolicyCarriesNoMilestoneTerm(t *testing.T) {
	if !milestoneTerm.MatchString("Minimal PR-1 policy.") {
		t.Fatal("the scan misses a planted milestone term")
	}
	if m := milestoneTerm.FindString(string(defaultV0JSON)); m != "" {
		t.Fatalf("%s carries the milestone term %q", DefaultPolicyID, m)
	}
	if m := milestoneTerm.FindString(yamlPolicy); m != "" {
		t.Fatalf("the YAML spelling of %s carries the milestone term %q", DefaultPolicyID, m)
	}
}

// gapDiff is a valid diff of identical captures with one synthetic change.
func gapDiff(t *testing.T, c compare.Change) compare.Diff {
	t.Helper()
	d := diffOf(t, identityCapture(testTime, "24.04", 0), identityCapture(testTime, "24.04", 0))
	d.Changes = []compare.Change{c}
	d.Counts = map[string]int{}
	for _, k := range compare.ChangeKinds() {
		d.Counts[string(k)] = 0
	}
	d.Counts[string(c.Kind)] = 1
	return d
}

// R-B, SPEC-0469 section 4.5: default-v0 rates every gap cause. A probe that
// is not applicable with a reason is info, required or not; every other cause
// is critical for a required and medium for an optional probe, so no cause
// falls through to the default severity.
func TestDefaultPolicyRatesEveryGapCause(t *testing.T) {
	for _, cause := range trustfreeze.GapReasons() {
		for _, required := range []bool{true, false} {
			d := gapDiff(t, compare.Change{Kind: compare.ChangeCollectionGap, ProbeID: "common.extra", Gap: &compare.Gap{Required: required, Cause: cause}})
			f := evaluate(t, d, defaultPolicy(t)).Findings[0]
			want := trustfreeze.Finding{Severity: trustfreeze.SeverityCritical, RuleID: "TF-POL-GAP-REQUIRED"}
			switch {
			case cause == trustfreeze.GapNotApplicable:
				want = trustfreeze.Finding{Severity: trustfreeze.SeverityInfo, RuleID: "TF-POL-GAP-NOT-APPLICABLE"}
			case !required:
				want = trustfreeze.Finding{Severity: trustfreeze.SeverityMedium, RuleID: "TF-POL-GAP-OPTIONAL"}
			}
			if f.Severity != want.Severity || f.RuleID != want.RuleID {
				t.Errorf("cause %s required %v: %s@%s, want %s@%s", cause, required, f.Severity, f.RuleID, want.Severity, want.RuleID)
			}
		}
	}
}

// MC/DC for the matcher conditions of the decision round: gap causes, gap
// statuses and the subject mismatch opt-in. Each false row flips exactly one
// condition of its all-true row.
func TestRuleMatchNewConditionsMCDC(t *testing.T) {
	yes, no := true, false
	gapKinds := []compare.ChangeKind{compare.ChangeCollectionGap}
	causeRule := Rule{ID: "c", Severity: trustfreeze.SeverityHigh, Match: Match{ChangeKinds: gapKinds, Required: &yes, GapCauses: []string{trustfreeze.GapNotCaptured}}}
	statusRule := Rule{ID: "s", Severity: trustfreeze.SeverityHigh, Match: Match{ChangeKinds: gapKinds, GapStatuses: []trustfreeze.ProbeStatus{trustfreeze.StatusTimeout}}}
	subjRule := Rule{ID: "a", Severity: trustfreeze.SeverityInfo, Match: Match{ChangeKinds: []compare.ChangeKind{compare.ChangeSubjectChanged}, SubjectMismatchAllowed: &yes}}
	subjDenied := Rule{ID: "d", Severity: trustfreeze.SeverityHigh, Match: Match{ChangeKinds: []compare.ChangeKind{compare.ChangeSubjectChanged}, SubjectMismatchAllowed: &no}}
	gap := func(req bool, cause string, st trustfreeze.ProbeStatus) compare.Change {
		return compare.Change{Kind: compare.ChangeCollectionGap, ProbeID: "p", Gap: &compare.Gap{Required: req, Cause: cause, Status: st}}
	}
	subj := func(allowed bool) compare.Change {
		return compare.Change{Kind: compare.ChangeSubjectChanged, BeforeSubjectID: "device/a", AfterSubjectID: "device/b", SubjectMismatchAllowed: allowed}
	}
	cases := []struct {
		name string
		rule Rule
		c    compare.Change
		want bool
	}{
		{"cause rule: all true", causeRule, gap(true, trustfreeze.GapNotCaptured, trustfreeze.StatusTimeout), true},
		{"cause rule: kind false", causeRule, compare.Change{Kind: compare.ChangeChanged, ArtifactID: "x"}, false},
		{"cause rule: required false", causeRule, gap(false, trustfreeze.GapNotCaptured, trustfreeze.StatusTimeout), false},
		{"cause rule: cause false", causeRule, gap(true, trustfreeze.GapNotApplicable, trustfreeze.StatusNotApplicable), false},
		{"status rule: all true", statusRule, gap(false, trustfreeze.GapNotCaptured, trustfreeze.StatusTimeout), true},
		{"status rule: status false", statusRule, gap(false, trustfreeze.GapNotCaptured, trustfreeze.StatusPartial), false},
		{"status rule: no status", statusRule, gap(false, trustfreeze.GapNoResult, ""), false},
		{"allowed rule: all true", subjRule, subj(true), true},
		{"allowed rule: opt-in false", subjRule, subj(false), false},
		{"allowed rule: kind false", subjRule, gap(true, trustfreeze.GapNotCaptured, trustfreeze.StatusTimeout), false},
		{"denied rule: all true", subjDenied, subj(false), true},
		{"denied rule: opt-in true", subjDenied, subj(true), false},
	}
	for _, tc := range cases {
		if got := tc.rule.matches(tc.c); got != tc.want {
			t.Errorf("%s: matches = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The new match conditions are refused where they cannot apply.
func TestPolicyValidateNewConditions(t *testing.T) {
	yes := true
	gapKinds := []compare.ChangeKind{compare.ChangeCollectionGap}
	base := func(m Match) Policy {
		return Policy{SchemaVersion: trustfreeze.SchemaPolicy, ID: "x", FailOn: ThresholdHigh, DefaultSeverity: trustfreeze.SeverityInfo,
			Rules: []Rule{{ID: "r", Severity: trustfreeze.SeverityLow, Match: m}}}
	}
	good := []Match{
		{ChangeKinds: gapKinds, GapCauses: []string{trustfreeze.GapNotApplicable}},
		{ChangeKinds: gapKinds, GapStatuses: []trustfreeze.ProbeStatus{trustfreeze.StatusTimeout}},
		{ChangeKinds: []compare.ChangeKind{compare.ChangeSubjectChanged}, SubjectMismatchAllowed: &yes},
	}
	for i, m := range good {
		if err := base(m).Validate(); err != nil {
			t.Errorf("good %d: %v", i, err)
		}
	}
	bad := map[string]Match{
		"gap causes beside another kind":     {ChangeKinds: []compare.ChangeKind{compare.ChangeCollectionGap, compare.ChangeAdded}, GapCauses: []string{trustfreeze.GapNoResult}},
		"gap statuses beside another kind":   {ChangeKinds: []compare.ChangeKind{compare.ChangeAdded}, GapStatuses: []trustfreeze.ProbeStatus{trustfreeze.StatusTimeout}},
		"unknown gap cause":                  {ChangeKinds: gapKinds, GapCauses: []string{"vanished"}},
		"unknown gap status":                 {ChangeKinds: gapKinds, GapStatuses: []trustfreeze.ProbeStatus{"gone"}},
		"empty gap causes":                   {ChangeKinds: gapKinds, GapCauses: []string{}},
		"empty gap statuses":                 {ChangeKinds: gapKinds, GapStatuses: []trustfreeze.ProbeStatus{}},
		"subject opt-in on another kind":     {ChangeKinds: []compare.ChangeKind{compare.ChangeChanged}, SubjectMismatchAllowed: &yes},
		"subject opt-in beside another kind": {ChangeKinds: []compare.ChangeKind{compare.ChangeSubjectChanged, compare.ChangeAdded}, SubjectMismatchAllowed: &yes},
	}
	for name, m := range bad {
		if err := base(m).Validate(); !errors.Is(err, ErrInvalidPolicy) {
			t.Errorf("%s: Validate = %v", name, err)
		}
	}
	// A policy file spells them the same way.
	p, err := ParsePolicy([]byte(`{"schema_version":"trust-freeze/policy/v1","id":"x","fail_on":"high","default_severity":"info","rules":[` +
		`{"id":"t","severity":"high","match":{"change_kinds":["collection_gap"],"gap_statuses":["timeout"],"gap_causes":["not_captured"]}}]}`))
	if err != nil || len(p.Rules[0].Match.GapStatuses) != 1 {
		t.Fatalf("parse: %v", err)
	}
	if _, err := ParsePolicy([]byte(`{"schema_version":"trust-freeze/policy/v1","id":"x","fail_on":"high","default_severity":"info","rules":[` +
		`{"id":"t","severity":"high","match":{"change_kinds":["collection_gap"],"gap_statuses":["asleep"]}}]}`)); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("unknown status in a file: %v", err)
	}
}

// The messages of the new kinds name ids and statuses, never values.
func TestMessagesOfNewKinds(t *testing.T) {
	cases := map[string]compare.Change{
		"the baseline describes device device/a, the current bundle device device/b":                                       {Kind: compare.ChangeSubjectChanged, BeforeSubjectID: "device/a", AfterSubjectID: "device/b"},
		"the baseline describes device device/a, the current bundle device device/b (the mismatch was allowed explicitly)": {Kind: compare.ChangeSubjectChanged, BeforeSubjectID: "device/a", AfterSubjectID: "device/b", SubjectMismatchAllowed: true},
		"artifact extra/x (fixture) was not observed: source probe common.extra was not captured":                          {Kind: compare.ChangeNotObserved, ArtifactID: "extra/x", ArtifactType: "fixture", ProbeID: "common.extra", BeforeDigest: "sha256:b"},
		"attributes k1, k2 of artifact extra/x (fixture) were not observed: source probe common.extra was not captured":    {Kind: compare.ChangeNotObserved, ArtifactID: "extra/x", ArtifactType: "fixture", ProbeID: "common.extra", UnobservedAttributes: []string{"k1", "k2"}, BeforeDigest: "sha256:b", AfterDigest: "sha256:a"},
		"probe common.extra moved from captured to not_applicable":                                                         {Kind: compare.ChangeApplicabilityChanged, ProbeID: "common.extra", BeforeStatus: trustfreeze.StatusCaptured, AfterStatus: trustfreeze.StatusNotApplicable},
		"required probe common.extra is not applicable (not_applicable, status not_applicable, reason no such tool)":       {Kind: compare.ChangeCollectionGap, ProbeID: "common.extra", Gap: &compare.Gap{Required: true, Cause: trustfreeze.GapNotApplicable, Status: trustfreeze.StatusNotApplicable, Reason: "no such tool"}},
	}
	for want, c := range cases {
		if got := message(c); got != want {
			t.Errorf("message = %q\nwant      %q", got, want)
		}
	}
	if got := findingID(compare.Change{Kind: compare.ChangeSubjectChanged, AfterSubjectID: "device/b"}); got != "subject_changed:device/b" {
		t.Errorf("subject finding id %q", got)
	}
	if got := findingID(compare.Change{Kind: compare.ChangeApplicabilityChanged, ProbeID: "common.extra"}); got != "applicability_changed:common.extra" {
		t.Errorf("applicability finding id %q", got)
	}
}
