package policy

import (
	"bytes"
	"context"
	"errors"
	"math/rand"
	"slices"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/compare"
)

// A changed os_version yields one stable finding: same id, severity, rule
// and message whatever the capture times, durations, pid or uptime.
func TestStableFindingForChangedOSVersion(t *testing.T) {
	bl := identityCapture(testTime, "24.04", 0)
	var first []byte
	for i, at := range []time.Time{testTime.Add(time.Hour), testTime.Add(49*time.Hour + 7*time.Second)} {
		v := evaluate(t, diffOf(t, bl, identityCapture(at, "24.10", i+3)), defaultPolicy(t))
		if len(v.Findings) != 1 {
			t.Fatalf("findings = %q", findingKeys(v))
		}
		f := v.Findings[0]
		want := trustfreeze.Finding{
			ID: "changed:device/os", Kind: "changed", Severity: trustfreeze.SeverityMedium,
			ArtifactID: "device/os", RuleID: "TF-POL-DEVICE-IDENTITY",
			Message: "artifact device/os (os) changed: attributes os_version",
		}
		if f != want {
			t.Fatalf("finding = %+v\nwant      %+v", f, want)
		}
		b := mustFile(t, v.Findings)
		if i == 0 {
			first = b
		} else if !bytes.Equal(first, b) {
			t.Fatalf("finding bytes differ between runs:\n%s\n%s", first, b)
		}
		if v.HighestSeverity != trustfreeze.SeverityMedium || v.ThresholdExceeded {
			t.Fatalf("verdict = %+v", v)
		}
	}
}

// TF04-R9: identical diff and policy give a byte-identical verdict; the
// golden pins the bytes.
func TestEvaluateByteIdenticalGolden(t *testing.T) {
	var outs [][]byte
	for i := 0; i < 3; i++ {
		d := diffOf(t, identityCapture(testTime, "24.04", 0), identityCapture(testTime.Add(time.Hour), "24.10", 5))
		outs = append(outs, mustFile(t, evaluate(t, d, defaultPolicy(t))))
	}
	for i := 1; i < len(outs); i++ {
		if !bytes.Equal(outs[0], outs[i]) {
			t.Fatalf("run %d differs", i)
		}
	}
	checkGolden(t, "verdict_os_version.golden", outs[0])
}

// TF04-AC5: a missing required probe is a collection gap, critical under the
// default policy, and blocks at fail-on high.
func TestMissingRequiredProbeBlocks(t *testing.T) {
	bl := identityCapture(testTime, "24.04", 0)
	for _, tc := range []struct {
		name    string
		results []trustfreeze.ProbeResult
		cause   string
	}{
		{"no result", nil, trustfreeze.GapNoResult},
		{"timeout", []trustfreeze.ProbeResult{result("common.identity", trustfreeze.StatusTimeout, testTime, 5000)}, trustfreeze.GapNotCaptured},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cur := identityCapture(testTime, "24.04", 1)
			cur.results = tc.results
			d := diffOf(t, bl, cur)
			p := defaultPolicy(t)
			if p.FailOn != ThresholdHigh {
				t.Fatalf("default fail_on = %q, want high", p.FailOn)
			}
			v := evaluate(t, d, p)
			if got := findingKeys(v); !slices.Equal(got, []string{"collection_gap:common.identity=critical@TF-POL-GAP-REQUIRED"}) {
				t.Fatalf("findings = %q", got)
			}
			if d.Changes[0].Gap.Cause != tc.cause {
				t.Fatalf("cause = %q", d.Changes[0].Gap.Cause)
			}
			if v.HighestSeverity != trustfreeze.SeverityCritical || !v.ThresholdExceeded {
				t.Fatalf("verdict = %+v, want critical and threshold exceeded", v)
			}
		})
	}
}

// TF04-AC6: MC/DC for the gap rules over the two conditions "probe is
// required" and "probe was captured", evaluated end to end (compare, then the
// default policy at fail-on high).
//
//	case  required  captured  finding            exceeded
//	A     T         T         none               false
//	B     T         F         critical           true
//	C     F         T         none               false
//	D     F         F         medium             false
//
// required alone: B vs D. captured alone: A vs B and C vs D.
func TestGapRulesMCDC(t *testing.T) {
	cases := []struct {
		name         string
		required     bool
		captured     bool
		wantFindings []string
		wantExceeded bool
	}{
		{"A required captured", true, true, nil, false},
		{"B required not captured", true, false, []string{"collection_gap:common.extra=critical@TF-POL-GAP-REQUIRED"}, true},
		{"C optional captured", false, true, nil, false},
		{"D optional not captured", false, false, []string{"collection_gap:common.extra=medium@TF-POL-GAP-OPTIONAL"}, false},
	}
	bl := identityCapture(testTime, "24.04", 0)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cur := identityCapture(testTime, "24.04", 0)
			st := trustfreeze.StatusCaptured
			if !tc.captured {
				st = trustfreeze.StatusUnavailable
			}
			cur.results = append(cur.results, result("common.extra", st, testTime, 1))
			if tc.required {
				cur.required = append(cur.required, "common.extra")
			}
			v := evaluate(t, diffOf(t, bl, cur), defaultPolicy(t))
			if got := findingKeys(v); !slices.Equal(got, tc.wantFindings) {
				t.Fatalf("findings = %q, want %q", got, tc.wantFindings)
			}
			if v.ThresholdExceeded != tc.wantExceeded {
				t.Fatalf("threshold_exceeded = %v", v.ThresholdExceeded)
			}
		})
	}
}

// MC/DC for the rule matcher, a conjunction of three conditions: change kind,
// artifact id, and the required flag of a gap. Each row flips exactly one
// condition of the all-true row and must flip the result.
func TestRuleMatchMCDC(t *testing.T) {
	yes, no := true, false
	idRule := Rule{ID: "r", Severity: trustfreeze.SeverityHigh, Match: Match{ChangeKinds: []compare.ChangeKind{compare.ChangeChanged}, ArtifactIDs: []string{"device/os"}}}
	gapRule := Rule{ID: "g", Severity: trustfreeze.SeverityHigh, Match: Match{ChangeKinds: []compare.ChangeKind{compare.ChangeCollectionGap}, Required: &yes}}
	gap := func(req bool) *compare.Gap { return &compare.Gap{Required: req, Cause: trustfreeze.GapNotCaptured} }
	cases := []struct {
		name string
		rule Rule
		c    compare.Change
		want bool
	}{
		{"id rule: all true", idRule, compare.Change{Kind: compare.ChangeChanged, ArtifactID: "device/os"}, true},
		{"id rule: kind false", idRule, compare.Change{Kind: compare.ChangeAdded, ArtifactID: "device/os"}, false},
		{"id rule: artifact false", idRule, compare.Change{Kind: compare.ChangeChanged, ArtifactID: "device/host"}, false},
		{"gap rule: all true", gapRule, compare.Change{Kind: compare.ChangeCollectionGap, ProbeID: "p", Gap: gap(true)}, true},
		{"gap rule: kind false", gapRule, compare.Change{Kind: compare.ChangeChanged, ArtifactID: "x"}, false},
		{"gap rule: required false", gapRule, compare.Change{Kind: compare.ChangeCollectionGap, ProbeID: "p", Gap: gap(false)}, false},
		{"optional gap rule matches optional", Rule{ID: "o", Severity: trustfreeze.SeverityLow, Match: Match{ChangeKinds: []compare.ChangeKind{compare.ChangeCollectionGap}, Required: &no}}, compare.Change{Kind: compare.ChangeCollectionGap, ProbeID: "p", Gap: gap(false)}, true},
		{"unset conditions do not restrict", Rule{ID: "a", Severity: trustfreeze.SeverityLow, Match: Match{ChangeKinds: []compare.ChangeKind{compare.ChangeChanged}}}, compare.Change{Kind: compare.ChangeChanged, ArtifactID: "any/thing"}, true},
	}
	for _, tc := range cases {
		if got := tc.rule.matches(tc.c); got != tc.want {
			t.Errorf("%s: matches = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TF04-R6: among matching rules the highest severity wins, independent of
// rule order; a change no rule matches gets the default severity.
func TestHighestSeverityWins(t *testing.T) {
	d := diffOf(t, identityCapture(testTime, "24.04", 0), identityCapture(testTime, "24.10", 0))
	p := defaultPolicy(t)
	v := evaluate(t, d, p)
	slices.Reverse(p.Rules)
	r := evaluate(t, d, p)
	if !slices.Equal(findingKeys(v), findingKeys(r)) || v.Findings[0].Severity != trustfreeze.SeverityMedium {
		t.Fatalf("order changed the outcome: %q vs %q", findingKeys(v), findingKeys(r))
	}

	cur := identityCapture(testTime, "24.04", 0)
	cur.arts[2].Provenance.Confidence = trustfreeze.ConfidenceReported
	v = evaluate(t, diffOf(t, identityCapture(testTime, "24.04", 0), cur), defaultPolicy(t))
	if got := findingKeys(v); !slices.Equal(got, []string{"confidence_changed:runtime/skillctl=info@" + DefaultSeverityRuleID}) {
		t.Fatalf("unmatched change: %q", got)
	}
}

// TF04-R8: the fail-on threshold changes only fail_on and threshold_exceeded
// of the verdict, and never the diff.
func TestFailOnChangesOnlyThresholdExceeded(t *testing.T) {
	d := diffOf(t, identityCapture(testTime, "24.04", 0), identityCapture(testTime, "24.10", 0)) // highest: medium
	diffBefore := mustFile(t, d)
	want := map[Threshold]bool{ThresholdNone: false, ThresholdLow: true, ThresholdMedium: true, ThresholdHigh: false, ThresholdCritical: false}
	var ref []byte
	for _, th := range Thresholds() {
		p := defaultPolicy(t)
		p.FailOn = th
		v := evaluate(t, d, p)
		if v.FailOn != th || v.ThresholdExceeded != want[th] {
			t.Fatalf("fail-on %s: exceeded = %v, want %v", th, v.ThresholdExceeded, want[th])
		}
		v.FailOn, v.ThresholdExceeded = ThresholdNone, false
		b := mustFile(t, v)
		if ref == nil {
			ref = b
		} else if !bytes.Equal(ref, b) {
			t.Fatalf("fail-on %s changed more than the threshold fields:\n%s\n---\n%s", th, ref, b)
		}
		if !bytes.Equal(diffBefore, mustFile(t, d)) {
			t.Fatalf("fail-on %s changed the diff", th)
		}
	}
}

// TF04-AC7: the order of the input artifacts changes neither the verdict nor
// the diff digest it records.
func TestInputOrderDoesNotChangeVerdict(t *testing.T) {
	bl := identityCapture(testTime, "24.04", 0)
	cur := identityCapture(testTime, "24.10", 0)
	cur.arts = append(cur.arts, trustfreeze.Artifact{
		ID: "runtime/node", Type: "runtime", Scope: "device", Source: "common.identity", State: trustfreeze.StateDeclared,
		Attributes:  map[string]string{"version": "22.4.0"},
		Provenance:  trustfreeze.Provenance{Method: "file", Confidence: trustfreeze.ConfidenceReported, ObservedAt: trustfreeze.FormatTime(testTime)},
		Sensitivity: trustfreeze.SensitivityPublic,
	})
	// The bundles are built once, so their manifests and content digests stay
	// fixed; only the order in which the loaded artifacts reach compare varies.
	blB, curB := bl.bundle(t, trustfreeze.KindBaseline), cur.bundle(t, trustfreeze.KindCapture)
	verdictBytes := func() []byte {
		d, err := compare.Compare(context.Background(), blB, curB, compare.CompareOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return mustFile(t, evaluate(t, d, defaultPolicy(t)))
	}
	want := verdictBytes()
	if !bytes.Equal(want, mustFile(t, evaluate(t, diffOf(t, bl, cur), defaultPolicy(t)))) {
		t.Fatal("fixture error: rebuilt bundles differ")
	}
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 25; i++ {
		ca, ba := curB.State.Artifacts, blB.State.Artifacts
		rng.Shuffle(len(ca), func(a, b int) { ca[a], ca[b] = ca[b], ca[a] })
		rng.Shuffle(len(ba), func(a, b int) { ba[a], ba[b] = ba[b], ba[a] })
		if got := verdictBytes(); !bytes.Equal(got, want) {
			t.Fatalf("shuffle %d changed the verdict:\n%s\n---\n%s", i, got, want)
		}
	}
}

// Evaluate is pure: it changes neither the diff nor the policy.
func TestEvaluateDoesNotMutate(t *testing.T) {
	d := diffOf(t, identityCapture(testTime, "24.04", 0), identityCapture(testTime, "24.10", 0))
	p := defaultPolicy(t)
	db, pb := mustFile(t, d), mustFile(t, p)
	evaluate(t, d, p)
	if !bytes.Equal(db, mustFile(t, d)) || !bytes.Equal(pb, mustFile(t, p)) {
		t.Fatal("Evaluate mutated an input")
	}
}

func TestEvaluateRejects(t *testing.T) {
	d := diffOf(t, identityCapture(testTime, "24.04", 0), identityCapture(testTime, "24.10", 0))
	p := defaultPolicy(t)
	bad := p
	bad.DefaultSeverity = ""
	if _, err := Evaluate(context.Background(), d, bad); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("invalid policy: %v", err)
	}
	bd := d
	bd.Counts = map[string]int{}
	if _, err := Evaluate(context.Background(), bd, p); !errors.Is(err, compare.ErrInvalidDiff) {
		t.Fatalf("invalid diff: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Evaluate(ctx, d, p); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled: %v", err)
	}
}

func TestNoChangesNoFindings(t *testing.T) {
	v := evaluate(t, diffOf(t, identityCapture(testTime, "24.04", 0), identityCapture(testTime.Add(time.Hour), "24.04", 7)), defaultPolicy(t))
	if len(v.Findings) != 0 || v.HighestSeverity != "" || v.ThresholdExceeded {
		t.Fatalf("verdict = %+v", v)
	}
	if v.Findings == nil {
		t.Fatal("findings must be an empty list, not null")
	}
	b := mustFile(t, v)
	if bytes.Contains(b, []byte("highest_severity")) || !bytes.Contains(b, []byte(`"findings": []`)) {
		t.Fatalf("verdict json:\n%s", b)
	}
}

func TestParseVerdictRoundTripAndTamper(t *testing.T) {
	d := diffOf(t, identityCapture(testTime, "24.04", 0), identityCapture(testTime, "24.10", 0))
	v := evaluate(t, d, defaultPolicy(t))
	b := mustFile(t, v)
	back, err := ParseVerdict(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mustFile(t, back), b) {
		t.Fatal("round trip changed the bytes")
	}
	for name, mutate := range map[string]func(*Verdict){
		"schema":        func(v *Verdict) { v.SchemaVersion = "trust-freeze/verdict/v0" },
		"highest":       func(v *Verdict) { v.HighestSeverity = trustfreeze.SeverityLow },
		"counts":        func(v *Verdict) { v.Counts["low"] = 9 },
		"exceeded":      func(v *Verdict) { v.ThresholdExceeded = true },
		"duplicate id":  func(v *Verdict) { v.Findings = append(v.Findings, v.Findings[0]); v.Counts["medium"]++ },
		"no diff ref":   func(v *Verdict) { v.DiffDigest = "" },
		"nil findings":  func(v *Verdict) { v.Findings = nil },
		"bad threshold": func(v *Verdict) { v.FailOn = "info" },
	} {
		c := back
		c.Counts = cloneCounts(back.Counts)
		c.Findings = slices.Clone(back.Findings)
		mutate(&c)
		if err := c.Validate(); !errors.Is(err, ErrInvalidVerdict) {
			t.Errorf("%s: Validate = %v", name, err)
		}
	}
	if _, err := ParseVerdict(bytes.ReplaceAll(b, []byte("\n"), []byte("\r\n"))); !errors.Is(err, ErrInvalidVerdict) {
		t.Fatalf("CRLF verdict accepted: %v", err)
	}
}

func cloneCounts(m map[string]int) map[string]int {
	out := map[string]int{}
	for k, v := range m {
		out[k] = v
	}
	return out
}
