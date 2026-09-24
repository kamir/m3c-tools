package compare

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
)

// driftFixture changes the current capture in every way compare knows: an
// attribute change (os_version, kernel_release), a field change, an added and
// a removed artifact, a confidence change, a transition to and one from
// observed, a non-observed state transition, and an optional probe that
// timed out.
func driftFixture(at time.Time) fixture {
	f := baseFixture(at, 3)
	f.arts[0].Attributes["os_version"] = "24.10"
	f.arts[0].Attributes["kernel_release"] = "6.11.0-8-generic"
	f.arts[1].Provenance.Confidence = trustfreeze.ConfidenceCorroborated // device/host
	f.arts[2].State = trustfreeze.StateResolved                          // runtime/skillctl: observed -> resolved
	f.arts[3].State = trustfreeze.StateObserved                          // runtime/python: declared -> observed
	f.arts[3].Type = "interpreter"
	f.arts = append(f.arts,
		artifact("runtime/node", "runtime", trustfreeze.StateResolved, trustfreeze.ConfidenceReported, trustfreeze.FormatTime(at), map[string]string{"version": "22.4.0"}),
	)
	f.results = append(f.results, probeResult("common.git", trustfreeze.StatusTimeout, "deadline exceeded", at, 5000))
	return f
}

func driftBaseline(at time.Time) fixture {
	f := baseFixture(at, 0)
	f.arts = append(f.arts,
		artifact("runtime/java", "runtime", trustfreeze.StateDeclared, trustfreeze.ConfidenceReported, trustfreeze.FormatTime(at), map[string]string{"version": "21"}),
		artifact("runtime/go", "runtime", trustfreeze.StateDeclared, trustfreeze.ConfidenceReported, trustfreeze.FormatTime(at), map[string]string{"version": "1.26.6"}),
	)
	return f
}

// TF04-R3: every change kind is distinguishable; golden pins the diff bytes.
func TestCompareAllKindsGolden(t *testing.T) {
	bl := driftBaseline(testTime)
	cur := driftFixture(testTime.Add(3 * time.Hour))
	// runtime/go goes from declared to resolved: a state change that neither
	// starts nor ends at observed.
	cur.arts = append(cur.arts, artifact("runtime/go", "runtime", trustfreeze.StateResolved, trustfreeze.ConfidenceReported, trustfreeze.FormatTime(cur.at), map[string]string{"version": "1.26.6"}))
	d := mustCompare(t, memBundle(t, trustfreeze.KindBaseline, bl), memBundle(t, trustfreeze.KindCapture, cur))

	want := []string{
		"added:runtime/node",
		"removed:runtime/java",
		"changed:device/os",
		"changed:runtime/go",
		"changed:runtime/python",
		"confidence_changed:device/host",
		"became_effective:runtime/python",
		"became_ineffective:runtime/skillctl",
		"collection_gap:common.git",
	}
	if got := kinds(d); !slices.Equal(got, want) {
		t.Fatalf("changes\n got %q\nwant %q", got, want)
	}
	byKey := map[string]Change{}
	for _, c := range d.Changes {
		byKey[string(c.Kind)+":"+c.ArtifactID+c.ProbeID] = c
	}
	osChange := byKey["changed:device/os"]
	if !slices.Equal(osChange.ChangedAttributes, []string{"kernel_release", "os_version"}) || len(osChange.ChangedFields) != 0 {
		t.Fatalf("device/os change = %+v", osChange)
	}
	if osChange.BeforeDigest == osChange.AfterDigest || !strings.HasPrefix(osChange.BeforeDigest, "sha256:") {
		t.Fatalf("device/os digests = %q %q", osChange.BeforeDigest, osChange.AfterDigest)
	}
	if c := byKey["changed:runtime/go"]; !slices.Equal(c.ChangedFields, []string{"state"}) || c.BeforeDigest != c.AfterDigest {
		t.Fatalf("runtime/go change = %+v", c)
	}
	if c := byKey["changed:runtime/python"]; !slices.Equal(c.ChangedFields, []string{"type"}) {
		t.Fatalf("runtime/python change = %+v", c)
	}
	gap := byKey["collection_gap:common.git"].Gap
	if gap == nil || gap.Required || gap.Status != trustfreeze.StatusTimeout || gap.Cause != trustfreeze.GapNotCaptured || gap.Reason != "deadline exceeded" {
		t.Fatalf("gap = %+v", gap)
	}
	// Attribute values never reach the diff.
	b := mustFile(t, d)
	for _, v := range []string{"24.10", "24.04", "host-a.example", "6.11.0-8-generic", "22.4.0"} {
		if bytes.Contains(b, []byte(v)) {
			t.Errorf("diff contains attribute value %q", v)
		}
	}
	checkGolden(t, "diff_all_kinds.golden", b)
}

// TF04-R9: identical inputs give byte-identical diffs, also when the bundles
// are written to and read from different directories.
func TestCompareIdenticalInputsByteIdentical(t *testing.T) {
	var outs [][]byte
	for i := 0; i < 3; i++ {
		d := mustCompare(t, memBundle(t, trustfreeze.KindBaseline, driftBaseline(testTime)), memBundle(t, trustfreeze.KindCapture, driftFixture(testTime.Add(time.Hour))))
		outs = append(outs, mustFile(t, d))
	}
	for i := 0; i < 2; i++ {
		dir := t.TempDir()
		bl := diskBundle(t, dir, "baseline", trustfreeze.KindBaseline, driftBaseline(testTime))
		cur := diskBundle(t, dir, "current", trustfreeze.KindCapture, driftFixture(testTime.Add(time.Hour)))
		outs = append(outs, mustFile(t, mustCompare(t, bl, cur)))
	}
	for i := 1; i < 3; i++ {
		if !bytes.Equal(outs[0], outs[i]) {
			t.Fatalf("in-memory run %d differs", i)
		}
	}
	if !bytes.Equal(outs[3], outs[4]) {
		t.Fatalf("on-disk runs differ:\n%s\n---\n%s", outs[3], outs[4])
	}
	// Both paths see the same changes; only the input digests differ.
	a, _ := ParseDiff(outs[0])
	b, _ := ParseDiff(outs[3])
	if !slices.Equal(kinds(a), kinds(b)) {
		t.Fatalf("in-memory %q vs on-disk %q", kinds(a), kinds(b))
	}
}

// TF04-AC1: scan time, durations, pid and uptime cause no drift. The planted
// control proves the same comparison does see a real change.
func TestCompareVolatileValuesCauseNoDrift(t *testing.T) {
	bl := memBundle(t, trustfreeze.KindBaseline, baseFixture(testTime, 0))
	later := baseFixture(testTime.Add(26*time.Hour+17*time.Second+123456789), 9)
	cur := memBundle(t, trustfreeze.KindCapture, later)
	if bl.Capture.Capture.StartedAt == cur.Capture.Capture.StartedAt || bl.Manifest.ContentDigest == cur.Manifest.ContentDigest {
		t.Fatal("fixture error: the two captures must differ in their volatile values")
	}
	d := mustCompare(t, bl, cur)
	if len(d.Changes) != 0 {
		t.Fatalf("volatile values caused drift: %q", kinds(d))
	}
	for k, n := range d.Counts {
		if n != 0 {
			t.Fatalf("count %s = %d", k, n)
		}
	}

	later.arts[2].Attributes["version"] = "0.0.1-test" // planted control
	d = mustCompare(t, bl, memBundle(t, trustfreeze.KindCapture, later))
	if got := kinds(d); !slices.Equal(got, []string{"changed:runtime/skillctl"}) {
		t.Fatalf("control: %q", got)
	}
	if !slices.Equal(d.Changes[0].ChangedAttributes, []string{"version"}) {
		t.Fatalf("control attributes = %q", d.Changes[0].ChangedAttributes)
	}
}

// TF04-AC7: the order of the input artifacts and probes does not change the
// diff bytes (and therefore not its digest).
func TestCompareInputOrderIndependent(t *testing.T) {
	bl := memBundle(t, trustfreeze.KindBaseline, driftBaseline(testTime))
	cur := memBundle(t, trustfreeze.KindCapture, driftFixture(testTime))
	want := mustFile(t, mustCompare(t, bl, cur))
	wantDigest, err := DiffDigest(mustCompare(t, bl, cur))
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(bl.State.Artifacts)
	slices.Reverse(cur.Capture.Probes)
	n := 0
	permute(cur.State.Artifacts, 0, func() {
		n++
		d := mustCompare(t, bl, cur)
		if got := mustFile(t, d); !bytes.Equal(got, want) {
			t.Fatalf("permutation %d changed the diff", n)
		}
		if got, _ := DiffDigest(d); got != wantDigest {
			t.Fatalf("permutation %d changed the digest", n)
		}
	})
	if n != 120 {
		t.Fatalf("ran %d permutations, want 120", n)
	}
}

func permute(a []trustfreeze.Artifact, k int, visit func()) {
	if k == len(a) {
		visit()
		return
	}
	for i := k; i < len(a); i++ {
		a[k], a[i] = a[i], a[k]
		permute(a, k+1, visit)
		a[k], a[i] = a[i], a[k]
	}
}

// TF04-AC5 and TF04-AC6: collection gap rules, MC/DC over "required" and
// "captured". Flipping either condition alone flips the outcome.
func TestCompareCollectionGapMCDC(t *testing.T) {
	cases := []struct {
		name     string
		required bool
		captured bool
		wantGap  bool
	}{
		{"required captured", true, true, false},
		{"required not captured", true, false, true},
		{"optional captured", false, true, false},
		{"optional not captured", false, false, true},
	}
	bl := memBundle(t, trustfreeze.KindBaseline, baseFixture(testTime, 0))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := baseFixture(testTime, 0)
			st := trustfreeze.StatusCaptured
			if !tc.captured {
				st = trustfreeze.StatusPermissionDenied
			}
			f.results = append(f.results, probeResult("common.extra", st, "", testTime, 1))
			if tc.required {
				f.required = append(f.required, "common.extra")
			}
			d := mustCompare(t, bl, memBundle(t, trustfreeze.KindCapture, f))
			var gaps []Change
			for _, c := range d.Changes {
				if c.Kind == ChangeCollectionGap {
					gaps = append(gaps, c)
				}
			}
			if !tc.wantGap {
				if len(gaps) != 0 {
					t.Fatalf("unexpected gaps %+v", gaps)
				}
				return
			}
			if len(gaps) != 1 || gaps[0].ProbeID != "common.extra" {
				t.Fatalf("gaps = %+v", gaps)
			}
			g := gaps[0].Gap
			if g.Required != tc.required || g.Status != trustfreeze.StatusPermissionDenied || g.Cause != trustfreeze.GapNotCaptured {
				t.Fatalf("gap = %+v", g)
			}
		})
	}
}

// Every other way a probe can be missing is a gap with its own cause.
func TestCompareGapCauses(t *testing.T) {
	bl := memBundle(t, trustfreeze.KindBaseline, baseFixture(testTime, 0))
	cases := []struct {
		name   string
		mutate func(*fixture)
		want   Gap
	}{
		{"required probe without result", func(f *fixture) {
			f.results = nil
		}, Gap{Required: true, Cause: trustfreeze.GapNoResult}},
		{"duplicate result", func(f *fixture) {
			f.results = append(f.results, probeResult("common.identity", trustfreeze.StatusFailed, "", testTime, 1))
		}, Gap{Required: true, Cause: trustfreeze.GapDuplicateResult}},
		{"not applicable without reason", func(f *fixture) {
			f.results[0] = probeResult("common.identity", trustfreeze.StatusNotApplicable, "", testTime, 1)
		}, Gap{Required: true, Status: trustfreeze.StatusNotApplicable, Cause: trustfreeze.GapNotApplicableNoReason}},
		// SPEC-0469 section 4.2: not applicable with a reason stays visible,
		// with its own cause, so a policy can rate it apart from a failure.
		{"not applicable with reason", func(f *fixture) {
			f.results[0] = probeResult("common.identity", trustfreeze.StatusNotApplicable, "no such feature", testTime, 1)
		}, Gap{Required: true, Status: trustfreeze.StatusNotApplicable, Cause: trustfreeze.GapNotApplicable, Reason: "no such feature"}},
		{"partial", func(f *fixture) {
			f.results[0] = probeResult("common.identity", trustfreeze.StatusPartial, "field_missing", testTime, 1)
		}, Gap{Required: true, Status: trustfreeze.StatusPartial, Cause: trustfreeze.GapNotCaptured, Reason: "field_missing"}},
		{"unsupported optional probe", func(f *fixture) {
			f.results = append(f.results, probeResult("linux.packages", trustfreeze.StatusUnsupported, trustfreeze.ReasonNotImplemented, testTime, 0))
		}, Gap{Required: false, Status: trustfreeze.StatusUnsupported, Cause: trustfreeze.GapNotCaptured, Reason: trustfreeze.ReasonNotImplemented}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := baseFixture(testTime, 0)
			tc.mutate(&f)
			d := mustCompare(t, bl, memBundle(t, trustfreeze.KindCapture, f))
			var got []Gap
			for _, c := range d.Changes {
				if c.Kind == ChangeCollectionGap {
					got = append(got, *c.Gap)
				}
			}
			if len(got) != 1 || got[0] != tc.want {
				t.Fatalf("gaps = %+v, want [%+v]", got, tc.want)
			}
		})
	}
}

func TestCompareStateAndConfidenceTransitions(t *testing.T) {
	bl := baseFixture(testTime, 0)
	cur := baseFixture(testTime, 0)
	cur.arts[2].State = trustfreeze.StateInferred // runtime/skillctl observed -> inferred
	cur.arts[3].State = trustfreeze.StateObserved // runtime/python declared -> observed
	cur.arts[0].Provenance.Confidence = trustfreeze.ConfidenceReported
	d := mustCompare(t, memBundle(t, trustfreeze.KindBaseline, bl), memBundle(t, trustfreeze.KindCapture, cur))
	want := []string{"confidence_changed:device/os", "became_effective:runtime/python", "became_ineffective:runtime/skillctl"}
	if got := kinds(d); !slices.Equal(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
	c := d.Changes[1]
	if c.BeforeState != trustfreeze.StateDeclared || c.AfterState != trustfreeze.StateObserved {
		t.Fatalf("became_effective = %+v", c)
	}
	c = d.Changes[0]
	if c.BeforeConfidence != trustfreeze.ConfidenceProven || c.AfterConfidence != trustfreeze.ConfidenceReported {
		t.Fatalf("confidence_changed = %+v", c)
	}
}

// Compare never modifies its inputs.
func TestCompareDoesNotMutateInputs(t *testing.T) {
	bl := memBundle(t, trustfreeze.KindBaseline, driftBaseline(testTime))
	cur := memBundle(t, trustfreeze.KindCapture, driftFixture(testTime))
	slices.Reverse(cur.State.Artifacts)
	before := [][]byte{mustFile(t, bl.State), mustFile(t, cur.State), mustFile(t, cur.Capture)}
	mustCompare(t, bl, cur)
	after := [][]byte{mustFile(t, bl.State), mustFile(t, cur.State), mustFile(t, cur.Capture)}
	for i := range before {
		if !bytes.Equal(before[i], after[i]) {
			t.Fatalf("input %d changed", i)
		}
	}
}

func TestCompareRejectsUnverifiedOrWrongInputs(t *testing.T) {
	good := func() (*trustfreeze.Bundle, *trustfreeze.Bundle) {
		return memBundle(t, trustfreeze.KindBaseline, baseFixture(testTime, 0)), memBundle(t, trustfreeze.KindCapture, baseFixture(testTime, 1))
	}
	cases := []struct {
		name   string
		mutate func(bl, cur *trustfreeze.Bundle) (*trustfreeze.Bundle, *trustfreeze.Bundle)
		want   error
	}{
		{"nil baseline", func(bl, cur *trustfreeze.Bundle) (*trustfreeze.Bundle, *trustfreeze.Bundle) { return nil, cur }, ErrNotVerified},
		{"integrity failed", func(bl, cur *trustfreeze.Bundle) (*trustfreeze.Bundle, *trustfreeze.Bundle) {
			cur.Integrity.OK = false
			return bl, cur
		}, ErrNotVerified},
		{"integrity digest differs", func(bl, cur *trustfreeze.Bundle) (*trustfreeze.Bundle, *trustfreeze.Bundle) {
			bl.Integrity.ContentDigest = cur.Manifest.ContentDigest
			return bl, cur
		}, ErrNotVerified},
		{"capture used as baseline", func(bl, cur *trustfreeze.Bundle) (*trustfreeze.Bundle, *trustfreeze.Bundle) {
			return cur, cur
		}, ErrInputKind},
		{"diff kind as current", func(bl, cur *trustfreeze.Bundle) (*trustfreeze.Bundle, *trustfreeze.Bundle) {
			cur.Manifest.Kind = trustfreeze.KindDiff
			return bl, cur
		}, ErrInputKind},
		{"no capture document", func(bl, cur *trustfreeze.Bundle) (*trustfreeze.Bundle, *trustfreeze.Bundle) {
			cur.Capture = nil
			return bl, cur
		}, ErrInvalidInput},
		{"duplicate artifact id", func(bl, cur *trustfreeze.Bundle) (*trustfreeze.Bundle, *trustfreeze.Bundle) {
			cur.State.Artifacts = append(cur.State.Artifacts, cur.State.Artifacts[0])
			return bl, cur
		}, ErrInvalidInput},
		{"absolute artifact id", func(bl, cur *trustfreeze.Bundle) (*trustfreeze.Bundle, *trustfreeze.Bundle) {
			cur.State.Artifacts[0].ID = "/home/alice/x"
			return bl, cur
		}, ErrInvalidInput},
		{"unknown state", func(bl, cur *trustfreeze.Bundle) (*trustfreeze.Bundle, *trustfreeze.Bundle) {
			bl.State.Artifacts[0].State = "active"
			return bl, cur
		}, ErrInvalidInput},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bl, cur := tc.mutate(good())
			_, err := Compare(context.Background(), bl, cur, CompareOptions{})
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	bl, cur := good()
	if _, err := Compare(context.Background(), bl, cur, CompareOptions{RuleSetID: "trust-freeze/normalize/v0"}); !errors.Is(err, ErrUnknownRuleSet) {
		t.Fatalf("unknown rule set: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Compare(ctx, bl, cur, CompareOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context: %v", err)
	}
}

// A baseline may be compared with a newer baseline; the current side keeps
// its kind in the diff.
func TestCompareBaselineAgainstBaseline(t *testing.T) {
	d := mustCompare(t, memBundle(t, trustfreeze.KindBaseline, baseFixture(testTime, 0)), memBundle(t, trustfreeze.KindBaseline, baseFixture(testTime, 1)))
	if d.Current.Kind != trustfreeze.KindBaseline || len(d.Changes) != 0 {
		t.Fatalf("diff = %+v", d)
	}
}

func TestParseDiffRoundTripAndTamper(t *testing.T) {
	d := mustCompare(t, memBundle(t, trustfreeze.KindBaseline, driftBaseline(testTime)), memBundle(t, trustfreeze.KindCapture, driftFixture(testTime)))
	b := mustFile(t, d)
	back, err := ParseDiff(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mustFile(t, back), b) {
		t.Fatal("round trip changed the bytes")
	}
	tamper := []struct {
		name   string
		mutate func(*Diff)
	}{
		{"schema", func(d *Diff) { d.SchemaVersion = "trust-freeze/diff/v2" }},
		{"kind", func(d *Diff) { d.Kind = trustfreeze.KindCapture }},
		{"rule set digest", func(d *Diff) { d.Normalization.Digest = trustfreeze.Digest(nil) }},
		{"rule set id", func(d *Diff) { d.Normalization.ID = "trust-freeze/normalize/v9" }},
		{"order", func(d *Diff) { d.Changes[0], d.Changes[1] = d.Changes[1], d.Changes[0] }},
		{"duplicate", func(d *Diff) { d.Changes[1] = d.Changes[0] }},
		{"counts", func(d *Diff) { d.Counts[string(ChangeAdded)]++ }},
		{"dropped change", func(d *Diff) { d.Changes = d.Changes[1:] }},
		{"gap without probe", func(d *Diff) { d.Changes[len(d.Changes)-1].ProbeID = "" }},
		{"baseline kind", func(d *Diff) { d.Baseline.Kind = trustfreeze.KindCapture }},
		{"nil changes", func(d *Diff) { d.Changes = nil }},
	}
	for _, tc := range tamper {
		t.Run(tc.name, func(t *testing.T) {
			var c Diff
			if err := trustfreeze.UnmarshalStrict(b, &c); err != nil {
				t.Fatal(err)
			}
			tc.mutate(&c)
			if err := c.Validate(); !errors.Is(err, ErrInvalidDiff) {
				t.Fatalf("Validate = %v, want ErrInvalidDiff", err)
			}
		})
	}
	if _, err := ParseDiff(bytes.ReplaceAll(b, []byte("\n"), []byte("\r\n"))); !errors.Is(err, ErrInvalidDiff) {
		t.Fatalf("CRLF diff accepted: %v", err)
	}
	if _, err := ParseDiff(bytes.Replace(b, []byte(`"kind": "diff"`), []byte(`"kind": "diff", "extra": 1`), 1)); !errors.Is(err, ErrInvalidDiff) {
		t.Fatalf("unknown field accepted: %v", err)
	}
}

func TestChangeKindStrict(t *testing.T) {
	if got := ChangeKinds(); len(got) != 10 || got[0] != ChangeSubjectChanged || got[9] != ChangeCollectionGap {
		t.Fatalf("ChangeKinds = %q", got)
	}
	for _, s := range []string{"", "Added", "added ", "drift"} {
		if _, err := ParseChangeKind(s); !errors.Is(err, trustfreeze.ErrInvalidEnum) {
			t.Errorf("ParseChangeKind(%q) = %v", s, err)
		}
	}
	var k ChangeKind
	for _, in := range []string{`null`, `1`, `"nope"`, `""`} {
		if err := k.UnmarshalJSON([]byte(in)); err == nil {
			t.Errorf("UnmarshalJSON(%s) accepted", in)
		}
	}
	if _, err := ChangeKind("").MarshalText(); err == nil {
		t.Error("empty kind marshaled")
	}
}
