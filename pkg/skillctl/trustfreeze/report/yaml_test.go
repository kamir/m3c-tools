package report

// FR-0472: YAML is a second rendering of the same projection, converted from
// the canonical JSON bytes. These tests hold down that it is the same value
// tree in the same order, that two runs give the same bytes, and that a plain
// scalar which a YAML 1.1 reader would resolve as a boolean or a base-60
// number is quoted.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
)

func TestCaptureReportYAMLGolden(t *testing.T) {
	dir := t.TempDir()
	b := writeCapture(t, dir, "cap", trustfreeze.KindCapture, testTime, "24.04", 0)
	r, err := FromBundle(b)
	if err != nil {
		t.Fatal(err)
	}
	got, err := MarshalYAML(r)
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "report_capture.yaml.golden", got)
}

func TestBaselineReportYAMLGolden(t *testing.T) {
	dir := t.TempDir()
	b := writeCapture(t, dir, "base", trustfreeze.KindBaseline, testTime, "24.04", 0)
	r, err := FromBundle(b)
	if err != nil {
		t.Fatal(err)
	}
	got, err := MarshalYAML(r)
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "report_baseline.yaml.golden", got)
}

func TestDiffReportYAMLGolden(t *testing.T) {
	dir := t.TempDir()
	_, _, d, v := scenario(t, dir)
	db := writeDiffBundle(t, dir, d, &v)
	r, err := FromBundle(db)
	if err != nil {
		t.Fatal(err)
	}
	got, err := MarshalYAML(r)
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "report_diff.yaml.golden", got)
}

// TestReportYAMLIsTheSameValueTree: the YAML and the JSON of one report parse
// to the same values. It catches a field the converter drops and a nesting it
// loses.
func TestReportYAMLIsTheSameValueTree(t *testing.T) {
	for _, r := range everyKindOfReport(t) {
		t.Run(string(r.Input.Kind), func(t *testing.T) {
			rawJSON, err := Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			rawYAML, err := MarshalYAML(r)
			if err != nil {
				t.Fatal(err)
			}
			var fromJSON any
			dec := json.NewDecoder(bytes.NewReader(rawJSON))
			dec.UseNumber()
			if err := dec.Decode(&fromJSON); err != nil {
				t.Fatal(err)
			}
			var fromYAML any
			if err := yaml.Unmarshal(rawYAML, &fromYAML); err != nil {
				t.Fatal(err)
			}
			a, b := numbersAsText(fromJSON), numbersAsText(fromYAML)
			if fmt.Sprintf("%#v", a) != fmt.Sprintf("%#v", b) {
				t.Fatalf("the YAML is another value tree than the JSON\n--- json ---\n%#v\n--- yaml ---\n%#v", a, b)
			}
		})
	}
}

// TestReportYAMLKeepsTheKeyOrder: the keys appear in the YAML in the order of
// the JSON document, so two reports stay comparable line by line.
func TestReportYAMLKeepsTheKeyOrder(t *testing.T) {
	for _, r := range everyKindOfReport(t) {
		t.Run(string(r.Input.Kind), func(t *testing.T) {
			rawJSON, err := Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			rawYAML, err := MarshalYAML(r)
			if err != nil {
				t.Fatal(err)
			}
			want := jsonKeyOutline(t, rawJSON)
			got := yamlKeyOutline(t, rawYAML)
			if want != got {
				t.Fatalf("key order differs\n--- json ---\n%s\n--- yaml ---\n%s", want, got)
			}
			if !strings.Contains(want, "schema_version") {
				t.Fatalf("the outline is empty, the test proves nothing:\n%s", want)
			}
		})
	}
}

// TestReportYAMLTwiceTheSameBytes: the converter renders the same report twice
// as the same bytes. Go randomizes the start of every range over a map, also
// inside one process, so the repetitions do see another order.
func TestReportYAMLTwiceTheSameBytes(t *testing.T) {
	for _, r := range everyKindOfReport(t) {
		t.Run(string(r.Input.Kind), func(t *testing.T) {
			first, err := MarshalYAML(r)
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 8; i++ {
				again, err := MarshalYAML(r)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(first, again) {
					t.Fatalf("run %d differs from the first run", i+2)
				}
			}
		})
	}
}

// TestRepeatedRunComparisonSeesAnUnorderedRange is the counter-probe to the
// test above: a renderer that walks a map without sorting must make a
// repeated-run comparison fail. Without this, a green determinism test is a
// hope and not a measurement.
func TestRepeatedRunComparisonSeesAnUnorderedRange(t *testing.T) {
	m := map[string]int{}
	for i := 0; i < 12; i++ {
		m[fmt.Sprintf("k%02d", i)] = i
	}
	unordered := func() string {
		var sb strings.Builder
		for k := range m {
			sb.WriteString(k)
		}
		return sb.String()
	}
	first := unordered()
	for i := 0; i < 100; i++ {
		if unordered() != first {
			return
		}
	}
	t.Fatal("100 unsorted walks over a 12-key map gave the same order every time: the comparison cannot see disorder")
}

// yaml11MustQuote are the scalar forms a YAML 1.1 reader (PyYAML, yaml.v2,
// Ruby Psych) resolves as a boolean, a base-60 number, an octal, a null or a
// timestamp instead of as the string it was. They must never leave the encoder
// as a bare word. The list is the YAML 1.1 type repository plus the forms
// measured on yaml.v3 v3.0.1 in TestYAMLWithoutTheQuotingRuleEmitsBareWords.
var yaml11MustQuote = []string{
	"no", "yes", "on", "off", "y", "n", "N", "Y", "No", "YES", "On", "OFF",
	"true", "false", "True", "FALSE", "1:30", "1:30:00", "1_000", "0755",
	"<<", "=", "3", "007", "null", "~", "", "0x1f", "1e3", ".inf", "2026-09-25",
}

// yaml11PlainIsFine are strings a plain scalar carries safely. They are in the
// fixture so the rule is not allowed to quote everything and call it a day.
var yaml11PlainIsFine = []string{"sha256:ab", "a b", "device/os"}

// TestReportYAMLQuotesYAML11Scalars: every form a YAML 1.1 reader would
// resolve as something other than a string leaves the encoder quoted, form by
// form, as a key and as a value. Without the rule an sshd directive stored as
// "no" is a boolean for such a reader; this test measures the representation,
// which is what the rule controls, and not a round-trip through yaml.v3, whose
// own resolver follows YAML 1.2 and reads the bare word back as a string.
func TestReportYAMLQuotesYAML11Scalars(t *testing.T) {
	attrs := map[string]string{}
	for i, f := range append(append([]string{}, yaml11MustQuote...), yaml11PlainIsFine...) {
		attrs[fmt.Sprintf("k%02d", i)] = f
		// A mapping key resolved as a boolean is the same loss as a value.
		attrs["key:"+f] = f
	}
	raw, err := MarshalYAML(reportWithAttributes(attrs))
	if err != nil {
		t.Fatal(err)
	}
	bare := plainScalars(t, raw)
	var missed []string
	for _, f := range yaml11MustQuote {
		if bare[f] {
			missed = append(missed, strconv.Quote(f))
		}
	}
	if len(missed) > 0 {
		sort.Strings(missed)
		t.Fatalf("%d of %d forms left the encoder as a bare word: %s",
			len(missed), len(yaml11MustQuote), strings.Join(missed, ", "))
	}
	// The values survive a reader that does follow YAML 1.2 as well.
	var tree any
	if err := yaml.Unmarshal(raw, &tree); err != nil {
		t.Fatal(err)
	}
	got := attributesOfFirstArtifact(t, tree)
	if len(got) != len(attrs) {
		t.Fatalf("the attribute map came back with %d keys, want %d", len(got), len(attrs))
	}
	for k, want := range attrs {
		if s, ok := got[k].(string); !ok || s != want {
			t.Fatalf("%s: %q came back as %#v", k, want, got[k])
		}
	}
}

// TestYAMLWithoutTheQuotingRuleEmitsBareWords is the counter-probe: the same
// scalars, emitted without the rule, and the forms that then leave the encoder
// as a bare word, by name. It measures that the check in the test above can
// see the condition at all; a quoting rule that is never shown to be
// load-bearing is decoration.
func TestYAMLWithoutTheQuotingRuleEmitsBareWords(t *testing.T) {
	root := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for i, f := range yaml11MustQuote {
		root.Content = append(root.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: strconv.Itoa(i)},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: f}) // no Style: the rule is off
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{root}}); err != nil {
		t.Fatal(err)
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
	bare := plainScalars(t, buf.Bytes())
	// Measured on yaml.v3 v3.0.1: these nine are the forms its own YAML 1.2
	// resolver considers harmless and therefore writes plain.
	for _, f := range []string{"no", "yes", "on", "off", "y", "n", "N", "Y", "1:30"} {
		if !bare[f] {
			t.Fatalf("without the rule %q was still quoted: the check cannot see what the rule fixes, or yaml.v3 changed its resolver\n%s", f, buf.String())
		}
		if !yamlNeedsQuotes(f) {
			t.Fatalf("the rule does not cover %q", f)
		}
	}
	for _, f := range yaml11PlainIsFine {
		if yamlNeedsQuotes(f) {
			t.Fatalf("the rule quotes %q, which needs no quoting", f)
		}
	}
}

// plainScalars returns the values of every scalar in a YAML document that is
// written as a bare word (no quotes, no block style).
func plainScalars(t *testing.T, raw []byte) map[string]bool {
	t.Helper()
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		if n.Kind == yaml.ScalarNode && n.Style == 0 {
			out[n.Value] = true
		}
		for _, c := range n.Content {
			walk(c)
		}
	}
	walk(&doc)
	return out
}

// reportWithAttributes is a minimal capture report whose single artifact
// carries attrs, for the scalar tests.
func reportWithAttributes(attrs map[string]string) Report {
	return Report{
		SchemaVersion: SchemaReport,
		Input:         Input{Kind: trustfreeze.KindCapture},
		Capture: &CaptureSection{
			Meta: trustfreeze.CaptureMeta{Tool: trustfreeze.CaptureTool},
			Completeness: trustfreeze.Completeness{
				Status: trustfreeze.CompletenessComplete, Required: []string{}, Gaps: []trustfreeze.CompletenessGap{},
			},
			Probes:       []trustfreeze.ProbeSummary{},
			ProbeResults: []trustfreeze.ProbeResult{},
			Artifacts: []trustfreeze.Artifact{{
				ID: "device/os", Type: "os", Scope: "device", Source: "common.identity",
				State: trustfreeze.StateObserved, Attributes: attrs, Sensitivity: trustfreeze.SensitivityPublic,
				Provenance: trustfreeze.Provenance{
					Method: "file", Confidence: trustfreeze.ConfidenceProven,
					ObservedAt: trustfreeze.FormatTime(testTime),
				},
			}},
		},
	}
}

// TestYAMLConverterRefusesAFloat: the canonical form of a report has no
// floating-point number, and the converter says so instead of inventing one.
func TestYAMLConverterRefusesAFloat(t *testing.T) {
	if _, err := yamlFromCanonicalJSON([]byte(`{"a": 1.5}`)); err == nil {
		t.Fatal("a floating-point number was accepted")
	}
	if _, err := yamlFromCanonicalJSON([]byte(`{"a": 1} {"b": 2}`)); err == nil {
		t.Fatal("trailing data after the document was accepted")
	}
	if _, err := yamlFromCanonicalJSON([]byte(`{"a":`)); err == nil {
		t.Fatal("a truncated document was accepted")
	}
}

// --- helpers -----------------------------------------------------------------

// everyKindOfReport returns one report per bundle kind, plus the capture with
// a capabilities document.
func everyKindOfReport(t *testing.T) []Report {
	t.Helper()
	dir := t.TempDir()
	out := []Report{}
	for _, tc := range []struct {
		name string
		kind trustfreeze.Kind
		caps *trustfreeze.CapabilitiesDoc
	}{
		{"cap", trustfreeze.KindCapture, nil},
		{"base", trustfreeze.KindBaseline, nil},
		{"capcaps", trustfreeze.KindCapture, capabilitiesFixture()},
	} {
		b := writeCaptureWith(t, dir, tc.name, tc.kind, testTime, "24.04", 0, tc.caps)
		r, err := FromBundle(b)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	_, _, d, v := scenario(t, dir)
	r, err := FromBundle(writeDiffBundle(t, dir, d, &v))
	if err != nil {
		t.Fatal(err)
	}
	return append(out, r)
}

// numbersAsText replaces every number by its decimal text, so a tree parsed
// from JSON and one parsed from YAML are comparable.
func numbersAsText(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, e := range t {
			out[k] = numbersAsText(e)
		}
		return out
	case map[any]any:
		out := map[string]any{}
		for k, e := range t {
			out[fmt.Sprint(k)] = numbersAsText(e)
		}
		return out
	case []any:
		out := make([]any, 0, len(t))
		for _, e := range t {
			out = append(out, numbersAsText(e))
		}
		return out
	case json.Number:
		return "num:" + t.String()
	case int:
		return "num:" + strconv.Itoa(t)
	case int64:
		return "num:" + strconv.FormatInt(t, 10)
	case uint64:
		return "num:" + strconv.FormatUint(t, 10)
	case float64:
		return "num:" + strconv.FormatFloat(t, 'g', -1, 64)
	}
	return v
}

// jsonKeyOutline lists every mapping key of a JSON document in document order,
// one indented line each.
func jsonKeyOutline(t *testing.T, raw []byte) string {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var sb strings.Builder
	var walk func(depth int) error
	walk = func(depth int) error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		d, isDelim := tok.(json.Delim)
		if !isDelim {
			return nil
		}
		switch d {
		case '{':
			for dec.More() {
				k, err := dec.Token()
				if err != nil {
					return err
				}
				fmt.Fprintf(&sb, "%s%v\n", strings.Repeat("  ", depth), k)
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for dec.More() {
				if err := walk(depth); err != nil {
					return err
				}
			}
		}
		_, err = dec.Token() // the closing delimiter
		return err
	}
	if err := walk(0); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	return sb.String()
}

// yamlKeyOutline lists every mapping key of a YAML document in document order,
// in the same shape as jsonKeyOutline.
func yamlKeyOutline(t *testing.T, raw []byte) string {
	t.Helper()
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	var walk func(n *yaml.Node, depth int)
	walk = func(n *yaml.Node, depth int) {
		switch n.Kind {
		case yaml.DocumentNode:
			for _, c := range n.Content {
				walk(c, depth)
			}
		case yaml.MappingNode:
			for i := 0; i+1 < len(n.Content); i += 2 {
				fmt.Fprintf(&sb, "%s%s\n", strings.Repeat("  ", depth), n.Content[i].Value)
				walk(n.Content[i+1], depth+1)
			}
		case yaml.SequenceNode:
			for _, c := range n.Content {
				walk(c, depth)
			}
		}
	}
	walk(&doc, 0)
	return sb.String()
}

// attributesOfFirstArtifact digs the attribute map of the first artifact out
// of a generic YAML tree.
func attributesOfFirstArtifact(t *testing.T, tree any) map[string]any {
	t.Helper()
	top, ok := tree.(map[string]any)
	if !ok {
		t.Fatalf("the document is not a mapping: %T", tree)
	}
	capture, ok := top["capture"].(map[string]any)
	if !ok {
		t.Fatalf("no capture section: %v", top["capture"])
	}
	arts, ok := capture["artifacts"].([]any)
	if !ok || len(arts) == 0 {
		t.Fatalf("no artifacts: %v", capture["artifacts"])
	}
	first, ok := arts[0].(map[string]any)
	if !ok {
		t.Fatalf("the artifact is not a mapping: %T", arts[0])
	}
	attrs, ok := first["attributes"].(map[string]any)
	if !ok {
		t.Fatalf("the artifact carries no attributes: %v", first["attributes"])
	}
	return attrs
}
