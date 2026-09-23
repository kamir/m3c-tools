package trustfreeze

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// enumCase describes one closed enum for the shared strictness test.
type enumCase struct {
	name   string
	values []string
	decode func([]byte) (string, error)
	text   func([]byte) error
	encode func(string) error
}

func enumCases() []enumCase {
	strs := func(n int, at func(int) string) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = at(i)
		}
		return out
	}
	return []enumCase{
		{
			name:   "ProbeStatus",
			values: strs(len(ProbeStatuses()), func(i int) string { return string(ProbeStatuses()[i]) }),
			decode: func(b []byte) (string, error) { var v ProbeStatus; err := json.Unmarshal(b, &v); return string(v), err },
			text:   func(b []byte) error { var v ProbeStatus; return v.UnmarshalText(b) },
			encode: func(s string) error { _, err := ProbeStatus(s).MarshalText(); return err },
		},
		{
			name:   "EvidenceState",
			values: strs(len(EvidenceStates()), func(i int) string { return string(EvidenceStates()[i]) }),
			decode: func(b []byte) (string, error) {
				var v EvidenceState
				err := json.Unmarshal(b, &v)
				return string(v), err
			},
			text:   func(b []byte) error { var v EvidenceState; return v.UnmarshalText(b) },
			encode: func(s string) error { _, err := EvidenceState(s).MarshalText(); return err },
		},
		{
			name:   "Confidence",
			values: strs(len(Confidences()), func(i int) string { return string(Confidences()[i]) }),
			decode: func(b []byte) (string, error) { var v Confidence; err := json.Unmarshal(b, &v); return string(v), err },
			text:   func(b []byte) error { var v Confidence; return v.UnmarshalText(b) },
			encode: func(s string) error { _, err := Confidence(s).MarshalText(); return err },
		},
		{
			name:   "Severity",
			values: strs(len(Severities()), func(i int) string { return string(Severities()[i]) }),
			decode: func(b []byte) (string, error) { var v Severity; err := json.Unmarshal(b, &v); return string(v), err },
			text:   func(b []byte) error { var v Severity; return v.UnmarshalText(b) },
			encode: func(s string) error { _, err := Severity(s).MarshalText(); return err },
		},
		{
			name:   "Sensitivity",
			values: []string{"public", "internal", "confidential"},
			decode: func(b []byte) (string, error) { var v Sensitivity; err := json.Unmarshal(b, &v); return string(v), err },
			text:   func(b []byte) error { var v Sensitivity; return v.UnmarshalText(b) },
			encode: func(s string) error { _, err := Sensitivity(s).MarshalText(); return err },
		},
		{
			name:   "AttributeClass",
			values: []string{"policy", "sensitive"},
			decode: func(b []byte) (string, error) {
				var v AttributeClass
				err := json.Unmarshal(b, &v)
				return string(v), err
			},
			text:   func(b []byte) error { var v AttributeClass; return v.UnmarshalText(b) },
			encode: func(s string) error { _, err := AttributeClass(s).MarshalText(); return err },
		},
		{
			name:   "Privilege",
			values: []string{"user", "elevated"},
			decode: func(b []byte) (string, error) { var v Privilege; err := json.Unmarshal(b, &v); return string(v), err },
			text:   func(b []byte) error { var v Privilege; return v.UnmarshalText(b) },
			encode: func(s string) error { _, err := Privilege(s).MarshalText(); return err },
		},
		{
			name:   "CompletenessStatus",
			values: []string{"complete", "incomplete"},
			decode: func(b []byte) (string, error) {
				var v CompletenessStatus
				err := json.Unmarshal(b, &v)
				return string(v), err
			},
			text:   func(b []byte) error { var v CompletenessStatus; return v.UnmarshalText(b) },
			encode: func(s string) error { _, err := CompletenessStatus(s).MarshalText(); return err },
		},
		{
			name:   "Kind",
			values: []string{"capture", "baseline", "diff"},
			decode: func(b []byte) (string, error) { var v Kind; err := json.Unmarshal(b, &v); return string(v), err },
			text:   func(b []byte) error { var v Kind; return v.UnmarshalText(b) },
			encode: func(s string) error { _, err := Kind(s).MarshalText(); return err },
		},
	}
}

// TestEnumsAreClosed: every enum accepts exactly its values and rejects
// everything else on decode and on encode (SPEC-0466 R6).
func TestEnumsAreClosed(t *testing.T) {
	for _, ec := range enumCases() {
		t.Run(ec.name, func(t *testing.T) {
			for _, v := range ec.values {
				got, err := ec.decode([]byte(`"` + v + `"`))
				if err != nil || got != v {
					t.Fatalf("decode %q = %q, %v", v, got, err)
				}
				if err := ec.text([]byte(v)); err != nil {
					t.Fatalf("UnmarshalText %q: %v", v, err)
				}
				if err := ec.encode(v); err != nil {
					t.Fatalf("MarshalText %q: %v", v, err)
				}
			}
			first := ec.values[0]
			badJSON := []string{
				`""`, `null`, `1`, `true`, `{}`, `[]`,
				`"` + strings.ToUpper(first) + `"`,
				`" ` + first + `"`,
				`"` + first + ` "`,
				`"` + first + `\u0000"`,
				`"unknown_value"`,
			}
			for _, in := range badJSON {
				if got, err := ec.decode([]byte(in)); err == nil {
					t.Errorf("decode %s accepted as %q", in, got)
				}
			}
			for _, in := range []string{"", strings.ToUpper(first), "unknown_value"} {
				if err := ec.text([]byte(in)); !errors.Is(err, ErrInvalidEnum) {
					t.Errorf("UnmarshalText %q = %v, want ErrInvalidEnum", in, err)
				}
				if err := ec.encode(in); !errors.Is(err, ErrInvalidEnum) {
					t.Errorf("MarshalText %q = %v, want ErrInvalidEnum", in, err)
				}
			}
		})
	}
}

// TestTF01AC6PermissionDeniedNeverCaptured: permission_denied cannot be
// deserialized as captured and never yields a complete capture
// (SPEC-0466 TF01-AC6).
func TestTF01AC6PermissionDeniedNeverCaptured(t *testing.T) {
	var r ProbeResult
	raw := `{"probe_id":"linux.firewall","probe_version":"1","status":"permission_denied","support":{"available":true},"started_at":"2026-01-02T03:04:05Z","duration_ms":1,"privilege":"user"}`
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatal(err)
	}
	if r.Status != StatusPermissionDenied || r.Status == StatusCaptured {
		t.Fatalf("status = %q, want permission_denied", r.Status)
	}
	for _, spoof := range []string{`"Captured"`, `"captured "`, `"CAPTURED"`, `null`, `""`} {
		in := strings.Replace(raw, `"permission_denied"`, spoof, 1)
		var x ProbeResult
		if err := json.Unmarshal([]byte(in), &x); err == nil {
			t.Errorf("status %s decoded as %q", spoof, x.Status)
		}
	}
	c := ComputeCompleteness([]string{"linux.firewall"}, []ProbeResult{r})
	if c.Status != CompletenessIncomplete {
		t.Fatalf("completeness = %s, want incomplete", c.Status)
	}
	if len(c.Gaps) != 1 || c.Gaps[0].Status != StatusPermissionDenied || c.Gaps[0].Reason != GapNotCaptured {
		t.Fatalf("gaps = %+v", c.Gaps)
	}
	// A capture.json that declares "complete" next to the permission_denied
	// probe is rejected by the recomputation.
	doc := sampleCaptureDoc([]string{"linux.firewall"}, []ProbeResult{r})
	doc.Completeness = Completeness{Status: CompletenessComplete, Required: []string{"linux.firewall"}, Gaps: []CompletenessGap{}}
	if err := CheckCompleteness(doc); !errors.Is(err, ErrCompletenessMismatch) {
		t.Fatalf("CheckCompleteness = %v, want ErrCompletenessMismatch", err)
	}
}

// TestComputeCompleteness covers SPEC-0466 R6 case by case.
func TestComputeCompleteness(t *testing.T) {
	res := func(id string, s ProbeStatus, reason string) ProbeResult {
		return ProbeResult{ProbeID: id, Status: s, Reason: reason}
	}
	cases := []struct {
		name     string
		required []string
		results  []ProbeResult
		status   CompletenessStatus
		gaps     []CompletenessGap
	}{
		{"all captured", []string{"a", "b"}, []ProbeResult{res("a", StatusCaptured, ""), res("b", StatusCaptured, "")}, CompletenessComplete, nil},
		{"no required probes", nil, []ProbeResult{res("a", StatusFailed, "")}, CompletenessComplete, nil},
		{"optional failure ignored", []string{"a"}, []ProbeResult{res("a", StatusCaptured, ""), res("b", StatusTimeout, "")}, CompletenessComplete, nil},
		{"not_applicable with reason", []string{"a"}, []ProbeResult{res("a", StatusNotApplicable, "no such feature on this OS")}, CompletenessComplete, nil},
		{"not_applicable without reason", []string{"a"}, []ProbeResult{res("a", StatusNotApplicable, "  ")}, CompletenessIncomplete, []CompletenessGap{{ProbeID: "a", Status: StatusNotApplicable, Reason: GapNotApplicableNoReason}}},
		{"missing result", []string{"a"}, nil, CompletenessIncomplete, []CompletenessGap{{ProbeID: "a", Reason: GapNoResult}}},
		{"duplicate result", []string{"a"}, []ProbeResult{res("a", StatusCaptured, ""), res("a", StatusCaptured, "")}, CompletenessIncomplete, []CompletenessGap{{ProbeID: "a", Reason: GapDuplicateResult}}},
		{"invalid status", []string{"a"}, []ProbeResult{res("a", "Captured", "")}, CompletenessIncomplete, []CompletenessGap{{ProbeID: "a", Reason: GapInvalidStatus}}},
		{"partial", []string{"a"}, []ProbeResult{res("a", StatusPartial, "")}, CompletenessIncomplete, []CompletenessGap{{ProbeID: "a", Status: StatusPartial, Reason: GapNotCaptured}}},
		{"timeout", []string{"a"}, []ProbeResult{res("a", StatusTimeout, "")}, CompletenessIncomplete, []CompletenessGap{{ProbeID: "a", Status: StatusTimeout, Reason: GapNotCaptured}}},
		{"failed", []string{"a"}, []ProbeResult{res("a", StatusFailed, "")}, CompletenessIncomplete, []CompletenessGap{{ProbeID: "a", Status: StatusFailed, Reason: GapNotCaptured}}},
		{"unsupported not_implemented", []string{"a"}, []ProbeResult{res("a", StatusUnsupported, ReasonNotImplemented)}, CompletenessIncomplete, []CompletenessGap{{ProbeID: "a", Status: StatusUnsupported, Reason: GapNotCaptured}}},
		{"unavailable", []string{"a"}, []ProbeResult{res("a", StatusUnavailable, "tool missing")}, CompletenessIncomplete, []CompletenessGap{{ProbeID: "a", Status: StatusUnavailable, Reason: GapNotCaptured}}},
		{"gaps sorted, required deduped", []string{"b", "a", "b"}, nil, CompletenessIncomplete, []CompletenessGap{{ProbeID: "a", Reason: GapNoResult}, {ProbeID: "b", Reason: GapNoResult}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := ComputeCompleteness(tc.required, tc.results)
			if c.Status != tc.status {
				t.Fatalf("status = %s, want %s", c.Status, tc.status)
			}
			want := tc.gaps
			if want == nil {
				want = []CompletenessGap{}
			}
			if !reflect.DeepEqual(c.Gaps, want) {
				t.Fatalf("gaps = %+v, want %+v", c.Gaps, want)
			}
			if c.Required == nil {
				t.Fatal("Required must be non-nil so it encodes as []")
			}
		})
	}
}

func TestSeverityRank(t *testing.T) {
	prev := 0
	for _, s := range Severities() {
		if s.Rank() <= prev {
			t.Fatalf("%s rank %d not above %d", s, s.Rank(), prev)
		}
		prev = s.Rank()
	}
	if SeverityCritical.Rank() != 5 || Severity("bogus").Rank() != 0 {
		t.Fatal("rank bounds changed")
	}
}

func TestSchemaIDs(t *testing.T) {
	want := map[string]string{
		SchemaCapture: "trust-freeze/capture/v1", SchemaBaseline: "trust-freeze/baseline/v1",
		SchemaDiff: "trust-freeze/diff/v1", SchemaManifest: "trust-freeze/manifest/v1",
		SchemaApproval: "trust-freeze/approval/v1", SchemaSignature: "trust-freeze/signature/v1",
		SchemaProfile: "trust-freeze/profile/v1", SchemaPolicy: "trust-freeze/policy/v1",
		SchemaTrustPolicy: "trust-freeze/trust-policy/v1",
	}
	for got, w := range want {
		if got != w || !KnownSchema(got) {
			t.Errorf("schema %q, want %q (known=%v)", got, w, KnownSchema(got))
		}
	}
	if KnownSchema("trust-freeze/capture/v2") {
		t.Fatal("v2 must be unknown")
	}
	if err := CheckSchema("trust-freeze/capture/v2", SchemaCapture); !errors.Is(err, ErrUnknownSchema) {
		t.Fatalf("CheckSchema = %v", err)
	}
	if _, err := ParseKind("snapshot"); !errors.Is(err, ErrUnknownKind) {
		t.Fatalf("ParseKind = %v", err)
	}
}

// TestModelHasNoFloats walks every model type and fails on a float field
// (SPEC-0466 R5).
func TestModelHasNoFloats(t *testing.T) {
	seen := map[reflect.Type]bool{}
	var walk func(rt reflect.Type, at string)
	walk = func(rt reflect.Type, at string) {
		if seen[rt] {
			return
		}
		seen[rt] = true
		switch rt.Kind() {
		case reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128:
			t.Errorf("floating-point type at %s", at)
		case reflect.Pointer, reflect.Slice, reflect.Array:
			walk(rt.Elem(), at+"[]")
		case reflect.Map:
			if rt.Key().Kind() != reflect.String {
				t.Errorf("non-string map key at %s", at)
			}
			walk(rt.Elem(), at+"{}")
		case reflect.Interface:
			t.Errorf("interface field at %s would allow floats", at)
		case reflect.Struct:
			for i := 0; i < rt.NumField(); i++ {
				f := rt.Field(i)
				walk(f.Type, at+"."+f.Name)
			}
		}
	}
	for _, v := range []any{Manifest{}, CaptureDoc{}, ProbeResult{}, StateDoc{}, Capability{}, Finding{}, IntegrityResult{}} {
		walk(reflect.TypeOf(v), reflect.TypeOf(v).Name())
	}
}

func TestArtifactDigestCoversIdentityAndAttributes(t *testing.T) {
	a := sampleArtifacts()[0]
	base, err := ComputeArtifactDigest(a)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*Artifact){
		"id":        func(x *Artifact) { x.ID = "device/os2" },
		"type":      func(x *Artifact) { x.Type = "os2" },
		"scope":     func(x *Artifact) { x.Scope = "runtime" },
		"attribute": func(x *Artifact) { x.Attributes = map[string]string{"os_name": "Other"} },
	}
	for name, mut := range mutations {
		b := a
		mut(&b)
		if d, _ := ComputeArtifactDigest(b); d == base {
			t.Errorf("mutating %s did not change the digest", name)
		}
	}
	c := a
	c.State = StateDeclared
	c.Provenance.ObservedAt = "2027-01-01T00:00:00Z"
	if d, _ := ComputeArtifactDigest(c); d != base {
		t.Error("state and provenance must not change the content digest")
	}
}

// TestAttributeClassesAreValidated: a class for an attribute that does not
// exist would exempt that name wherever the redaction pass meets it, so the
// artifact is refused. An unknown class is refused too.
func TestAttributeClassesAreValidated(t *testing.T) {
	a := sampleArtifacts()[0]
	a.Attributes = map[string]string{"os_name": "Ubuntu"}
	a.AttributeClasses = map[string]AttributeClass{"os_name": AttributeClassPolicy}
	if err := a.ValidateAttributeClasses(); err != nil {
		t.Fatalf("a declared attribute was refused: %v", err)
	}
	if got := a.AttributeKeysByClass(AttributeClassPolicy); len(got) != 1 || got[0] != "os_name" {
		t.Fatalf("policy keys %v", got)
	}
	if got := a.AttributeKeysByClass(AttributeClassSensitive); len(got) != 0 {
		t.Fatalf("sensitive keys %v", got)
	}
	b := a
	b.AttributeClasses = map[string]AttributeClass{"os_build": AttributeClassPolicy}
	if err := b.ValidateAttributeClasses(); err == nil {
		t.Fatal("a class for an attribute that does not exist was accepted")
	}
	c := a
	c.AttributeClasses = map[string]AttributeClass{"os_name": AttributeClass("public")}
	if err := c.ValidateAttributeClasses(); err == nil {
		t.Fatal("an unknown class was accepted")
	}
	// The class is not part of the content digest, which covers identity and
	// attributes: a probe that starts declaring a field does not look like a
	// changed host.
	base, err := ComputeArtifactDigest(sampleArtifacts()[0])
	if err != nil {
		t.Fatal(err)
	}
	d := sampleArtifacts()[0]
	d.AttributeClasses = map[string]AttributeClass{"os_name": AttributeClassPolicy}
	if got, _ := ComputeArtifactDigest(d); got != base {
		t.Fatal("the attribute classes changed the content digest")
	}
}
