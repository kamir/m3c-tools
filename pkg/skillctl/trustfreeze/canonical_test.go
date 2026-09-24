package trustfreeze

import (
	"bytes"
	"encoding/json"
	"errors"
	"math/rand"
	"strconv"
	"strings"
	"testing"
	"time"
)

func goldenValues() map[string]any {
	results := []ProbeResult{
		sampleProbeResult("common.identity", StatusCaptured),
		sampleProbeResult("linux.firewall", StatusPermissionDenied),
	}
	m := Manifest{
		SchemaVersion: SchemaManifest,
		Kind:          KindCapture,
		BundleID:      BundleID(KindCapture, testTime, testSubject().ID),
		CreatedAt:     FormatTime(testTime),
		Subject:       testSubject(),
		BundlePolicy:  BundlePolicy{RejectAdditions: true},
		Files: []FileEntry{
			{Path: "capture.json", Size: 3, SHA256: SHA256Hex([]byte("abc"))},
			{Path: "probes/common.identity.json", Size: 0, SHA256: SHA256Hex(nil)},
		},
	}
	d, err := ComputeContentDigest(m)
	if err != nil {
		panic(err)
	}
	m.ContentDigest = d
	return map[string]any{
		"capture":      sampleCaptureDoc([]string{"common.identity", "linux.firewall"}, results),
		"probe_result": results[0],
		"manifest":     m,
	}
}

// TestGoldenCanonicalAndFile pins the exact bytes of both encodings
// (SPEC-0466 R5).
func TestGoldenCanonicalAndFile(t *testing.T) {
	for name, v := range goldenValues() {
		t.Run(name, func(t *testing.T) {
			c, err := MarshalCanonical(v)
			if err != nil {
				t.Fatal(err)
			}
			checkGolden(t, "canonical_"+name+".golden", c)
			f, err := MarshalFile(v)
			if err != nil {
				t.Fatal(err)
			}
			checkGolden(t, "file_"+name+".golden", f)
		})
	}
}

// TestCanonicalForms: compact form has no trailing newline, file form ends in
// exactly one LF, neither escapes HTML.
func TestCanonicalForms(t *testing.T) {
	v := map[string]string{"b": "<x & y>", "a": "1"}
	c, err := MarshalCanonical(v)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(c), `{"a":"1","b":"<x & y>"}`; got != want {
		t.Fatalf("MarshalCanonical = %s, want %s", got, want)
	}
	f, err := MarshalFile(v)
	if err != nil {
		t.Fatal(err)
	}
	if want := "{\n  \"a\": \"1\",\n  \"b\": \"<x & y>\"\n}\n"; string(f) != want {
		t.Fatalf("MarshalFile = %q, want %q", f, want)
	}
	if bytes.HasSuffix(f, []byte("\n\n")) || bytes.Contains(f, []byte("\r")) {
		t.Fatalf("MarshalFile must end in exactly one LF and contain no CR: %q", f)
	}
}

// TestTF01AC1ByteEqualSerialization: two serializations of the same value, and
// a decode and re-encode, are byte-equal (SPEC-0466 TF01-AC1).
func TestTF01AC1ByteEqualSerialization(t *testing.T) {
	for name, v := range goldenValues() {
		t.Run(name, func(t *testing.T) {
			a, err := MarshalFile(v)
			if err != nil {
				t.Fatal(err)
			}
			b, err := MarshalFile(v)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(a, b) {
				t.Fatal("two serializations differ")
			}
			var again any
			switch v.(type) {
			case CaptureDoc:
				again = &CaptureDoc{}
			case ProbeResult:
				again = &ProbeResult{}
			case Manifest:
				again = &Manifest{}
			}
			if err := UnmarshalCanonicalFile(a, again); err != nil {
				t.Fatalf("round trip: %v", err)
			}
		})
	}
}

// TestTF01AC2MapInsertionOrder: the insertion order of a map never changes the
// bytes or the digest (SPEC-0466 TF01-AC2).
func TestTF01AC2MapInsertionOrder(t *testing.T) {
	keys := make([]string, 200)
	for i := range keys {
		keys[i] = "k" + strconv.Itoa(i)
	}
	build := func(order []int) Artifact {
		attrs := map[string]string{}
		for _, i := range order {
			attrs[keys[i]] = "v" + strconv.Itoa(i)
		}
		return Artifact{
			ID: "device/os", Type: "os", Scope: "device", State: StateObserved, Attributes: attrs,
			Provenance:  Provenance{Method: "file", Confidence: ConfidenceProven, ObservedAt: FormatTime(testTime)},
			Sensitivity: SensitivityPublic,
		}
	}
	rng := rand.New(rand.NewSource(1))
	base := build(rng.Perm(len(keys)))
	wantBytes, err := MarshalCanonical(base)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest, err := ComputeArtifactDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		a := build(rng.Perm(len(keys)))
		got, err := MarshalCanonical(a)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, wantBytes) {
			t.Fatalf("permutation %d changed the canonical bytes", i)
		}
		d, err := ComputeArtifactDigest(a)
		if err != nil {
			t.Fatal(err)
		}
		if d != wantDigest {
			t.Fatalf("permutation %d changed the artifact digest", i)
		}
	}
}

// TestCanonicalRejects: values outside the canonicalization contract are
// refused instead of being encoded in a lossy or unstable way.
func TestCanonicalRejects(t *testing.T) {
	type withFloat struct {
		F float64 `json:"f"`
	}
	type withTime struct {
		T time.Time `json:"t"`
	}
	type hidden struct {
		F float64 `json:"-"`
		s float64 //nolint:unused // proves unexported fields are skipped like encoding/json does
		N int64   `json:"n"`
	}
	cases := []struct {
		name string
		v    any
		ok   bool
	}{
		{"float field", withFloat{F: 1.5}, false},
		{"float in any", map[string]any{"x": 1.0}, false},
		{"float32", float32(1), false},
		{"int keyed map", map[int]string{1: "a"}, false},
		{"time.Time", withTime{T: testTime}, false},
		{"json.Number", map[string]any{"n": json.Number("1.5")}, false},
		{"json.RawMessage", map[string]any{"r": json.RawMessage(`{"b":1,"a":2}`)}, false},
		{"invalid utf8 value", map[string]string{"a": "\xff"}, false},
		{"invalid utf8 key", map[string]string{"\xff": "a"}, false},
		{"func", map[string]any{"f": func() {}}, false},
		{"nested float in slice", []any{"a", []any{2.5}}, false},
		{"ignored and unexported fields", hidden{F: 1.5, N: 2}, true},
		{"int64 and strings", map[string]any{"n": int64(3), "s": "x"}, true},
		{"nil interface", map[string]any{"x": nil}, true},
		{"invalid enum", ProbeResult{Status: "Captured"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := MarshalCanonical(tc.v)
			if tc.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.ok {
				if err == nil {
					t.Fatal("expected an error")
				}
				if !errors.Is(err, ErrNotCanonical) && !errors.Is(err, ErrInvalidEnum) {
					t.Fatalf("error %v does not wrap ErrNotCanonical or ErrInvalidEnum", err)
				}
			}
			if _, ferr := MarshalFile(tc.v); (ferr == nil) != (err == nil) {
				t.Fatalf("MarshalFile and MarshalCanonical disagree: %v vs %v", ferr, err)
			}
		})
	}
}

// TestUnmarshalCanonicalFile: anything a writer never produces is rejected.
func TestUnmarshalCanonicalFile(t *testing.T) {
	good, err := MarshalFile(Subject{ID: "device/0123456789abcdef", OSFamily: "linux"})
	if err != nil {
		t.Fatal(err)
	}
	var s Subject
	if err := UnmarshalCanonicalFile(good, &s); err != nil {
		t.Fatalf("canonical input rejected: %v", err)
	}
	bad := map[string]string{
		"crlf":          strings.ReplaceAll(string(good), "\n", "\r\n"),
		"compact":       `{"id":"device/0123456789abcdef","os_family":"linux"}` + "\n",
		"reordered":     "{\n  \"os_family\": \"linux\",\n  \"id\": \"device/0123456789abcdef\"\n}\n",
		"duplicate key": "{\n  \"id\": \"device/x\",\n  \"id\": \"device/0123456789abcdef\",\n  \"os_family\": \"linux\"\n}\n",
		"unknown field": "{\n  \"id\": \"device/0123456789abcdef\",\n  \"os_family\": \"linux\",\n  \"x\": \"y\"\n}\n",
		"no newline":    strings.TrimSuffix(string(good), "\n"),
		"trailing data": string(good) + "{}",
	}
	for name, in := range bad {
		t.Run(name, func(t *testing.T) {
			var s Subject
			if err := UnmarshalCanonicalFile([]byte(in), &s); !errors.Is(err, ErrNotCanonical) {
				t.Fatalf("got %v, want ErrNotCanonical", err)
			}
		})
	}
}

// TestDigestFormat pins the digest helpers.
func TestDigestFormat(t *testing.T) {
	if got, want := Digest([]byte("abc")), "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"; got != want {
		t.Fatalf("Digest = %s, want %s", got, want)
	}
}
