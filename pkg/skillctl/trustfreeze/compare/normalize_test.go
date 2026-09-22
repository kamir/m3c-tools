package compare

import (
	"bytes"
	"errors"
	"slices"
	"testing"
)

// normalizeV1Digest pins trust-freeze/normalize/v1. Changing the rule set
// data must come with a new rule set id (SPEC-0469 R4), never with an edit of
// v1; this constant makes such an edit fail loudly.
const normalizeV1Digest = "sha256:9813f9b495979bf3b5103a1816d07aab19a2bd95fb05491197b614bf28e575d9"

func TestRuleSetV1(t *testing.T) {
	rs, err := LoadRuleSet("")
	if err != nil {
		t.Fatal(err)
	}
	if rs.ID != RuleSetNormalizeV1 || DefaultRuleSetID != RuleSetNormalizeV1 {
		t.Fatalf("default rule set = %q", rs.ID)
	}
	// TF04-AC1 categories: timestamps, durations, pid, uptime.
	for _, k := range []string{"pid", "uptime_seconds", "started_at", "duration_ms", "boot_time"} {
		if !slices.Contains(rs.VolatileAttributes, k) {
			t.Errorf("volatile_attributes lacks %q", k)
		}
	}
	// Nothing that describes the state itself is volatile.
	for _, k := range []string{"os_version", "version", "hostname", "kernel_release"} {
		if slices.Contains(rs.VolatileAttributes, k) {
			t.Errorf("volatile_attributes contains state attribute %q", k)
		}
	}
	if !slices.Equal(rs.VolatileFields, []string{"provenance.observed_at"}) {
		t.Fatalf("volatile_fields = %q", rs.VolatileFields)
	}
	d, err := rs.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if d != normalizeV1Digest {
		t.Fatalf("normalize/v1 digest = %s, pinned %s: add a new rule set id instead of editing v1", d, normalizeV1Digest)
	}
}

// A CRLF checkout of the embedded file gives the same rule set and digest.
func TestRuleSetCRLFCheckoutSameDigest(t *testing.T) {
	orig := ruleSetFiles[RuleSetNormalizeV1]
	t.Cleanup(func() { ruleSetFiles[RuleSetNormalizeV1] = orig })
	lf, err := LoadRuleSet(RuleSetNormalizeV1)
	if err != nil {
		t.Fatal(err)
	}
	ruleSetFiles[RuleSetNormalizeV1] = bytes.ReplaceAll(bytes.ReplaceAll(orig, []byte("\r\n"), []byte("\n")), []byte("\n"), []byte("\r\n"))
	crlf, err := LoadRuleSet(RuleSetNormalizeV1)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := lf.Digest()
	b, _ := crlf.Digest()
	if a != b {
		t.Fatalf("CRLF digest %s != LF digest %s", b, a)
	}
}

func TestRuleSetValidate(t *testing.T) {
	cases := map[string]RuleSet{
		"empty id":                  {VolatileFields: []string{}, VolatileAttributes: []string{}},
		"unknown field":             {ID: "x", VolatileFields: []string{"provenance.color"}},
		"state is never volatile":   {ID: "x", VolatileFields: []string{"state"}},
		"attributes are not fields": {ID: "x", VolatileFields: []string{"attributes"}},
		"unsorted":                  {ID: "x", VolatileAttributes: []string{"uptime", "pid"}},
		"duplicate":                 {ID: "x", VolatileAttributes: []string{"pid", "pid"}},
		"empty entry":               {ID: "x", VolatileAttributes: []string{""}},
	}
	for name, rs := range cases {
		if err := rs.Validate(); !errors.Is(err, ErrUnknownRuleSet) {
			t.Errorf("%s: Validate = %v", name, err)
		}
	}
	if _, err := LoadRuleSet("trust-freeze/normalize/v2"); !errors.Is(err, ErrUnknownRuleSet) {
		t.Fatalf("unknown id: %v", err)
	}
}

func TestNormalizeAttributesCopies(t *testing.T) {
	rs, err := LoadRuleSet("")
	if err != nil {
		t.Fatal(err)
	}
	in := map[string]string{"pid": "1", "version": "2"}
	out := rs.NormalizeAttributes(in)
	if len(out) != 1 || out["version"] != "2" || len(in) != 2 {
		t.Fatalf("in %v out %v", in, out)
	}
	if got := rs.NormalizeAttributes(nil); got == nil || len(got) != 0 {
		t.Fatalf("nil map -> %v", got)
	}
	if !slices.IsSorted(ComparedFields()) || !slices.Contains(ComparedFields(), "state") {
		t.Fatalf("ComparedFields = %q", ComparedFields())
	}
}
