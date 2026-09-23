package policy

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze"
)

// defaultV0RulesDigest pins trust-freeze/policy/default-v0 as SPEC-0469
// section 4.5 defines it: the requester's decision round changed v0 before
// its first release (subject_changed, the not_applicable cause, not_observed,
// applicability_changed, no milestone term in the description). From here on,
// changing what the default policy judges needs a new policy id, never an
// edit of v0.
const defaultV0RulesDigest = "sha256:ee9fcbc71aa53e1fd63ec40975c843475c9b5b0cd06043cef0a37f994b46d319"

// defaultV0FileSHA256 pins the BYTES of builtin/default-v0.json. The rules
// digest above covers what v0 judges; this covers the file itself, so an edit
// of a published policy cannot pass as a reformatting either (R-T4).
//
// The byte pin sits on v0 and on no other built-in on purpose: v0 is the only
// built-in policy with a committed reference to compare against, so the value
// below is checkable outside this test as the sha256 of
// "git show HEAD:pkg/skillctl/trustfreeze/policy/builtin/default-v0.json".
// default-v1 is created by this branch and has no such predecessor, so a byte
// pin on it would only restate the file this branch just wrote; what v1 judges
// is pinned by its rules digest instead.
const defaultV0FileSHA256 = "sha256:7927277caa205ee216a50e1944b1af32984846450d5f57f1e6ad78ac39e0dd15"

// defaultV1RulesDigest pins what trust-freeze/policy/default-v1 judges: v0
// plus the capability rules, with every root privilege of the core vocabulary
// in the root rule and coverage_increased rated info (R-T1, R-T4). Changing
// any of that needs a new policy id, never an edit of v1 once it is published.
const defaultV1RulesDigest = "sha256:a74f9eb62318cc8bee01ced0a0b829df720d49336cafae3a08447554084e4ddd"

func TestDefaultPolicyV0(t *testing.T) {
	p, err := PolicyV0()
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != PolicyV0ID || p.SchemaVersion != trustfreeze.SchemaPolicy {
		t.Fatalf("id %q schema %q", p.ID, p.SchemaVersion)
	}
	if p.FailOn != ThresholdHigh || p.DefaultSeverity != trustfreeze.SeverityInfo {
		t.Fatalf("fail_on %q default %q", p.FailOn, p.DefaultSeverity)
	}
	var ids []string
	for _, r := range p.Rules {
		ids = append(ids, r.ID+"="+string(r.Severity))
	}
	want := "TF-POL-SUBJECT-CHANGED=high,TF-POL-SUBJECT-CHANGED-ALLOWED=info,TF-POL-GAP-REQUIRED=critical,TF-POL-GAP-OPTIONAL=medium," +
		"TF-POL-GAP-NOT-APPLICABLE=info,TF-POL-DEVICE-IDENTITY=medium,TF-POL-ARTIFACT-DRIFT=low,TF-POL-NOT-OBSERVED=low,TF-POL-APPLICABILITY=low"
	if got := strings.Join(ids, ","); got != want {
		t.Fatalf("rules %s", got)
	}
	d, err := p.RulesDigest()
	if err != nil {
		t.Fatal(err)
	}
	if d != defaultV0RulesDigest {
		t.Fatalf("default-v0 rules digest = %s, pinned %s: add a new policy id instead of editing v0", d, defaultV0RulesDigest)
	}
	if got := trustfreeze.Digest(defaultV0JSON); got != defaultV0FileSHA256 {
		t.Fatalf("builtin/default-v0.json = %s, pinned %s: a published policy is superseded, never edited", got, defaultV0FileSHA256)
	}
	// v0 judges no capability entry: that is why v1 exists.
	for _, r := range p.Rules {
		for _, k := range r.Match.ChangeKinds {
			if k.IsCapability() {
				t.Fatalf("rule %s of the frozen v0 rates capability kind %s", r.ID, k)
			}
		}
	}
}

// TF06-R3, R-T1, R-T4 (SPEC-0469 AC3): default-v1 is the built-in default and
// the only new built-in T-03 ships. It is v0 plus the capability rules, with
// both container paths to root in the root rule and coverage_increased rated
// info, and it is reached without naming a file.
func TestDefaultPolicyV1(t *testing.T) {
	p := defaultPolicy(t)
	if p.ID != DefaultPolicyID || DefaultPolicyID != "trust-freeze/policy/default-v1" {
		t.Fatalf("the default policy is %q", p.ID)
	}
	if p.SchemaVersion != trustfreeze.SchemaPolicy {
		t.Fatalf("schema %q", p.SchemaVersion)
	}
	if p.FailOn != ThresholdHigh || p.DefaultSeverity != trustfreeze.SeverityInfo {
		t.Fatalf("fail_on %q default %q", p.FailOn, p.DefaultSeverity)
	}
	var ids []string
	for _, r := range p.Rules {
		ids = append(ids, r.ID+"="+string(r.Severity))
	}
	want := "TF-POL-SUBJECT-CHANGED=high,TF-POL-SUBJECT-CHANGED-ALLOWED=info,TF-POL-GAP-REQUIRED=critical,TF-POL-GAP-OPTIONAL=medium," +
		"TF-POL-GAP-NOT-APPLICABLE=info,TF-POL-DEVICE-IDENTITY=medium,TF-POL-ARTIFACT-DRIFT=low,TF-POL-NOT-OBSERVED=low," +
		"TF-POL-CAPABILITY-ROOT=critical,TF-POL-CAPABILITY-ADDED=high,TF-POL-CAPABILITY-CHANGED=medium,TF-POL-CAPABILITY-GONE=low," +
		"TF-POL-COVERAGE-INCREASED=info,TF-POL-APPLICABILITY=low"
	if got := strings.Join(ids, ","); got != want {
		t.Fatalf("rules %s", got)
	}
	// The root rule names every privilege the core calls root, so a resolver
	// that adds one cannot silently fall through to the weaker rule.
	for _, r := range p.Rules {
		if r.ID != "TF-POL-CAPABILITY-ROOT" {
			continue
		}
		if !slices.Equal(r.Match.Privileges, trustfreeze.RootPrivileges()) {
			t.Fatalf("TF-POL-CAPABILITY-ROOT privileges %v, the core vocabulary is %v", r.Match.Privileges, trustfreeze.RootPrivileges())
		}
	}
	d, err := p.RulesDigest()
	if err != nil {
		t.Fatal(err)
	}
	if d != defaultV1RulesDigest {
		t.Fatalf("default-v1 rules digest = %s, pinned %s: add a new policy id instead of editing v1", d, defaultV1RulesDigest)
	}
	// Each call returns an independent copy.
	orig := p.Rules[0].Severity
	if orig == trustfreeze.SeverityLow {
		t.Fatal("fixture error: the first rule must not already be low")
	}
	p.Rules[0].Severity = trustfreeze.SeverityLow
	again, err := DefaultPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if again.Rules[0].Severity != orig {
		t.Fatal("DefaultPolicy shares state between calls")
	}
	// fail_on is not part of the rules digest.
	p = again
	p.FailOn = ThresholdNone
	if d2, _ := p.RulesDigest(); d2 != d {
		t.Fatal("fail_on changed the rules digest")
	}
	// T-03 ships exactly one new built-in beyond v0: every built-in id
	// resolves, an unknown one is not invented, and no third id exists.
	if got := BuiltinPolicyIDs(); !slices.Equal(got, []string{PolicyV0ID, DefaultPolicyID}) {
		t.Fatalf("built-in policy ids %v", got)
	}
	for _, id := range BuiltinPolicyIDs() {
		got, ok, err := BuiltinPolicy(id)
		if err != nil || !ok || got.ID != id {
			t.Fatalf("BuiltinPolicy(%q) = %q, %v, %v", id, got.ID, ok, err)
		}
	}
	for _, id := range []string{"trust-freeze/policy/default-v2", "trust-freeze/policy/default-v9"} {
		if _, ok, err := BuiltinPolicy(id); ok || err != nil {
			t.Fatalf("BuiltinPolicy(%q) resolved: %v, %v", id, ok, err)
		}
	}
}

const yamlPolicy = `# the default policy, spelled in YAML
schema_version: trust-freeze/policy/v1
id: trust-freeze/policy/default-v0
description: >-
  Default policy. Comparing two different devices is high, info when the
  mismatch was allowed explicitly. A collection gap of a required probe is
  critical, of an optional probe medium; a probe that is not applicable with a
  reason is info. A changed device/os or device/host is medium. Every other
  added, removed or changed artifact, a baseline artifact that was not
  observed and a probe that moved between captured and not_applicable are low.
  Changes no rule matches get the default severity info.
fail_on: high
default_severity: info
rules:
  - id: TF-POL-SUBJECT-CHANGED
    description: The baseline and the current bundle describe different devices.
    severity: high
    match:
      change_kinds: [subject_changed]
      subject_mismatch_allowed: false
  - id: TF-POL-SUBJECT-CHANGED-ALLOWED
    description: Different devices, compared on purpose (allow_subject_mismatch).
    severity: info
    match:
      change_kinds: [subject_changed]
      subject_mismatch_allowed: true
  - id: TF-POL-GAP-REQUIRED
    description: A required probe was not captured.
    severity: critical
    match:
      change_kinds: [collection_gap]
      required: true
      gap_causes: [duplicate_result, invalid_status, no_result, not_applicable_without_reason, not_captured]
  - id: TF-POL-GAP-OPTIONAL
    description: An optional probe was not captured.
    severity: medium
    match:
      change_kinds: [collection_gap]
      required: false
      gap_causes: [duplicate_result, invalid_status, no_result, not_applicable_without_reason, not_captured]
  - id: TF-POL-GAP-NOT-APPLICABLE
    description: A probe is not applicable on this host and says why. It stays visible and does not block.
    severity: info
    match:
      change_kinds: [collection_gap]
      gap_causes: [not_applicable]
  - id: TF-POL-DEVICE-IDENTITY
    description: The operating system or host identity changed.
    severity: medium
    match:
      change_kinds: [changed]
      artifact_ids: [device/host, device/os]
  - id: TF-POL-ARTIFACT-DRIFT
    description: Any other artifact was added, removed or changed.
    severity: low
    match:
      change_kinds: [added, changed, removed]
  - id: TF-POL-NOT-OBSERVED
    description: A baseline artifact, or some of its attributes, was not observed because its source probe was not captured.
    severity: low
    match:
      change_kinds: [not_observed]
  - id: TF-POL-APPLICABILITY
    description: A probe moved between captured and not_applicable.
    severity: low
    match:
      change_kinds: [applicability_changed]
`

// The same policy in YAML and in JSON is the same policy (same rules digest).
func TestYAMLAndJSONPolicyAreEquivalent(t *testing.T) {
	dir := t.TempDir()
	yp, err := LoadPolicyFile(writeFile(t, dir, "p.yaml", yamlPolicy))
	if err != nil {
		t.Fatal(err)
	}
	jp, err := LoadPolicyFile(writeFile(t, dir, "p.json", string(defaultV0JSON)))
	if err != nil {
		t.Fatal(err)
	}
	a, _ := yp.RulesDigest()
	b, _ := jp.RulesDigest()
	if a != b || a != defaultV0RulesDigest {
		t.Fatalf("yaml %s json %s pinned %s", a, b, defaultV0RulesDigest)
	}
	for _, name := range []string{"p.yml", "policy"} {
		if _, err := LoadPolicyFile(writeFile(t, dir, name, yamlPolicy)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := LoadPolicyFile(writeFile(t, dir, "policy.txt", string(defaultV0JSON))); err != nil {
		t.Fatalf("sniffed json: %v", err)
	}
	crlf := strings.ReplaceAll(yamlPolicy, "\n", "\r\n")
	if _, err := LoadPolicyFile(writeFile(t, dir, "crlf.yaml", crlf)); err != nil {
		t.Fatalf("CRLF yaml: %v", err)
	}
}

func TestParsePolicyStrict(t *testing.T) {
	good := string(defaultV0JSON)
	sub := func(old, new string) string {
		if !strings.Contains(good, old) {
			t.Fatalf("fixture error: %q not in default policy", old)
		}
		return strings.Replace(good, old, new, 1)
	}
	ysub := func(old, new string) string {
		if !strings.Contains(yamlPolicy, old) {
			t.Fatalf("fixture error: %q not in yaml policy", old)
		}
		return strings.Replace(yamlPolicy, old, new, 1)
	}
	cases := map[string]string{
		"json unknown field":         sub(`"fail_on": "high",`, `"fail_on": "high", "failOn": "low",`),
		"json unknown severity":      sub(`"severity": "critical"`, `"severity": "severe"`),
		"json null severity":         sub(`"severity": "critical"`, `"severity": null`),
		"json unknown threshold":     sub(`"fail_on": "high"`, `"fail_on": "info"`),
		"json wrong schema":          sub(`trust-freeze/policy/v1`, `trust-freeze/policy/v2`),
		"json empty id":              sub(`"id": "trust-freeze/policy/default-v0"`, `"id": " "`),
		"json duplicate rule id":     sub(`"TF-POL-GAP-OPTIONAL"`, `"TF-POL-GAP-REQUIRED"`),
		"json reserved rule id":      sub(`"TF-POL-GAP-OPTIONAL"`, `"default_severity"`),
		"json empty change kinds":    sub(`"change_kinds": ["changed"]`, `"change_kinds": []`),
		"json unknown change kind":   sub(`"change_kinds": ["changed"]`, `"change_kinds": ["modified"]`),
		"json required on non gap":   sub(`"change_kinds": ["collection_gap"],`+"\n        \"required\": false", `"change_kinds": ["collection_gap", "added"],`+"\n        \"required\": false"),
		"json artifact ids on gap":   sub(`"change_kinds": ["changed"]`, `"change_kinds": ["changed", "collection_gap"]`),
		"json bad artifact id":       sub(`"device/host", "device/os"`, `"/etc/os-release"`),
		"json trailing data":         good + "{}",
		"json duplicate key":         sub(`"fail_on": "high",`, `"fail_on": "high", "fail_on": "none",`),
		"json nested duplicate key":  sub(`"severity": "critical",`, `"severity": "low", "severity": "critical",`),
		"yaml unknown field":         ysub("fail_on: high", "fail_on: high\nfailOn: low"),
		"yaml duplicate key":         ysub("fail_on: high", "fail_on: high\nfail_on: low"),
		"yaml float":                 ysub("required: true", "required: 1.5"),
		"yaml yes is not a bool":     ysub("required: true", "required: yes"),
		"yaml second document":       yamlPolicy + "---\nid: other\n",
		"yaml anchor and alias":      ysub("change_kinds: [changed]", "change_kinds: &k [changed]") + "extra: *k\n",
		"yaml timestamp":             ysub("fail_on: high", "fail_on: 2026-01-02"),
		"yaml non string key":        ysub("fail_on: high", "fail_on: high\n1: x"),
		"yaml empty":                 "",
		"yaml merge key":             ysub("    match:\n      change_kinds: [changed]", "    match:\n      <<: {x: 1}\n      change_kinds: [changed]"),
		"yaml unknown severity text": ysub("severity: critical", "severity: CRITICAL"),
	}
	for name, in := range cases {
		if _, err := ParsePolicy([]byte(in)); !errors.Is(err, ErrInvalidPolicy) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	missing := `{"schema_version":"trust-freeze/policy/v1","id":"x","fail_on":"high","default_severity":"info"}`
	if _, err := ParsePolicy([]byte(missing)); !errors.Is(err, ErrInvalidPolicy) {
		t.Errorf("missing rules: %v", err)
	}
	minimal := `{"schema_version":"trust-freeze/policy/v1","id":"x","fail_on":"none","default_severity":"low","rules":[]}`
	if _, err := ParsePolicy([]byte(minimal)); err != nil {
		t.Errorf("minimal policy: %v", err)
	}
}

func TestLoadPolicyFileLimits(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadPolicyFile(dir); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("directory: %v", err)
	}
	if _, err := LoadPolicyFile(filepath.Join(dir, "missing.json")); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("missing: %v", err)
	}
	big := string(defaultV0JSON[:len(defaultV0JSON)-2]) + strings.Repeat(" ", MaxPolicyFileBytes) + "}\n"
	if _, err := LoadPolicyFile(writeFile(t, dir, "big.json", big)); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("oversized: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "y.yaml"), defaultV0JSON, 0o600); err != nil {
		t.Fatal(err)
	}
	// JSON is valid YAML: a .yaml file holding JSON loads through YAML.
	if _, err := LoadPolicyFile(filepath.Join(dir, "y.yaml")); err != nil {
		t.Fatalf("json in .yaml: %v", err)
	}
}

func TestThreshold(t *testing.T) {
	for _, s := range []string{"", "info", "High", " high", "all"} {
		if _, err := ParseThreshold(s); !errors.Is(err, trustfreeze.ErrInvalidEnum) {
			t.Errorf("ParseThreshold(%q) = %v", s, err)
		}
	}
	cases := []struct {
		th   Threshold
		sev  trustfreeze.Severity
		want bool
	}{
		{ThresholdNone, trustfreeze.SeverityCritical, false},
		{ThresholdLow, trustfreeze.SeverityInfo, false},
		{ThresholdLow, trustfreeze.SeverityLow, true},
		{ThresholdHigh, trustfreeze.SeverityMedium, false},
		{ThresholdHigh, trustfreeze.SeverityHigh, true},
		{ThresholdHigh, trustfreeze.SeverityCritical, true},
		{ThresholdCritical, trustfreeze.SeverityHigh, false},
		{ThresholdCritical, "", false},
		{"", trustfreeze.SeverityCritical, false},
	}
	for _, tc := range cases {
		if got := tc.th.Exceeded(tc.sev); got != tc.want {
			t.Errorf("%q.Exceeded(%q) = %v", tc.th, tc.sev, got)
		}
	}
	var th Threshold
	for _, in := range []string{`null`, `3`, `"info"`} {
		if err := th.UnmarshalJSON([]byte(in)); err == nil {
			t.Errorf("UnmarshalJSON(%s) accepted", in)
		}
	}
	if _, err := Threshold("").MarshalText(); err == nil {
		t.Error("empty threshold marshaled")
	}
	if len(Thresholds()) != 5 {
		t.Fatal("Thresholds")
	}
}
