package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// baseOpts is a minimal, valid set of assembly options. Each test overrides only
// what it exercises. producedAt is fixed so runs are deterministic.
func baseOpts() options {
	return options{
		commit:         "464e47d0c0ffee1234567890abcdef0123456789",
		tag:            "skillctl/v0.5.0",
		repo:           "kamir/m3c-tools",
		runURL:         "https://github.com/kamir/m3c-tools/actions/runs/9900112233",
		channel:        "skillctl",
		producedAt:     "2026-09-03T09:14:22Z",
		toolVersion:    "0.1.0-test",
		autoRefs:       true,
		provenanceName: "multiple.intoto.jsonl",
		sbomName:       "skillctl.sbom.cdx.json",
		artifacts: []Artifact{
			{Name: "skillctl-linux-amd64", Digest: Digest{SHA256: strings.Repeat("a", 64)}},
		},
	}
}

// allRequiredPass returns a gate-result set where every REQUIRED gate passes and
// the sole advisory gate (threat-model-delta) is skipped.
func allRequiredPass() []gateInput {
	var gs []gateInput
	for _, m := range registry {
		st := "pass"
		if !m.required {
			st = "skip"
		}
		gs = append(gs, gateInput{ID: m.id, Status: st})
	}
	return gs
}

func TestRecompute_AllRequiredPass_IsReady(t *testing.T) {
	o := baseOpts()
	o.gates = allRequiredPass()

	b, err := buildBundle(o)
	if err != nil {
		t.Fatalf("buildBundle: %v", err)
	}
	if err := validate(b); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if !b.Summary.EnterpriseReady {
		t.Fatalf("enterprise_ready = false, want true when every required gate passes")
	}
	if b.Summary.RequiredFailed != 0 {
		t.Fatalf("required_failed = %d, want 0", b.Summary.RequiredFailed)
	}
	if b.Summary.RequiredPassed != b.Summary.RequiredTotal {
		t.Fatalf("required_passed %d != required_total %d", b.Summary.RequiredPassed, b.Summary.RequiredTotal)
	}
	// Sanity: policy G currently has 12 required gates.
	if b.Summary.RequiredTotal != 12 {
		t.Fatalf("required_total = %d, want 12 (gate-set G)", b.Summary.RequiredTotal)
	}
}

func TestRecompute_OneRequiredFail_NotReady(t *testing.T) {
	o := baseOpts()
	gs := allRequiredPass()
	// Flip one REQUIRED gate to fail.
	flipped := false
	for i := range gs {
		if gs[i].ID == "gosec-sast" { // required:true under policy G
			gs[i].Status = "fail"
			flipped = true
		}
	}
	if !flipped {
		t.Fatal("test setup: gosec-sast not found in gate set")
	}
	o.gates = gs

	b, err := buildBundle(o)
	if err != nil {
		t.Fatalf("buildBundle: %v", err)
	}
	if b.Summary.EnterpriseReady {
		t.Fatalf("enterprise_ready = true, want false when a required gate fails")
	}
	if b.Summary.RequiredFailed != 1 {
		t.Fatalf("required_failed = %d, want 1", b.Summary.RequiredFailed)
	}
}

func TestRecompute_RequiredSkip_NotReady(t *testing.T) {
	o := baseOpts()
	gs := allRequiredPass()
	for i := range gs {
		if gs[i].ID == "platform-smoke" { // required:true under policy G
			gs[i].Status = "skip"
		}
	}
	o.gates = gs

	b, err := buildBundle(o)
	if err != nil {
		t.Fatalf("buildBundle: %v", err)
	}
	if b.Summary.EnterpriseReady {
		t.Fatalf("enterprise_ready = true, want false when a required gate is skipped")
	}
	if b.Summary.RequiredFailed != 0 {
		t.Fatalf("required_failed = %d, want 0 (a skip is not a fail)", b.Summary.RequiredFailed)
	}
}

// A caller supplying results for only SOME gates: the missing required gates
// default to skip, so the bundle is complete and not enterprise-ready.
func TestMissingGate_DefaultsToSkip_NotReady(t *testing.T) {
	o := baseOpts()
	o.gates = []gateInput{{ID: "unit-tests", Status: "pass"}}

	b, err := buildBundle(o)
	if err != nil {
		t.Fatalf("buildBundle: %v", err)
	}
	if len(b.Gates) != len(registry) {
		t.Fatalf("emitted %d gates, want %d (one per registry entry)", len(b.Gates), len(registry))
	}
	if b.Summary.EnterpriseReady {
		t.Fatal("enterprise_ready = true, want false when most required gates are unsupplied (skip)")
	}
}

// GitHub needs.<job>.result vocabulary must normalise into the bundle.
func TestNormalizeStatus_GitHubResults(t *testing.T) {
	cases := map[string]string{
		"success": "pass", "pass": "pass", "SUCCESS": "pass",
		"failure": "fail", "cancelled": "fail", "timed_out": "fail",
		"skipped": "skip", "": "skip", "neutral": "skip",
	}
	for in, want := range cases {
		got, err := normalizeStatus(in)
		if err != nil {
			t.Fatalf("normalizeStatus(%q): %v", in, err)
		}
		if got != want {
			t.Errorf("normalizeStatus(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := normalizeStatus("bogus"); err == nil {
		t.Error("normalizeStatus(bogus): want error, got nil")
	}
}

func TestBuildBundle_RejectsUnknownGateID(t *testing.T) {
	o := baseOpts()
	o.gates = []gateInput{{ID: "not-a-real-gate", Status: "pass"}}
	if _, err := buildBundle(o); err == nil {
		t.Fatal("want error for an unknown gate id, got nil")
	}
}

func TestBuildBundle_RequiresCoreFields(t *testing.T) {
	o := baseOpts()
	o.commit = ""
	if _, err := buildBundle(o); err == nil {
		t.Fatal("want error when -commit is empty, got nil")
	}
}

// The assembled bundle must round-trip through JSON with all required top-level
// keys present, and carry the fixed predicate/policy identity.
func TestBundle_ShapeAndRoundTrip(t *testing.T) {
	o := baseOpts()
	o.gates = allRequiredPass()
	o.checksumsSHA256 = strings.Repeat("b", 64)

	b, err := buildBundle(o)
	if err != nil {
		t.Fatalf("buildBundle: %v", err)
	}
	if err := validate(b); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if b.PredicateType != predicateType {
		t.Errorf("predicate_type = %q, want %q", b.PredicateType, predicateType)
	}
	if b.BundleID != "kamir/m3c-tools@skillctl/v0.5.0" {
		t.Errorf("bundle_id = %q", b.BundleID)
	}
	if b.Policy == nil || b.Policy.ID != policyID {
		t.Errorf("policy.id missing/wrong: %+v", b.Policy)
	}
	// references index must be present with the checksums digest wired in.
	var haveChecksums bool
	for _, r := range b.References {
		if r.Type == "checksums" {
			haveChecksums = true
			if r.SHA256 != strings.Repeat("b", 64) {
				t.Errorf("checksums reference sha256 = %q", r.SHA256)
			}
		}
	}
	if !haveChecksums {
		t.Error("references[] missing the checksums pointer")
	}

	data, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back map[string]json.RawMessage
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"schema_version", "subject", "produced_at", "gates", "summary"} {
		if _, ok := back[k]; !ok {
			t.Errorf("required top-level key %q missing from output", k)
		}
	}
}

// parseGateFlag must keep an evidence URL (with its `=`/`:`) intact.
func TestParseGateFlag_EvidenceURLIntact(t *testing.T) {
	gi, err := parseGateFlag("cosign-signature=success,evidence=https://github.com/kamir/m3c-tools/releases/download/skillctl/v0.5.0/SHA256SUMS.cosign.bundle?x=1")
	if err != nil {
		t.Fatalf("parseGateFlag: %v", err)
	}
	if gi.ID != "cosign-signature" || gi.Status != "success" {
		t.Fatalf("parsed id/status wrong: %+v", gi)
	}
	if !strings.HasPrefix(gi.Evidence, "https://") || !strings.Contains(gi.Evidence, "x=1") {
		t.Fatalf("evidence URL mangled: %q", gi.Evidence)
	}
}

func TestParseChecksums(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/SHA256SUMS"
	content := strings.Repeat("a", 64) + "  skillctl-linux-amd64\n" +
		strings.Repeat("c", 64) + "  skillctl-windows-amd64.exe\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	arts, err := parseChecksums(path)
	if err != nil {
		t.Fatalf("parseChecksums: %v", err)
	}
	if len(arts) != 2 {
		t.Fatalf("got %d artifacts, want 2", len(arts))
	}
	if arts[1].Name != "skillctl-windows-amd64.exe" {
		t.Errorf("artifact name = %q", arts[1].Name)
	}
}

// validate must reject a bundle whose stored summary was tampered to claim
// readiness that the gates do not support.
func TestValidate_RejectsTamperedSummary(t *testing.T) {
	o := baseOpts()
	gs := allRequiredPass()
	for i := range gs {
		if gs[i].ID == "lint" {
			gs[i].Status = "fail"
		}
	}
	o.gates = gs
	b, err := buildBundle(o)
	if err != nil {
		t.Fatalf("buildBundle: %v", err)
	}
	// Forge the stored bool.
	b.Summary.EnterpriseReady = true
	if err := validate(b); err == nil {
		t.Fatal("validate accepted a tampered summary; want error")
	}
}
