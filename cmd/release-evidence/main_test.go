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

// allRequiredPass returns a gate-result set where every engineering REQUIRED gate passes and
// the sole advisory gate (threat-model-delta) is skipped.
func allRequiredPass() []gateInput {
	var gs []gateInput
	for _, m := range registry {
		if m.id == customerGateID {
			continue
		}
		st := "pass"
		if !m.required {
			st = "skip"
		}
		gs = append(gs, gateInput{ID: m.id, Status: st})
	}
	return gs
}

func TestRecompute_EngineeringPass_CustomerUnconfirmed(t *testing.T) {
	o := baseOpts()
	o.gates = allRequiredPass()

	b, err := buildBundle(o)
	if err != nil {
		t.Fatalf("buildBundle: %v", err)
	}
	if err := validate(b); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if b.Summary.EnterpriseReady {
		t.Fatal("engineering success must not establish customer acceptance")
	}
	if b.Summary.RequiredFailed != 0 {
		t.Fatalf("required_failed = %d, want 0", b.Summary.RequiredFailed)
	}
	if b.Summary.RequiredPassed != 13 || b.Summary.RequiredTotal != 14 {
		t.Fatalf("required_passed %d != required_total %d", b.Summary.RequiredPassed, b.Summary.RequiredTotal)
	}
	// Thirteen engineering gates retain their results; customer acceptance is the 14th.
	if b.Summary.RequiredTotal != 14 {
		t.Fatalf("required_total = %d, want 14 (gate-set G)", b.Summary.RequiredTotal)
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

// A consistent summary cannot authorize a weaker policy or a smaller gate set.
// Recompute the attacker's summary after every mutation to exercise that boundary.
func TestValidate_RejectsPolicyTampering(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Bundle)
	}{
		{"missing required", func(b *Bundle) { b.Gates = b.Gates[1:] }},
		{"missing advisory", func(b *Bundle) { b.Gates = b.Gates[:len(b.Gates)-1] }},
		{"empty gates", func(b *Bundle) { b.Gates = nil }},
		{"required downgraded", func(b *Bundle) {
			b.Gates[0].Required = false
			b.Gates[0].Status = "fail"
		}},
		{"advisory upgraded", func(b *Bundle) { b.Gates[len(b.Gates)-1].Required = true }},
		{"name", func(b *Bundle) { b.Gates[0].Name = "substitute check" }},
		{"kind", func(b *Bundle) { b.Gates[0].Kind = "sast" }},
		{"evidence type", func(b *Bundle) { b.Gates[0].EvidenceType = "external" }},
		{"verifiability", func(b *Bundle) { b.Gates[0].Verifiability = "reference" }},
		{"missing policy", func(b *Bundle) { b.Policy = nil }},
		{"legacy policy", func(b *Bundle) { b.Policy.ID = "trust-binder/policy@legacy" }},
		{"duplicate gate", func(b *Bundle) { b.Gates = append(b.Gates, b.Gates[0]) }},
		{"unknown gate", func(b *Bundle) { b.Gates[0].ID = "unregistered-check" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := baseOpts()
			o.gates = allRequiredPass()
			b, err := buildBundle(o)
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(b)
			b.Summary = computeSummary(b.Gates)
			if err := validate(b); err == nil {
				t.Fatal("accepted altered policy with a matching recomputed summary")
			}
		})
	}
}

func TestValidate_RejectsAmbiguousArtifactNames(t *testing.T) {
	for _, tc := range []struct {
		name, artifactName, digest string
	}{
		{"same digest", "skillctl-linux-amd64", strings.Repeat("a", 64)},
		{"conflicting digest", "skillctl-linux-amd64", strings.Repeat("b", 64)},
		{"whitespace alias", " skillctl-linux-amd64 ", strings.Repeat("a", 64)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := baseOpts()
			o.gates = allRequiredPass()
			o.artifacts = append(o.artifacts, Artifact{Name: tc.artifactName, Digest: Digest{SHA256: tc.digest}})
			b, err := buildBundle(o)
			if err != nil {
				t.Fatal(err)
			}
			if err := validate(b); err == nil || !strings.Contains(err.Error(), "duplicate artifact") {
				t.Fatalf("error = %v, want duplicate artifact refusal", err)
			}
		})
	}
}

func TestValidate_AcceptsCallerEvidenceWithFixedPolicy(t *testing.T) {
	o := baseOpts()
	o.gates = allRequiredPass()
	o.gates[0].Evidence = "https://example.invalid/runs/one"
	o.gates[0].Note = "synthetic evidence reference"
	b, err := buildBundle(o)
	if err != nil {
		t.Fatal(err)
	}
	if err := validate(b); err != nil {
		t.Fatalf("valid caller evidence was refused: %v", err)
	}
}

func TestValidate_NilBundle(t *testing.T) {
	if err := validate(nil); err == nil {
		t.Fatal("nil bundle was accepted")
	}
}

func readinessTestHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("M3C_TOKEN_STORE", "file")
	t.Setenv("M3C_TEST_KEYCHAIN", "0")
	return home
}

func TestCustomerAcceptanceReservedInputs(t *testing.T) {
	readinessTestHome(t)
	for _, status := range []string{"pass", "success", "SUCCESS", "fail", "skip", ""} {
		t.Run(status, func(t *testing.T) {
			o := baseOpts()
			o.gates = append(allRequiredPass(), gateInput{ID: " " + customerGateID + " ", Status: status, Evidence: "https://synthetic.invalid/acceptance", Note: "claimed approval"})
			if _, err := buildBundle(o); err == nil || !strings.Contains(err.Error(), "reserved") {
				t.Fatalf("caller supplied reserved customer acceptance: %v", err)
			}
		})
	}
}

func TestCustomerAcceptanceCLIAndGatesFileCannotAuthorize(t *testing.T) {
	for _, mode := range []string{"flag-pass", "flag-success", "file-pass", "file-success"} {
		t.Run(mode, func(t *testing.T) {
			home := readinessTestHome(t)
			o := baseOpts()
			out := home + "/evidence.json"
			args := []string{"-commit", o.commit, "-tag", o.tag, "-repo", o.repo, "-artifact", "synthetic=" + strings.Repeat("a", 64), "-out", out, "-schema", "../../docs/security/release-evidence.schema.json"}
			status := "pass"
			if strings.HasSuffix(mode, "success") {
				status = "success"
			}
			if strings.HasPrefix(mode, "flag") {
				args = append(args, "-gate", customerGateID+"="+status)
			} else {
				path := home + "/gates.json"
				data, err := json.Marshal([]gateInput{{ID: customerGateID, Status: status}})
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "-gates-file", path)
			}
			if code := run(args); code == 0 {
				t.Fatal("reserved caller gate succeeded through CLI")
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Fatal("rejected reserved gate published evidence")
			}
		})
	}
}

func TestCustomerAcceptanceStrictValidationRejectsForgery(t *testing.T) {
	readinessTestHome(t)
	for _, tc := range []struct {
		name   string
		mutate func(*Bundle)
	}{
		{"missing-customer", func(b *Bundle) {
			for i, g := range b.Gates {
				if g.ID == customerGateID {
					b.Gates = append(b.Gates[:i], b.Gates[i+1:]...)
					return
				}
			}
		}},
		{"pass", func(b *Bundle) {
			for i := range b.Gates {
				if b.Gates[i].ID == customerGateID {
					b.Gates[i].Status = "pass"
				}
			}
		}},
		{"not-required", func(b *Bundle) {
			for i := range b.Gates {
				if b.Gates[i].ID == customerGateID {
					b.Gates[i].Required = false
				}
			}
		}},
		{"forged-evidence", func(b *Bundle) {
			for i := range b.Gates {
				if b.Gates[i].ID == customerGateID {
					b.Gates[i].EvidenceRef = "https://synthetic.invalid/issuer"
				}
			}
		}},
		{"forged-note", func(b *Bundle) {
			for i := range b.Gates {
				if b.Gates[i].ID == customerGateID {
					b.Gates[i].Note = "accepted"
				}
			}
		}},
		{"forged-verifiability", func(b *Bundle) {
			for i := range b.Gates {
				if b.Gates[i].ID == customerGateID {
					b.Gates[i].Verifiability = "trust-ci"
				}
			}
		}},
		{"old-policy", func(b *Bundle) { b.Policy.ID = "trust-binder/policy@v0" }},
		{"forged-rule", func(b *Bundle) { b.Policy.Rule = "engineering-only" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := baseOpts()
			o.gates = allRequiredPass()
			b, err := buildBundle(o)
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(b)
			b.Summary = computeSummary(b.Gates)
			if err := validate(b); err == nil {
				t.Fatal("forged customer policy accepted with recomputed summary")
			}
		})
	}
}

func TestCustomerAcceptanceSyntheticSummaryIsNotAuthorization(t *testing.T) {
	readinessTestHome(t)
	o := baseOpts()
	o.gates = allRequiredPass()
	b, err := buildBundle(o)
	if err != nil {
		t.Fatal(err)
	}
	for i := range b.Gates {
		if b.Gates[i].ID == customerGateID {
			b.Gates[i].Status = "pass"
		}
	}
	b.Summary = computeSummary(b.Gates)
	if !b.Summary.EnterpriseReady || b.Summary.RequiredTotal != 14 || b.Summary.RequiredPassed != 14 {
		t.Fatalf("synthetic all-pass recomputation wrong: %+v", b.Summary)
	}
	if err := validate(b); err == nil {
		t.Fatal("synthetic summary was mistaken for trusted acceptance")
	}
	if computeSummary(nil).EnterpriseReady {
		t.Fatal("empty gate set is not readiness")
	}
}

func TestCustomerAcceptanceOutputAndStatementRemainUnconfirmed(t *testing.T) {
	home := readinessTestHome(t)
	o := baseOpts()
	args := []string{"-commit", o.commit, "-tag", o.tag, "-repo", o.repo, "-artifact", "synthetic=" + strings.Repeat("a", 64), "-out", home + "/bundle.json", "-intoto", home + "/statement.json", "-schema", "../../docs/security/release-evidence.schema.json"}
	for _, g := range allRequiredPass() {
		args = append(args, "-gate", g.ID+"="+g.Status)
	}
	if code := run(args); code != 0 {
		t.Fatalf("engineering evidence assembly failed: %d", code)
	}
	var b Bundle
	data, err := os.ReadFile(home + "/bundle.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &b); err != nil {
		t.Fatal(err)
	}
	if b.SchemaVersion != "0.1.0" || b.Policy.ID != policyID || b.Summary.RequiredPassed != 13 || b.Summary.RequiredTotal != 14 || b.Summary.EnterpriseReady {
		t.Fatalf("incorrect readiness output: %+v", b.Summary)
	}
	for _, g := range b.Gates {
		if g.ID == customerGateID && (g.Status != "skip" || g.EvidenceRef != "" || g.Note != customerGateNote) {
			t.Fatalf("fabricated customer evidence: %+v", g)
		}
	}
	var statement Statement
	data, err = os.ReadFile(home + "/statement.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &statement); err != nil {
		t.Fatal(err)
	}
	if statement.Predicate == nil || statement.Predicate.Summary.EnterpriseReady {
		t.Fatal("in-toto wrapper claims readiness")
	}
}

func TestCustomerAcceptanceSchemaContract(t *testing.T) {
	readinessTestHome(t)
	path := "../../docs/security/release-evidence.schema.json"
	if err := crossCheckSchema(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	props := schema["properties"].(map[string]any)
	policy := props["policy"].(map[string]any)["properties"].(map[string]any)
	if policy["rule"].(map[string]any)["const"] != policyRule {
		t.Fatal("schema policy rule drift")
	}
	if policy["id"].(map[string]any)["const"] != policyID {
		t.Fatal("schema policy version drift")
	}
	summary := props["summary"].(map[string]any)["properties"].(map[string]any)
	if summary["enterprise_ready"].(map[string]any)["const"] != false {
		t.Fatal("schema permits readiness without trusted producer")
	}
	gates := props["gates"].(map[string]any)
	if gates["minItems"] != float64(len(registry)) || gates["minContains"] != float64(1) || gates["maxContains"] != float64(1) {
		t.Fatal("schema can omit or duplicate reserved gate")
	}
}
