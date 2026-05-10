package awareness

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/model"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// stubSigner produces a deterministic base64 "signature" so tests can
// assert envelope shape without dragging ed25519 in. The real CLI wires
// AuthorSigner to ed25519.Sign; this stub returns the message reversed
// + a base64 wrapper so different inputs produce different outputs but
// the result is reproducible.
func stubSigner(message []byte) (string, error) {
	rev := make([]byte, len(message))
	for i, b := range message {
		rev[len(message)-1-i] = b
	}
	return base64.StdEncoding.EncodeToString(rev), nil
}

func sampleInventory(t *testing.T) *model.Inventory {
	t.Helper()
	return &model.Inventory{
		ScannedAt:  "2026-05-06T10:00:00Z",
		ScanPaths:  []string{"/Users/kamir/.claude/skills"},
		TotalCount: 2,
		Skills: []model.SkillDescriptor{
			{
				ID:           "didactic-session",
				Name:         "didactic-session",
				Type:         model.SkillTypeClaudeCodeSkill,
				SourcePath:   "/Users/kamir/.claude/skills/didactic-session",
				ContentHash:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				ContentSizeBytes: 1024,
				Tier:         "user",
				Frontmatter: &model.Frontmatter{
					Name:            "didactic-session",
					Version:         "1.0.0",
					Description:     "test",
					GovernanceLevel: "yellow",
				},
			},
			{
				ID:          "fetch-contract",
				Name:        "fetch-contract",
				Type:        model.SkillTypeClaudeCodeSkill,
				SourcePath:  "/Users/kamir/.claude/skills/fetch-contract",
				ContentHash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				Tier:        "user",
				Frontmatter: &model.Frontmatter{
					Name:    "fetch-contract",
					Version: "0.9.0",
					Metadata: map[string]interface{}{
						"intent": map[string]interface{}{
							"summary":      "fetch a contract",
							"side_effects": []interface{}{"read"},
						},
					},
				},
			},
		},
		ByType:    map[string]int{"claude_code_skill": 2},
		ByProject: map[string]int{"user-global": 2},
	}
}

func baseOpts(t *testing.T) Opts {
	t.Helper()
	return Opts{
		Inventory:               sampleInventory(t),
		RegistryURL:             "https://registry.example.com/api/skills",
		SessionTag:              "skill-awareness/testhost/2026-05-06",
		AuthorIdentity:          "id:tester@m3c",
		AuthorPubkeyFingerprint: "sha256:deadbeef",
		AuthorSigner:            stubSigner,
		Now:                     func() time.Time { return time.Date(2026, 5, 6, 10, 0, 0, 0, time.UTC) },
		Hostname:                func() (string, error) { return "testhost", nil },
		Ctx:                     context.Background(),
	}
}

// TestBuildEnvelope_Spec0195_5_1_Shape pins the SPEC-0195 §5.1 envelope
// JSON shape. If the spec changes, this fixture has to change too.
func TestBuildEnvelope_Spec0195_5_1_Shape(t *testing.T) {
	o := applyOptDefaults(baseOpts(t))
	env, skipped, err := BuildEnvelope(o)
	if err != nil {
		t.Fatalf("BuildEnvelope: %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("expected no local skips, got %v", skipped)
	}
	if env.SessionTag != o.SessionTag {
		t.Errorf("SessionTag = %q, want %q", env.SessionTag, o.SessionTag)
	}
	if env.ClientIdentity != o.AuthorIdentity {
		t.Errorf("ClientIdentity = %q, want %q", env.ClientIdentity, o.AuthorIdentity)
	}
	if env.ClientPubkeyFingerprint != o.AuthorPubkeyFingerprint {
		t.Errorf("ClientPubkeyFingerprint mismatch")
	}
	if env.EnvelopeVersion != EnvelopeVersion {
		t.Errorf("EnvelopeVersion = %q, want %q", env.EnvelopeVersion, EnvelopeVersion)
	}
	if got, want := len(env.Skills), 2; got != want {
		t.Fatalf("len(Skills) = %d, want %d", got, want)
	}

	// Pin the wire-level field set on a single skill.
	js, _ := json.Marshal(env.Skills[0])
	keys := []string{"name", "skill_md_sha256", "tier", "source_path", "client_signature_b64"}
	for _, k := range keys {
		if !strings.Contains(string(js), `"`+k+`"`) {
			t.Errorf("skill[0] missing wire field %q in %s", k, js)
		}
	}
}

// TestResolveRegistry_Precedence: flag > trust-roots > env > error.
func TestResolveRegistry_Precedence(t *testing.T) {
	t.Setenv(DefaultRegistryEnv, "")

	t.Run("flag wins", func(t *testing.T) {
		t.Setenv(DefaultRegistryEnv, "https://from-env.example/api/skills")
		tr := &verify.TrustRoots{DefaultRegistry: "https://from-tr.example/api/skills"}
		got, err := ResolveRegistry("https://from-flag.example/api/skills", tr)
		if err != nil {
			t.Fatal(err)
		}
		if got != "https://from-flag.example/api/skills" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("trust-roots wins over env", func(t *testing.T) {
		t.Setenv(DefaultRegistryEnv, "https://from-env.example/api/skills")
		tr := &verify.TrustRoots{DefaultRegistry: "https://from-tr.example/api/skills"}
		got, err := ResolveRegistry("", tr)
		if err != nil {
			t.Fatal(err)
		}
		if got != "https://from-tr.example/api/skills" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("env when no trust-roots", func(t *testing.T) {
		t.Setenv(DefaultRegistryEnv, "https://from-env.example/api/skills")
		got, err := ResolveRegistry("", nil)
		if err != nil {
			t.Fatal(err)
		}
		if got != "https://from-env.example/api/skills" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("error when nothing set", func(t *testing.T) {
		t.Setenv(DefaultRegistryEnv, "")
		_, err := ResolveRegistry("", nil)
		if err == nil {
			t.Fatal("want error, got nil")
		}
	})
}

// TestSync_DryRun_NoHTTP: --dry-run produces an envelope and makes zero
// HTTP requests. We give Sync a server that records every hit, then
// assert nothing landed there.
func TestSync_DryRun_NoHTTP(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	var stdout strings.Builder
	o := baseOpts(t)
	o.RegistryURL = srv.URL + "/api/skills"
	o.DryRun = true
	o.Stdout = &stdout
	o.HTTPClient = srv.Client()

	res, err := Sync(o)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if hits != 0 {
		t.Fatalf("expected 0 HTTP hits, got %d", hits)
	}
	if res.Response != nil {
		t.Errorf("expected nil Response on dry-run, got %+v", res.Response)
	}
	if !strings.Contains(stdout.String(), `"name":"didactic-session"`) {
		t.Errorf("stdout missing skill dump:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), `"session_tag"`) {
		t.Errorf("stdout missing envelope dump:\n%s", stdout.String())
	}
}

// TestSync_DevSeedAgainstProd_RefusesPreflight: §6.1 client-side
// short-circuit. The HTTP server should never be hit.
func TestSync_DevSeedAgainstProd_RefusesPreflight(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	o := baseOpts(t)
	o.RegistryURL = srv.URL + "/api/skills"
	o.AuthorIdentity = DevSeedSentinel
	o.TrustRoots = &verify.TrustRoots{Environment: "prod"}
	o.Confirm = true
	o.HTTPClient = srv.Client()

	_, err := Sync(o)
	if !errors.Is(err, ErrDevSeedAgainstProd()) {
		t.Fatalf("expected ErrDevSeedAgainstProd, got %v", err)
	}
	if hits != 0 {
		t.Errorf("expected 0 HTTP hits, got %d", hits)
	}
}

// TestSync_DevSeedAgainstNonProd_AllowsPreflight: dev-seed against a
// non-prod environment is permitted (the gate is dev-seed-against-PROD,
// not dev-seed-anywhere).
func TestSync_DevSeedAgainstNonProd_AllowsPreflight(t *testing.T) {
	o := applyOptDefaults(baseOpts(t))
	o.AuthorIdentity = DevSeedSentinel
	o.TrustRoots = &verify.TrustRoots{Environment: "dev"}

	env, _, err := BuildEnvelope(o)
	if err != nil {
		t.Fatalf("BuildEnvelope: %v", err)
	}
	if err := shortCircuitIfDevSeedProd(env, o.TrustRoots); err != nil {
		t.Fatalf("shortCircuit: %v (want nil for env=dev)", err)
	}
	// And nil trust-roots is also permitted.
	if err := shortCircuitIfDevSeedProd(env, nil); err != nil {
		t.Fatalf("shortCircuit nil tr: %v", err)
	}
}

// TestSync_LiveRoundTrip: a happy-path POST to a fake server returning a
// SPEC-0195 §5.2 response. Verifies the URL, the request body, and the
// decoded response.
func TestSync_LiveRoundTrip(t *testing.T) {
	var seenPath string
	var seenBody SyncEnvelope
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.Method + " " + r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&seenBody)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(SyncResponse{
			SessionTag: seenBody.SessionTag,
			Admitted: []AdmittedRow{
				{Name: "didactic-session", LocalDigest: "sha256:aaaa", Status: "admitted"},
				{Name: "fetch-contract", LocalDigest: "sha256:bbbb", Status: "admitted"},
			},
			Summary: SyncSummary{Received: 2, Admitted: 2, Skipped: 0},
		})
	}))
	defer srv.Close()

	o := baseOpts(t)
	o.RegistryURL = srv.URL + "/api/skills"
	o.HTTPClient = srv.Client()
	o.Confirm = true

	res, err := Sync(o)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if seenPath != "POST /api/skills/admit-from-scan" {
		t.Errorf("seenPath = %q", seenPath)
	}
	if got := len(seenBody.Skills); got != 2 {
		t.Errorf("server saw %d skills, want 2", got)
	}
	if res.Response == nil {
		t.Fatal("expected non-nil Response")
	}
	if got := res.Response.Summary.Admitted; got != 2 {
		t.Errorf("admitted = %d, want 2", got)
	}
}

// TestSync_DefaultAttest_TriggersAttestCall: --default-attest yellow
// follows up the sync with a POST /admit-from-scan/attest.
func TestSync_DefaultAttest_TriggersAttestCall(t *testing.T) {
	var attestSeen bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/skills/admit-from-scan":
			_ = json.NewEncoder(w).Encode(SyncResponse{
				SessionTag: "skill-awareness/testhost/2026-05-06",
				Summary:    SyncSummary{Admitted: 2, Received: 2},
			})
		case "/api/skills/admit-from-scan/attest":
			attestSeen = true
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"session_tag": "skill-awareness/testhost/2026-05-06",
				"attested":    2,
			})
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	o := baseOpts(t)
	o.RegistryURL = srv.URL + "/api/skills"
	o.HTTPClient = srv.Client()
	o.Confirm = true
	o.DefaultAttest = AttestYellow

	res, err := Sync(o)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if !attestSeen {
		t.Errorf("attest endpoint was not called")
	}
	if res.Attestation == nil {
		t.Fatal("expected non-nil Attestation")
	}
	if got := res.Attestation.Attested; got != 2 {
		t.Errorf("Attested = %d, want 2", got)
	}
}

// TestVerify_ReadsBackAdmissions: smoke test for the verify subcommand
// path — fake server returns a list, helper prints one line per skill.
func TestVerify_ReadsBackAdmissions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("session"); got != "skill-awareness/testhost/2026-05-06" {
			t.Errorf("server saw session=%q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(VerifyResponse{
			SessionTag: "skill-awareness/testhost/2026-05-06",
			Admitted: []AdmittedRow{
				{Name: "didactic-session", LocalDigest: "sha256:aaa", Status: "admitted"},
			},
			Summary: SyncSummary{Admitted: 1, ByTier: map[string]int{"user": 1}},
		})
	}))
	defer srv.Close()

	var stdout strings.Builder
	resp, err := Verify(VerifyOpts{
		RegistryURL: srv.URL + "/api/skills",
		SessionTag:  "skill-awareness/testhost/2026-05-06",
		HTTPClient:  srv.Client(),
		Stdout:      &stdout,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if resp.Summary.Admitted != 1 {
		t.Errorf("Summary.Admitted = %d", resp.Summary.Admitted)
	}
	if !strings.Contains(stdout.String(), "didactic-session") {
		t.Errorf("stdout missing skill: %s", stdout.String())
	}
}

// TestSync_RequireIntent_RejectsSentinel: --require-intent + UNKNOWN
// sentinel → server NEVER sees the bad row.
func TestSync_RequireIntent_RejectsSentinel(t *testing.T) {
	inv := &model.Inventory{
		Skills: []model.SkillDescriptor{
			{
				ID: "good", Name: "good", ContentHash: strings.Repeat("c", 64),
				Tier: "user",
				Frontmatter: &model.Frontmatter{
					Name: "good",
					Metadata: map[string]interface{}{
						"intent": map[string]interface{}{
							"summary":      "real intent",
							"side_effects": []interface{}{"read"},
						},
					},
				},
			},
			{
				ID: "unknown", Name: "unknown", ContentHash: strings.Repeat("d", 64),
				Tier: "user",
				Frontmatter: &model.Frontmatter{
					Name: "unknown",
					Metadata: map[string]interface{}{
						"intent": map[string]interface{}{
							"side_effects": []interface{}{"UNKNOWN"},
						},
					},
				},
			},
			{
				ID: "no-intent", Name: "no-intent", ContentHash: strings.Repeat("e", 64),
				Tier:        "user",
				Frontmatter: &model.Frontmatter{Name: "no-intent"},
			},
		},
	}
	o := applyOptDefaults(baseOpts(t))
	o.Inventory = inv
	o.RequireIntent = true

	env, skipped, err := BuildEnvelope(o)
	if err != nil {
		t.Fatalf("BuildEnvelope: %v", err)
	}
	if len(env.Skills) != 1 || env.Skills[0].Name != "good" {
		t.Errorf("expected only %q in envelope, got %d skills", "good", len(env.Skills))
	}
	if len(skipped) != 2 {
		t.Errorf("expected 2 local skips, got %d: %+v", len(skipped), skipped)
	}
	gotReasons := map[string]bool{}
	for _, s := range skipped {
		gotReasons[s.FailedRule] = true
	}
	if !gotReasons["side_effects_unknown_sentinel"] {
		t.Error("missing side_effects_unknown_sentinel reason")
	}
	if !gotReasons["missing_intent_block"] {
		t.Error("missing missing_intent_block reason")
	}
}

// TestSync_DefaultIntentYellow_StampsAll: --default-intent yellow stamps
// the gov level on every entry whose intent was missing or UNKNOWN.
// The "real intent" entry stays as-is.
func TestSync_DefaultIntentYellow_StampsAll(t *testing.T) {
	inv := &model.Inventory{
		Skills: []model.SkillDescriptor{
			{
				ID: "real", Name: "real", ContentHash: strings.Repeat("a", 64),
				Frontmatter: &model.Frontmatter{
					Name: "real",
					Metadata: map[string]interface{}{
						"intent": map[string]interface{}{
							"summary":      "real",
							"side_effects": []interface{}{"read"},
						},
					},
				},
			},
			{
				ID: "unknown", Name: "unknown", ContentHash: strings.Repeat("b", 64),
				Frontmatter: &model.Frontmatter{
					Name: "unknown",
					Metadata: map[string]interface{}{
						"intent": map[string]interface{}{
							"side_effects": []interface{}{"UNKNOWN"},
						},
					},
				},
			},
			{
				ID: "no-intent", Name: "no-intent", ContentHash: strings.Repeat("c", 64),
				Frontmatter: &model.Frontmatter{Name: "no-intent"},
			},
		},
	}
	o := applyOptDefaults(baseOpts(t))
	o.Inventory = inv
	o.DefaultIntentLevel = "yellow"

	env, skipped, err := BuildEnvelope(o)
	if err != nil {
		t.Fatalf("BuildEnvelope: %v", err)
	}
	if len(skipped) != 0 {
		t.Errorf("expected 0 local skips with --default-intent, got %d: %+v", len(skipped), skipped)
	}
	if len(env.Skills) != 3 {
		t.Fatalf("expected 3 skills, got %d", len(env.Skills))
	}
	// real should stay as-is — no _default_intent_source key.
	for _, sk := range env.Skills {
		switch sk.Name {
		case "real":
			if _, stamped := sk.Intent["_default_intent_source"]; stamped {
				t.Errorf("real skill got default-intent stamp; should have been skipped")
			}
			if got, _ := sk.Intent["governance_level"].(string); got == "yellow" {
				t.Errorf("real skill governance_level got overwritten to yellow")
			}
		case "unknown", "no-intent":
			if _, stamped := sk.Intent["_default_intent_source"]; !stamped {
				t.Errorf("%s did NOT receive default-intent stamp", sk.Name)
			}
			if got, _ := sk.Intent["governance_level"].(string); got != "yellow" {
				t.Errorf("%s governance_level = %q, want yellow", sk.Name, got)
			}
		}
	}
}

// TestSync_InventoryFromStdinShape — Sync doesn't read stdin itself; the
// CLI does, but the package-level invariant is that an inventory built
// from stdin and one built from a file produce the SAME envelope. This
// test asserts the BuildEnvelope output is deterministic given a stable
// inventory + signer + identity.
func TestBuildEnvelope_DeterministicShape(t *testing.T) {
	o1 := applyOptDefaults(baseOpts(t))
	env1, _, err := BuildEnvelope(o1)
	if err != nil {
		t.Fatalf("BuildEnvelope #1: %v", err)
	}
	js1, err := CanonicalEnvelopeJSON(env1)
	if err != nil {
		t.Fatal(err)
	}

	o2 := applyOptDefaults(baseOpts(t))
	env2, _, err := BuildEnvelope(o2)
	if err != nil {
		t.Fatalf("BuildEnvelope #2: %v", err)
	}
	js2, err := CanonicalEnvelopeJSON(env2)
	if err != nil {
		t.Fatal(err)
	}
	if js1 != js2 {
		t.Errorf("envelope JSON not deterministic:\n#1: %s\n#2: %s", js1, js2)
	}
}

// TestResolveSessionTag_Default: default tag uses host + UTC date.
func TestResolveSessionTag_Default(t *testing.T) {
	o := baseOpts(t)
	o.SessionTag = ""
	got, err := resolveSessionTag(applyOptDefaults(o))
	if err != nil {
		t.Fatal(err)
	}
	want := "skill-awareness/testhost/2026-05-06"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestValidateOpts_RejectsObviousMisuse — the 6 required fields fail loud.
func TestValidateOpts_RejectsObviousMisuse(t *testing.T) {
	cases := []struct {
		name string
		mut  func(o *Opts)
	}{
		{"no inventory", func(o *Opts) { o.Inventory = nil }},
		{"no registry", func(o *Opts) { o.RegistryURL = "" }},
		{"no identity", func(o *Opts) { o.AuthorIdentity = "" }},
		{"no fingerprint", func(o *Opts) { o.AuthorPubkeyFingerprint = "" }},
		{"no signer", func(o *Opts) { o.AuthorSigner = nil }},
		{"bad attest level", func(o *Opts) { o.DefaultAttest = "purple" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := applyOptDefaults(baseOpts(t))
			c.mut(&o)
			if err := validateOpts(o); err == nil {
				t.Errorf("expected error for %s", c.name)
			}
		})
	}
}

// Sanity: package's exported constants are stable.
func TestPackageConstants(t *testing.T) {
	if EnvelopeVersion != "awareness/v1" {
		t.Errorf("EnvelopeVersion = %q", EnvelopeVersion)
	}
	if DevSeedSentinel != "id:dev-skill-awareness@m3c" {
		t.Errorf("DevSeedSentinel = %q", DevSeedSentinel)
	}
	if EnvProdEnvironment != "prod" {
		t.Errorf("EnvProdEnvironment = %q", EnvProdEnvironment)
	}
	// Belt-and-braces: ensure default attest sentinel is the empty
	// sentinel we expect at the wire layer.
	if !AttestYellow.IsCallable() || !AttestGreen.IsCallable() || AttestNone.IsCallable() {
		t.Errorf("AttestLevel.IsCallable matrix wrong")
	}
	// Compile-time ref to keep `os` in the import list when we
	// otherwise don't use it from the test.
	_ = os.Getenv("PATH")
}
