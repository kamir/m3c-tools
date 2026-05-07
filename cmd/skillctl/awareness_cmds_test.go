package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/awareness"
	"github.com/kamir/m3c-tools/pkg/skillctl/model"
)

// writeInventoryFile writes a minimal scanner inventory to a temp file
// and returns the path. Used by every test that needs to drive
// `awareness sync --inventory <file>`.
func writeInventoryFile(t *testing.T) string {
	t.Helper()
	inv := model.Inventory{
		ScannedAt:  "2026-05-06T10:00:00Z",
		ScanPaths:  []string{"/tmp/skills"},
		TotalCount: 2,
		Skills: []model.SkillDescriptor{
			{
				ID:           "didactic-session",
				Name:         "didactic-session",
				Type:         model.SkillTypeClaudeCodeSkill,
				SourcePath:   "/tmp/skills/didactic-session",
				ContentHash:  strings.Repeat("a", 64),
				ContentSizeBytes: 100,
				Tier:         "user",
				Frontmatter: &model.Frontmatter{
					Name:            "didactic-session",
					Version:         "1.0.0",
					GovernanceLevel: "yellow",
					Metadata: map[string]interface{}{
						"intent": map[string]interface{}{
							"summary":      "didactic",
							"side_effects": []interface{}{"read"},
						},
					},
				},
			},
			{
				ID:          "fetch-contract",
				Name:        "fetch-contract",
				Type:        model.SkillTypeClaudeCodeSkill,
				SourcePath:  "/tmp/skills/fetch-contract",
				ContentHash: strings.Repeat("b", 64),
				Tier:        "user",
				Frontmatter: &model.Frontmatter{
					Name:    "fetch-contract",
					Version: "0.9.0",
					Metadata: map[string]interface{}{
						"intent": map[string]interface{}{
							"summary":      "fetch",
							"side_effects": []interface{}{"read"},
						},
					},
				},
			},
		},
		ByType:    map[string]int{"claude_code_skill": 2},
		ByProject: map[string]int{"user-global": 2},
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "inv.json")
	body, err := json.MarshalIndent(inv, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// withDevSeed enables the deterministic dev-seed identity path so tests
// don't need an on-disk author key.
func withDevSeed(t *testing.T) {
	t.Helper()
	t.Setenv("SKILLCTL_DEV_SEED", "dev:skill-awareness:s2")
}

// isolateHome points HOME at a clean temp dir so a developer's real
// ~/.claude/skill-trust-roots.yaml doesn't leak into the test.
func isolateHome(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(tmp, ".claude"))
	return tmp
}

// TestAwarenessSync_DryRun_NoHTTP — `awareness sync --dry-run --inventory FILE`
// makes ZERO HTTP requests against a mock server.
func TestAwarenessSync_DryRun_NoHTTP(t *testing.T) {
	withDevSeed(t)
	isolateHome(t)
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	invPath := writeInventoryFile(t)
	args := []string{"sync",
		"--inventory", invPath,
		"--registry", srv.URL + "/api/skills",
		"--dry-run",
	}
	var stdout, stderr bytes.Buffer
	code := runAwareness(args, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; stderr=%s", code, exitOK, stderr.String())
	}
	if hits != 0 {
		t.Errorf("expected 0 HTTP hits in dry-run, got %d", hits)
	}
	if !strings.Contains(stdout.String(), `"name":"didactic-session"`) {
		t.Errorf("stdout missing skill JSON line:\n%s", stdout.String())
	}
}

// TestAwarenessSync_EnvelopeMatchesSpec0195_5_1 — assert the envelope's
// JSON keys verbatim match SPEC-0195 §5.1.
func TestAwarenessSync_EnvelopeMatchesSpec0195_5_1(t *testing.T) {
	withDevSeed(t)
	isolateHome(t)
	invPath := writeInventoryFile(t)

	args := []string{"sync",
		"--inventory", invPath,
		"--registry", "https://example.com/api/skills",
		"--dry-run",
	}
	var stdout, stderr bytes.Buffer
	if code := runAwareness(args, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit %d; stderr=%s", code, stderr.String())
	}
	out := stdout.String()
	for _, k := range []string{
		`"session_tag"`,
		`"client_identity"`,
		`"client_pubkey_fingerprint"`,
		`"skills"`,
		`"skill_md_sha256"`,
		`"frontmatter"`,
		`"client_signature_b64"`,
	} {
		if !strings.Contains(out, k) {
			t.Errorf("dry-run output missing wire field %s\n--- output ---\n%s", k, out)
		}
	}
}

// TestAwarenessSync_InventoryFromStdin — `--inventory -` reads from stdin.
// We verify by intercepting stdin via the loadAwarenessInventory helper.
func TestAwarenessSync_InventoryFromStdin(t *testing.T) {
	invPath := writeInventoryFile(t)
	body, err := os.ReadFile(invPath)
	if err != nil {
		t.Fatal(err)
	}
	// Swap stdin for a pipe carrying the inventory bytes.
	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()
	go func() {
		defer w.Close()
		_, _ = w.Write(body)
	}()

	inv, err := loadAwarenessInventory("-", "")
	if err != nil {
		t.Fatalf("loadAwarenessInventory: %v", err)
	}
	if inv.TotalCount != 2 {
		t.Errorf("TotalCount = %d, want 2", inv.TotalCount)
	}
	if len(inv.Skills) != 2 || inv.Skills[0].Name != "didactic-session" {
		t.Errorf("skills not decoded as expected: %+v", inv.Skills)
	}
}

// TestAwarenessSync_RegistryResolutionPrecedence —
// flag > trust-roots default_registry > $M3C_REGISTRY_URL > error.
func TestAwarenessSync_RegistryResolutionPrecedence(t *testing.T) {
	// Exercise the public ResolveRegistry helper that the CLI uses.
	t.Run("flag wins over env", func(t *testing.T) {
		t.Setenv(awareness.DefaultRegistryEnv, "https://from-env.example/api/skills")
		got, err := awareness.ResolveRegistry("https://flag.example/api/skills", nil)
		if err != nil || got != "https://flag.example/api/skills" {
			t.Errorf("got %q err=%v", got, err)
		}
	})
	t.Run("env when no flag and no trust-roots", func(t *testing.T) {
		t.Setenv(awareness.DefaultRegistryEnv, "https://from-env.example/api/skills")
		got, err := awareness.ResolveRegistry("", nil)
		if err != nil || got != "https://from-env.example/api/skills" {
			t.Errorf("got %q err=%v", got, err)
		}
	})
	t.Run("error when nothing is set", func(t *testing.T) {
		t.Setenv(awareness.DefaultRegistryEnv, "")
		_, err := awareness.ResolveRegistry("", nil)
		if err == nil {
			t.Error("want error, got nil")
		}
	})
}

// TestAwarenessSync_RequireIntent_RejectsSentinel — --require-intent
// causes UNKNOWN-sentinel skills to be locally skipped (server never
// sees them).
func TestAwarenessSync_RequireIntent_RejectsSentinel(t *testing.T) {
	withDevSeed(t)
	isolateHome(t)

	inv := model.Inventory{
		Skills: []model.SkillDescriptor{
			{
				ID: "good", Name: "good", ContentHash: strings.Repeat("a", 64),
				Frontmatter: &model.Frontmatter{
					Name: "good",
					Metadata: map[string]interface{}{
						"intent": map[string]interface{}{
							"summary":      "good",
							"side_effects": []interface{}{"read"},
						},
					},
				},
			},
			{
				ID: "bad", Name: "bad", ContentHash: strings.Repeat("b", 64),
				Frontmatter: &model.Frontmatter{
					Name: "bad",
					Metadata: map[string]interface{}{
						"intent": map[string]interface{}{
							"side_effects": []interface{}{"UNKNOWN"},
						},
					},
				},
			},
		},
	}
	dir := t.TempDir()
	invPath := filepath.Join(dir, "inv.json")
	body, _ := json.Marshal(inv)
	if err := os.WriteFile(invPath, body, 0o600); err != nil {
		t.Fatal(err)
	}

	args := []string{"sync",
		"--inventory", invPath,
		"--registry", "https://example.com/api/skills",
		"--require-intent",
		"--dry-run",
	}
	var stdout, stderr bytes.Buffer
	if code := runAwareness(args, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit %d; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"name":"good"`) {
		t.Errorf("expected good skill in envelope dump")
	}
	if strings.Contains(stdout.String(), `"client_signature_b64"`) &&
		strings.Contains(stdout.String(), `"name":"bad"`) {
		t.Errorf("bad skill should NOT appear with a signature in envelope")
	}
}

// TestAwarenessSync_DefaultIntentYellow_StampsAll — --default-intent yellow
// stamps the level on entries with no/UNKNOWN intent so they pass the gate.
func TestAwarenessSync_DefaultIntentYellow_StampsAll(t *testing.T) {
	withDevSeed(t)
	isolateHome(t)

	inv := model.Inventory{
		Skills: []model.SkillDescriptor{
			{
				ID: "no-intent", Name: "no-intent",
				ContentHash: strings.Repeat("c", 64),
				Frontmatter: &model.Frontmatter{Name: "no-intent"},
			},
			{
				ID: "unknown", Name: "unknown",
				ContentHash: strings.Repeat("d", 64),
				Frontmatter: &model.Frontmatter{
					Name: "unknown",
					Metadata: map[string]interface{}{
						"intent": map[string]interface{}{
							"side_effects": []interface{}{"UNKNOWN"},
						},
					},
				},
			},
		},
	}
	dir := t.TempDir()
	invPath := filepath.Join(dir, "inv.json")
	body, _ := json.Marshal(inv)
	if err := os.WriteFile(invPath, body, 0o600); err != nil {
		t.Fatal(err)
	}

	args := []string{"sync",
		"--inventory", invPath,
		"--registry", "https://example.com/api/skills",
		"--default-intent", "yellow",
		"--dry-run",
	}
	var stdout, stderr bytes.Buffer
	if code := runAwareness(args, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit %d; stderr=%s", code, stderr.String())
	}
	out := stdout.String()
	// Both skills should appear, AND the yellow stamp marker should
	// be in the envelope.
	for _, name := range []string{"no-intent", "unknown"} {
		if !strings.Contains(out, `"name":"`+name+`"`) {
			t.Errorf("missing %q in envelope dump", name)
		}
	}
	if !strings.Contains(out, `"_default_intent_source"`) {
		t.Errorf("envelope missing _default_intent_source marker")
	}
}

// TestAwarenessSync_DevSeedAgainstProd_RefusesPreflight — S2.6 client
// short-circuit. We write a fake trust-roots file with _environment: prod
// and confirm the CLI refuses to issue ANY HTTP request.
func TestAwarenessSync_DevSeedAgainstProd_RefusesPreflight(t *testing.T) {
	withDevSeed(t)
	tmp := isolateHome(t)

	// Write a trust-roots file with a single registry pinned + prod env.
	cfgDir := filepath.Join(tmp, ".claude")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	trustYAML := `trust_roots:
  - registry_url: https://prod.example.com/api/skills
    registry_keys:
      - id: prod-key
        pubkey: ` + base64Stub32() + `
        issued: 2026-05-06
    identity_keys_authorized: from-registry
    governance_minimum: green
default_registry: https://prod.example.com/api/skills
_environment: prod
`
	if err := os.WriteFile(filepath.Join(cfgDir, "skill-trust-roots.yaml"), []byte(trustYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	invPath := writeInventoryFile(t)
	args := []string{"sync",
		"--inventory", invPath,
		"--registry", srv.URL + "/api/skills", // not the prod URL but env still says prod
		"--confirm",
	}
	var stdout, stderr bytes.Buffer
	code := runAwareness(args, &stdout, &stderr)
	if code != exitUsage {
		t.Errorf("exit code = %d, want %d (dev-seed against prod refused)", code, exitUsage)
	}
	if hits != 0 {
		t.Errorf("expected 0 HTTP hits, got %d (server should never be reached)", hits)
	}
	if !strings.Contains(stderr.String(), "dev-seed identity") {
		t.Errorf("expected dev-seed error in stderr, got: %s", stderr.String())
	}
}

// TestScan_PushToRegistry_DelegatesToAwarenessSync — SPEC-0189 §13
// acceptance #6: scan --push-to-registry --dry-run-push produces the
// same envelope shape as awareness sync --dry-run from the same
// inventory.
func TestScan_PushToRegistry_DelegatesToAwarenessSync(t *testing.T) {
	withDevSeed(t)
	isolateHome(t)

	// Build an inventory in-memory and run the delegate directly. The
	// full cmdScan path goes through the scanner against the live
	// filesystem; we exercise the post-scan delegate (the only piece
	// that's new) deterministically.
	inv := &model.Inventory{
		ScannedAt:  "2026-05-06T10:00:00Z",
		TotalCount: 1,
		Skills: []model.SkillDescriptor{
			{
				ID: "didactic-session", Name: "didactic-session",
				ContentHash: strings.Repeat("a", 64),
				Tier:        "user",
				Frontmatter: &model.Frontmatter{
					Name: "didactic-session", Version: "1.0.0",
					Metadata: map[string]interface{}{
						"intent": map[string]interface{}{
							"summary":      "didactic",
							"side_effects": []interface{}{"read"},
						},
					},
				},
			},
		},
	}

	// Capture the stderr (the delegate dumps the envelope to stderr in
	// dry-run-push mode per §13.4 #7).
	r, w, _ := os.Pipe()
	oldStderr := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = oldStderr }()

	exit := runScanPushToRegistry(inv, "https://example.com/api/skills", "none", true)
	w.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)

	if exit != exitOK {
		t.Errorf("runScanPushToRegistry exit = %d; want %d; output:\n%s", exit, exitOK, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, `"client_identity"`) {
		t.Errorf("envelope missing client_identity in scan delegate output:\n%s", out)
	}
	if !strings.Contains(out, `"skill_md_sha256"`) {
		t.Errorf("envelope missing skill_md_sha256:\n%s", out)
	}
}

// TestAwarenessVerify_ReadsBackAdmissions — `awareness verify` reads
// /admit-from-scan?session=<tag> and prints the summary.
func TestAwarenessVerify_ReadsBackAdmissions(t *testing.T) {
	isolateHome(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/skills/admit-from-scan" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("session"); got != "skill-awareness/host/2026-05-06" {
			t.Errorf("server saw session=%q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(awareness.VerifyResponse{
			SessionTag: "skill-awareness/host/2026-05-06",
			Admitted: []awareness.AdmittedRow{
				{Name: "didactic-session", LocalDigest: "sha256:aaa", Status: "admitted"},
			},
			Summary: awareness.SyncSummary{Admitted: 1, ByTier: map[string]int{"user": 1}},
		})
	}))
	defer srv.Close()

	args := []string{"verify",
		"--registry", srv.URL + "/api/skills",
		"--session", "skill-awareness/host/2026-05-06",
	}
	var stdout, stderr bytes.Buffer
	code := runAwareness(args, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit %d; stderr=%s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "didactic-session") {
		t.Errorf("verify output missing skill name:\n%s", out)
	}
	if !strings.Contains(out, "admitted: 1") {
		t.Errorf("verify output missing admitted count:\n%s", out)
	}
}

// base64Stub32 returns a base64 of 32 zero bytes — a syntactically valid
// (but functionally inert) ed25519 public key for trust-roots fixture
// purposes. The trust-roots loader's only check is "decodes to 32 bytes",
// which this satisfies.
func base64Stub32() string {
	return "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
}
