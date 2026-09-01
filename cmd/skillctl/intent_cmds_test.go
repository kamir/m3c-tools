package main

// Stream S2-M2 tests for `skillctl intent declare`.
//
// Coverage matrix (from S2-QUESTIONS.md §5.A acceptance plan):
//
//   TestIntentDeclare_BuildsPatchPayload   — flag values flow into PATCH body
//   TestIntentDeclare_FromYaml             — --from-yaml supplies base layer
//   TestIntentDeclare_DryRunPrintsNoHTTP   — --dry-run is strictly non-side-effecting
//   TestIntentDeclare_CrossRuleViolationExits18 — 400 → exit 18
//   TestIntentDeclare_FailsWithoutConfirm  — refuses without --confirm
//
// Pattern: most tests drive `runIntentDeclareWithClient` directly with a
// pre-built `intentDeclareOpts`, including an httptest.Server-backed
// http.Client when network behavior matters. This avoids the flag-parser
// for tests that aren't testing flag-parsing.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newIntentTestServer wires an httptest.Server that mirrors what Stream A's
// PATCH endpoint will return for the relevant cases. The handler asserts
// the request shape and lets each test pre-configure the response code +
// body via the mode parameter.
func newIntentTestServer(t *testing.T, mode string, captured *intentDeclareReq) *httptest.Server {
	t.Helper()
	h := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !strings.Contains(r.URL.Path, "/bundles/") || !strings.HasSuffix(r.URL.Path, "/intent") {
			http.Error(w, "wrong path: "+r.URL.Path, http.StatusNotFound)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "read: "+err.Error(), http.StatusBadRequest)
			return
		}
		var req intentDeclareReq
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "decode: "+err.Error(), http.StatusBadRequest)
			return
		}
		if captured != nil {
			*captured = req
		}
		switch mode {
		case "ok":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "cross_rule":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"reason":"intent_data_inconsistent","failed_rule":"network_false_http_dep","detail":"HTTP dep contradicts network=false"}`))
		default:
			http.Error(w, "unknown mode "+mode, http.StatusInternalServerError)
		}
	}
	return httptest.NewServer(http.HandlerFunc(h))
}

func TestIntentDeclare_BuildsPatchPayload(t *testing.T) {
	// Goal: flag-derived intent block flows into the PATCH body unchanged.
	// We bypass the flag-parser and feed the runner directly so we can
	// assert the wire shape against the captured request.
	var captured intentDeclareReq
	srv := newIntentTestServer(t, "ok", &captured)
	defer srv.Close()

	opts := intentDeclareOpts{
		skill:       "@sha256:" + strings.Repeat("a", 64),
		registryURL: srv.URL,
		confirm:     true,
		intent: map[string]any{
			"summary":      "test skill",
			"destructive":  false,
			"network":      true,
			"side_effects": []string{"fs:write", "llm:call"},
		},
		dataDeps: []map[string]any{
			// read dep needs no scope; network=true requires an http dep, so
			// include one (valid client-side declaration — the server still
			// gets the PATCH).
			{"id": "ds:filesystem/cwd", "kind": "local_fs", "access": "read"},
			{"id": "ds:http/anthropic", "kind": "http_endpoint", "access": "passthrough", "scope": "https://api.anthropic.com/*"},
		},
		httpClient: srv.Client(),
	}
	var stdout, stderr bytes.Buffer
	code := runIntentDeclareWithClient(opts, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit = %d, want 0; stderr=%q", code, stderr.String())
	}
	if got, want := captured.Intent["summary"], "test skill"; got != want {
		t.Errorf("captured.Intent.summary = %v, want %q", got, want)
	}
	if got := captured.Intent["network"]; got != true {
		t.Errorf("captured.Intent.network = %v, want true", got)
	}
	if got := len(captured.DataDependencies); got != 2 {
		t.Fatalf("captured.DataDependencies len = %d, want 2", got)
	}
	if got := captured.DataDependencies[0]["kind"]; got != "local_fs" {
		t.Errorf("captured DataDeps[0].kind = %v, want local_fs", got)
	}
}

func TestIntentDeclare_FromYaml(t *testing.T) {
	// Goal: --from-yaml provides the base intent + data_dependencies and
	// per-flag overrides are layered on top. The buildIntentFromInputs
	// helper is the unit under test; it's pure (no HTTP) so we assert
	// directly on the returned tuple.
	tmp := t.TempDir()
	yaml := []byte(`
intent:
  summary: "scaffold a session deck"
  destructive: false
  network: false
  side_effects:
    - fs:write
data_dependencies:
  - id: ds:filesystem/decks
    kind: local_fs
    access: write
`)
	yamlPath := filepath.Join(tmp, "intent.yaml")
	if err := os.WriteFile(yamlPath, yaml, 0o600); err != nil {
		t.Fatal(err)
	}

	intent, deps, err := buildIntentFromInputs(yamlPath, "", "true", "", "", "", "", nil)
	if err != nil {
		t.Fatalf("buildIntentFromInputs error: %v", err)
	}
	// summary survives from YAML; destructive overridden via flag.
	if got := intent["summary"]; got != "scaffold a session deck" {
		t.Errorf("intent.summary = %v, want %q", got, "scaffold a session deck")
	}
	if got := intent["destructive"]; got != true {
		t.Errorf("intent.destructive = %v, want true (flag override)", got)
	}
	// data_dependencies came from the YAML.
	if len(deps) != 1 {
		t.Fatalf("data_dependencies len = %d, want 1", len(deps))
	}
	if got := deps[0]["access"]; got != "write" {
		t.Errorf("deps[0].access = %v, want write", got)
	}
}

func TestIntentDeclare_DryRunPrintsNoHTTP(t *testing.T) {
	// Goal: --dry-run never opens a TCP connection. We point the runner
	// at a registry URL that would 500 if hit, and pre-stage an httptest
	// server we will then assert was NEVER touched.
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Error(w, "should not be called", http.StatusInternalServerError)
	}))
	defer srv.Close()

	opts := intentDeclareOpts{
		skill:       "didactic-session",
		registryURL: srv.URL,
		dryRun:      true,
		intent: map[string]any{
			"summary":     "dry-run preview",
			"destructive": false,
			"network":     false,
		},
		httpClient: srv.Client(),
	}
	var stdout, stderr bytes.Buffer
	code := runIntentDeclareWithClient(opts, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit = %d, want 0; stderr=%q", code, stderr.String())
	}
	if hits != 0 {
		t.Errorf("--dry-run hit the server %d times, want 0", hits)
	}
	if !strings.Contains(stdout.String(), "payload:") {
		t.Errorf("stdout missing payload preview; got: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "didactic-session") {
		t.Errorf("stdout missing skill name; got: %q", stdout.String())
	}
}

func TestIntentDeclare_CrossRuleViolationExits18(t *testing.T) {
	// Goal: a 400 with `reason: intent_data_inconsistent` maps to exit 18.
	srv := newIntentTestServer(t, "cross_rule", nil)
	defer srv.Close()

	opts := intentDeclareOpts{
		skill:       "@sha256:" + strings.Repeat("b", 64),
		registryURL: srv.URL,
		confirm:     true,
		intent: map[string]any{
			"network": false,
		},
		// Client-valid (http dep carries a scope), but the SERVER rejects the
		// network=false ↔ http-dep contradiction → 400 → exit 18. This keeps
		// the test exercising the server-side cross-rule path, not the client
		// one (the client only fires on network=true without an http dep).
		dataDeps: []map[string]any{
			{"id": "ds:http/api", "kind": "http_endpoint", "access": "passthrough", "scope": "https://api.example.com/*"},
		},
		httpClient: srv.Client(),
	}
	var stdout, stderr bytes.Buffer
	code := runIntentDeclareWithClient(opts, &stdout, &stderr)
	if code != 18 {
		t.Fatalf("exit = %d, want 18 (ExitIntentInconsistent); stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "network_false_http_dep") {
		t.Errorf("stderr missing failed_rule; got: %q", stderr.String())
	}
}

func TestIntentDeclare_LocalCrossRuleExits18(t *testing.T) {
	// A §3.3 cross-rule that the CLIENT catches (destructive=true + green)
	// must exit 18 WITHOUT touching the network — the binding can't be
	// bypassed by declaring offline.
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Error(w, "should not be reached", http.StatusInternalServerError)
	}))
	defer srv.Close()

	opts := intentDeclareOpts{
		skill:       "@sha256:" + strings.Repeat("d", 64),
		registryURL: srv.URL,
		confirm:     true,
		governance:  "green",
		intent: map[string]any{
			"destructive":  true,
			"side_effects": []string{"fs:delete"},
		},
		httpClient: srv.Client(),
	}
	var stdout, stderr bytes.Buffer
	code := runIntentDeclareWithClient(opts, &stdout, &stderr)
	if code != 18 {
		t.Fatalf("exit = %d, want 18 (local destructive_green); stderr=%q", code, stderr.String())
	}
	if hits != 0 {
		t.Errorf("client-side cross-rule hit the server %d times, want 0", hits)
	}
	if !strings.Contains(stderr.String(), "destructive_green") {
		t.Errorf("stderr missing failed_rule destructive_green; got %q", stderr.String())
	}
}

func TestIntentDeclare_InvalidScopeIsUsageError(t *testing.T) {
	// A structurally-invalid data-scope (write to local_fs without a scope) is
	// a usage error (exit 2), not an inconsistency (18) — and never reaches
	// the server, even in --dry-run.
	opts := intentDeclareOpts{
		skill:       "@sha256:" + strings.Repeat("e", 64),
		registryURL: "http://127.0.0.1:1",
		dryRun:      true,
		intent: map[string]any{
			"destructive": true,
		},
		dataDeps: []map[string]any{
			{"id": "ds:fs", "kind": "local_fs", "access": "write"}, // no scope → invalid
		},
	}
	var stdout, stderr bytes.Buffer
	code := runIntentDeclareWithClient(opts, &stdout, &stderr)
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d (usage); stderr=%q", code, exitUsage, stderr.String())
	}
}

func TestIntentDeclare_DataScopesFlagParsed(t *testing.T) {
	// The typed --data-scopes flag flows through the flag-parser into the
	// PATCH body. Drive runIntent end-to-end with a captured server.
	var captured intentDeclareReq
	srv := newIntentTestServer(t, "ok", &captured)
	defer srv.Close()

	args := []string{
		"declare",
		"@sha256:" + strings.Repeat("f", 64),
		"--registry", srv.URL,
		"--summary", "typed scope test",
		"--destructive", "true",
		"--side-effects", "fs:write",
		"--data-scopes", `{"id":"ds:fs/out","kind":"local_fs","access":"write","scope":"<cwd>/out/**"}`,
		"--confirm",
	}
	var stdout, stderr bytes.Buffer
	code := runIntent(args, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit = %d, want 0; stderr=%q", code, stderr.String())
	}
	if len(captured.DataDependencies) != 1 {
		t.Fatalf("data deps len = %d, want 1", len(captured.DataDependencies))
	}
	if captured.DataDependencies[0]["scope"] != "<cwd>/out/**" {
		t.Errorf("scope not carried through: %v", captured.DataDependencies[0])
	}
}

func TestIntentDeclare_DataDepAliasStillWorks(t *testing.T) {
	// The deprecated --data-dep alias routes through the SAME validator and
	// reaches the PATCH; a deprecation note is printed to stderr.
	var captured intentDeclareReq
	srv := newIntentTestServer(t, "ok", &captured)
	defer srv.Close()

	args := []string{
		"declare",
		"@sha256:" + strings.Repeat("1", 64),
		"--registry", srv.URL,
		"--summary", "alias test",
		"--side-effects", "fs:read",
		"--data-dep", `{"id":"ds:er1/plm","kind":"er1_collection","access":"read"}`,
		"--confirm",
	}
	var stdout, stderr bytes.Buffer
	code := runIntent(args, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit = %d, want 0; stderr=%q", code, stderr.String())
	}
	if len(captured.DataDependencies) != 1 {
		t.Fatalf("data deps len = %d, want 1", len(captured.DataDependencies))
	}
	if !strings.Contains(stderr.String(), "deprecated") {
		t.Errorf("expected deprecation note for --data-dep; got %q", stderr.String())
	}
}

func TestIntentDeclare_FailsWithoutConfirm(t *testing.T) {
	// Goal: refuse to PATCH without --confirm (footgun-resistance). We
	// drive the flag-parser path here so the --confirm gate is exercised
	// end-to-end.
	args := []string{
		"declare",
		"@sha256:" + strings.Repeat("c", 64),
		"--registry", "http://127.0.0.1:1",
		"--summary", "no-confirm test",
	}
	var stdout, stderr bytes.Buffer
	code := runIntent(args, &stdout, &stderr)
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d (usage); stderr=%q", code, exitUsage, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--confirm") {
		t.Errorf("stderr should mention --confirm; got: %q", stderr.String())
	}
}
