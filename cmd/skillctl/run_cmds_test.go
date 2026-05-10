package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillgate"
)

// makeSignedToken builds a fully-signed token using the same canonicalizer
// as skillgate.Verify. Returns the JSON wire form, the registry key id, and
// the public key.
func makeSignedToken(t *testing.T, env skillgate.TokenEnvelope, expiresIn time.Duration) (jsonBytes []byte, keyID string, pub ed25519.PublicKey) {
	t.Helper()
	pubKey, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	now := time.Now().UTC()
	tok := &skillgate.Token{
		Schema:         "m3c-skill-capability/v1",
		TokenID:        "ct:01HZTESTTESTTESTTESTTESTTE",
		IssuedAt:       now.Format("2006-01-02T15:04:05Z"),
		ExpiresAt:      now.Add(expiresIn).Format("2006-01-02T15:04:05Z"),
		BundleDigest:   "sha256:abc",
		SkillName:      "wrapper-test",
		SkillVersion:   "0.1.0",
		CallerIdentity: "id:tester",
		CallerSession:  "sess:01HZSESSIONSESSIONSESSIO",
		Envelope:       env,
		RegistryKeyID:  "k-test",
		TenantScope:    "tenant-x",
	}
	msg, err := skillgate.CanonicalizeToken(tok)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	tok.SignatureB64 = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))
	b, err := json.Marshal(tok)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b, "k-test", pubKey
}

// writeTrustRoots writes a YAML trust roots file with one key.
func writeTrustRoots(t *testing.T, dir, keyID string, pub ed25519.PublicKey) string {
	t.Helper()
	path := filepath.Join(dir, "trust-roots.yaml")
	contents := "registry_keys:\n  " + keyID + ": " + base64.StdEncoding.EncodeToString(pub) + "\n"
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatalf("write trust roots: %v", err)
	}
	return path
}

func TestRun_TokenNotFound(t *testing.T) {
	tmp := t.TempDir()
	roots := filepath.Join(tmp, "missing.yaml") // also missing — but token check fires first
	rc := runRun([]string{
		"--token", filepath.Join(tmp, "no-such-token.json"),
		"--trust-roots", roots,
		"--target", "local",
		"--", "echo", "hi",
	})
	if rc != skillgate.ExitDataSourceMissing {
		t.Fatalf("want exit %d (token-not-found), got %d", skillgate.ExitDataSourceMissing, rc)
	}
}

func TestRun_VerifyExpired(t *testing.T) {
	tmp := t.TempDir()
	tokenJSON, kid, pub := makeSignedToken(t, skillgate.TokenEnvelope{
		Capabilities:        []string{"subprocess_run:echo"},
		SubprocessAllowlist: []string{"echo"},
	}, -time.Minute) // expired

	tokPath := filepath.Join(tmp, "token.json")
	if err := os.WriteFile(tokPath, tokenJSON, 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	rootsPath := writeTrustRoots(t, tmp, kid, pub)

	rc := runRun([]string{
		"--token", tokPath,
		"--trust-roots", rootsPath,
		"--target", "local",
		"--", "echo", "hi",
	})
	if rc != skillgate.ExitTokenExpired {
		t.Fatalf("want exit %d (expired), got %d", skillgate.ExitTokenExpired, rc)
	}
}

func TestRun_VerifyBadSignature(t *testing.T) {
	tmp := t.TempDir()
	tokenJSON, kid, pub := makeSignedToken(t, skillgate.TokenEnvelope{
		Capabilities:        []string{"subprocess_run:echo"},
		SubprocessAllowlist: []string{"echo"},
	}, time.Hour)

	// Tamper: re-decode JSON, mutate skill_name, re-encode (sig now invalid).
	var tok skillgate.Token
	if err := json.Unmarshal(tokenJSON, &tok); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	tok.SkillName = "tampered"
	b, _ := json.Marshal(&tok)

	tokPath := filepath.Join(tmp, "token.json")
	if err := os.WriteFile(tokPath, b, 0600); err != nil {
		t.Fatalf("write tampered: %v", err)
	}
	rootsPath := writeTrustRoots(t, tmp, kid, pub)

	rc := runRun([]string{
		"--token", tokPath,
		"--trust-roots", rootsPath,
		"--target", "local",
		"--", "echo", "hi",
	})
	if rc != skillgate.ExitFileOutsideEnv {
		t.Fatalf("want exit %d (bad_signature → 34), got %d", skillgate.ExitFileOutsideEnv, rc)
	}
}

func TestRun_HappyPathPostsAuditAndExecsChild(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skip exec test on windows; covered by cross-compile gate")
	}
	tmp := t.TempDir()

	// Stub audit endpoint: capture posted events.
	var (
		mu     sync.Mutex
		posted []runEvent
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ev runEvent
		_ = json.NewDecoder(r.Body).Decode(&ev)
		mu.Lock()
		posted = append(posted, ev)
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	tokenJSON, kid, pub := makeSignedToken(t, skillgate.TokenEnvelope{
		Capabilities:        []string{"subprocess_run:echo"},
		SubprocessAllowlist: []string{"echo"},
	}, time.Hour)
	tokPath := filepath.Join(tmp, "token.json")
	if err := os.WriteFile(tokPath, tokenJSON, 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	rootsPath := writeTrustRoots(t, tmp, kid, pub)

	rc := runRun([]string{
		"--token", tokPath,
		"--trust-roots", rootsPath,
		"--target", "local",
		"--audit-url", srv.URL + "/api/skills/runtime/invocations",
		"--", "echo", "hi",
	})
	if rc != 0 {
		t.Fatalf("want exit 0, got %d", rc)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(posted) != 2 {
		t.Fatalf("want 2 audit events (invoked+completed), got %d", len(posted))
	}
	if posted[0].Type != "skill.invoked" {
		t.Errorf("first event type = %q, want skill.invoked", posted[0].Type)
	}
	if posted[1].Type != "skill.completed" {
		t.Errorf("second event type = %q, want skill.completed", posted[1].Type)
	}
	if posted[1].ExitCode != 0 {
		t.Errorf("completed exit_code = %d, want 0", posted[1].ExitCode)
	}
	if posted[0].TokenID == "" || posted[0].SkillName != "wrapper-test" {
		t.Errorf("event lacks token_id/skill_name: %+v", posted[0])
	}
}

func TestRun_AuditFailureDoesNotBlockChild(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skip exec test on windows")
	}
	tmp := t.TempDir()

	tokenJSON, kid, pub := makeSignedToken(t, skillgate.TokenEnvelope{
		Capabilities:        []string{"subprocess_run:echo"},
		SubprocessAllowlist: []string{"echo"},
	}, time.Hour)
	tokPath := filepath.Join(tmp, "token.json")
	_ = os.WriteFile(tokPath, tokenJSON, 0600)
	rootsPath := writeTrustRoots(t, tmp, kid, pub)

	// Audit URL points to a black-hole port → POST will fail; child must
	// still run and we must still get exit 0.
	rc := runRun([]string{
		"--token", tokPath,
		"--trust-roots", rootsPath,
		"--target", "local",
		"--audit-url", "http://127.0.0.1:1/dead",
		"--", "echo", "ok",
	})
	if rc != 0 {
		t.Fatalf("audit failure must not block child; got exit %d", rc)
	}
}

func TestRun_TrustRootsMissing(t *testing.T) {
	tmp := t.TempDir()
	tokenJSON, _, _ := makeSignedToken(t, skillgate.TokenEnvelope{}, time.Hour)
	tokPath := filepath.Join(tmp, "token.json")
	_ = os.WriteFile(tokPath, tokenJSON, 0600)

	rc := runRun([]string{
		"--token", tokPath,
		"--trust-roots", filepath.Join(tmp, "no-roots.yaml"),
		"--target", "local",
		"--", "echo", "hi",
	})
	if rc != skillgate.ExitInvalidSignature {
		t.Fatalf("want exit %d (invalid-signature/missing-roots), got %d",
			skillgate.ExitInvalidSignature, rc)
	}
}

func TestRun_TokenViaEnvVar(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skip exec test on windows")
	}
	tmp := t.TempDir()
	tokenJSON, kid, pub := makeSignedToken(t, skillgate.TokenEnvelope{
		Capabilities:        []string{"subprocess_run:echo"},
		SubprocessAllowlist: []string{"echo"},
	}, time.Hour)
	rootsPath := writeTrustRoots(t, tmp, kid, pub)

	t.Setenv("RUN_TOKEN_TEST_VAR", string(tokenJSON))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	rc := runRun([]string{
		"--token", "env:RUN_TOKEN_TEST_VAR",
		"--trust-roots", rootsPath,
		"--target", "local",
		"--audit-url", srv.URL + "/api/skills/runtime/invocations",
		"--", "echo", "ok",
	})
	if rc != 0 {
		t.Fatalf("env-var token happy path, want 0, got %d", rc)
	}
}

func TestRun_VerifyReasonToExit_Map(t *testing.T) {
	tests := []struct {
		reason string
		want   int
	}{
		{"expired", skillgate.ExitTokenExpired},
		{"bad_signature", skillgate.ExitFileOutsideEnv},
		{"unknown_issuer", skillgate.ExitFileOutsideEnv},
		{"envelope_grew", skillgate.ExitFileOutsideEnv},
		{"chain_too_deep", skillgate.ExitFileOutsideEnv},
		{"malformed", skillgate.ExitInvalidSignature},
	}
	for _, tt := range tests {
		got := verifyReasonToExit(tt.reason)
		if got != tt.want {
			t.Errorf("verifyReasonToExit(%q) = %d, want %d", tt.reason, got, tt.want)
		}
	}
}

func TestLoadTrustRoots_JSONForm(t *testing.T) {
	tmp := t.TempDir()
	pub, _, _ := ed25519.GenerateKey(nil)
	encoded := base64.StdEncoding.EncodeToString(pub)
	doc := `{"registry_keys": {"k-json": "` + encoded + `"}}`
	path := filepath.Join(tmp, "roots.json")
	_ = os.WriteFile(path, []byte(doc), 0600)

	roots, err := loadTrustRoots(path)
	if err != nil {
		t.Fatalf("loadTrustRoots: %v", err)
	}
	if _, ok := roots.RegistryKeys["k-json"]; !ok {
		t.Fatalf("k-json missing")
	}
}

func TestLoadTrustRoots_YAMLWithComment(t *testing.T) {
	tmp := t.TempDir()
	pub, _, _ := ed25519.GenerateKey(nil)
	encoded := base64.StdEncoding.EncodeToString(pub)
	doc := "# trust roots\nregistry_keys:\n  k-yaml: " + encoded + "  # primary\n"
	path := filepath.Join(tmp, "roots.yaml")
	_ = os.WriteFile(path, []byte(doc), 0600)

	roots, err := loadTrustRoots(path)
	if err != nil {
		t.Fatalf("loadTrustRoots: %v", err)
	}
	if _, ok := roots.RegistryKeys["k-yaml"]; !ok {
		t.Fatalf("k-yaml missing in %#v", roots.RegistryKeys)
	}
}

func TestAppendOrReplaceEnv(t *testing.T) {
	env := []string{"FOO=1", "BAR=2"}
	env = appendOrReplaceEnv(env, "BAR", "99")
	env = appendOrReplaceEnv(env, "BAZ", "3")
	want := "BAR=99"
	found := false
	for _, e := range env {
		if e == want {
			found = true
		}
	}
	if !found {
		t.Errorf("expected %q in env, got %v", want, env)
	}
	if !strings.Contains(strings.Join(env, "|"), "BAZ=3") {
		t.Errorf("expected BAZ=3 appended, got %v", env)
	}
}
