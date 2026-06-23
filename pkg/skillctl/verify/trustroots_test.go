package verify

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writePubkeyPEM writes a freshly generated ed25519 public key in PEM
// SPKI form (the format `skillctl keygen` produces) and returns the
// path + the raw 32-byte pubkey for assertions.
func writePubkeyPEM(t *testing.T, dir, name string) (string, []byte) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pemBytes, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path, []byte(pub)
}

// trustRootsTempPath returns a temp file path for a trust-roots config
// inside t.TempDir(). It does NOT create the file.
func trustRootsTempPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "skill-trust-roots.yaml")
}

func TestLoad_FileMissing(t *testing.T) {
	path := trustRootsTempPath(t)
	tr, err := Load(path)
	if err == nil {
		t.Fatalf("expected error for missing file, got nil")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing-file error not wrapped with os.ErrNotExist: %v", err)
	}
	if tr == nil {
		t.Fatalf("expected non-nil TrustRoots even on missing file (bootstrap path)")
	}
	if tr.Path != path {
		t.Errorf("Path = %q, want %q", tr.Path, path)
	}
	if len(tr.Roots) != 0 {
		t.Errorf("Roots non-empty on missing file: %+v", tr.Roots)
	}
}

func TestSaveAndLoad_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.yaml")
	pub1Path, _ := writePubkeyPEM(t, dir, "k1.pub")
	pub2Path, _ := writePubkeyPEM(t, dir, "k2.pub")

	tr := &TrustRoots{Path: path}
	if err := tr.AddRegistry("https://aims.example.com/api/skills", pub1Path, "aims-core-dev"); err != nil {
		t.Fatalf("AddRegistry: %v", err)
	}
	// Multi-entry: add a second key under the same registry (rotation overlap).
	if err := tr.AddRegistry("https://aims.example.com/api/skills/", pub2Path, "aims-core-dev-2"); err != nil {
		t.Fatalf("AddRegistry overlap: %v", err)
	}
	if err := tr.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Reload and compare.
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(loaded.Roots) != 1 {
		t.Fatalf("Roots len = %d, want 1", len(loaded.Roots))
	}
	got := loaded.Roots[0]
	if got.RegistryURL != "https://aims.example.com/api/skills" {
		t.Errorf("RegistryURL = %q", got.RegistryURL)
	}
	if len(got.RegistryKeys) != 2 {
		t.Fatalf("RegistryKeys len = %d, want 2", len(got.RegistryKeys))
	}
	if got.RegistryKeys[0].ID != "aims-core-dev" || got.RegistryKeys[1].ID != "aims-core-dev-2" {
		t.Errorf("key ids = %q, %q", got.RegistryKeys[0].ID, got.RegistryKeys[1].ID)
	}
	for i, k := range got.RegistryKeys {
		if len(k.Pubkey) != 32 {
			t.Errorf("key[%d] Pubkey len = %d, want 32", i, len(k.Pubkey))
		}
		if k.PubkeyB64 == "" {
			t.Errorf("key[%d] PubkeyB64 empty", i)
		}
		if !k.IsActive() {
			t.Errorf("key[%d] should be active", i)
		}
	}
	if got.IdentityKeysAuthorized != "from-registry" {
		t.Errorf("IdentityKeysAuthorized = %q", got.IdentityKeysAuthorized)
	}
	if got.GovernanceMinimum != "green" {
		t.Errorf("GovernanceMinimum = %q", got.GovernanceMinimum)
	}
}

func TestLoad_RetiredKeyParses(t *testing.T) {
	path := trustRootsTempPath(t)
	dir := filepath.Dir(path)
	_, rawPub := writePubkeyPEM(t, dir, "retired.pub")
	b64 := base64.StdEncoding.EncodeToString(rawPub)
	yaml := `trust_roots:
  - registry_url: https://aims.example.com/api/skills
    registry_keys:
      - id: old-key
        pubkey: ` + b64 + `
        issued: 2026-01-01
        retired: 2026-04-01
      - id: new-key
        pubkey: ` + b64 + `
        issued: 2026-04-01
    identity_keys_authorized: from-registry
    governance_minimum: green
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	tr, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	root := tr.Roots[0]
	if len(root.RegistryKeys) != 2 {
		t.Fatalf("RegistryKeys len = %d", len(root.RegistryKeys))
	}
	if root.RegistryKeys[0].IsActive() {
		t.Errorf("retired key should NOT be active")
	}
	if !root.RegistryKeys[1].IsActive() {
		t.Errorf("new key should be active")
	}
	active := root.ActiveKeys()
	if len(active) != 1 {
		t.Errorf("ActiveKeys len = %d, want 1", len(active))
	}
	if len(active) > 0 && active[0].ID != "new-key" {
		t.Errorf("active key id = %q, want new-key", active[0].ID)
	}
}

func TestLoad_RejectsUnknownField(t *testing.T) {
	path := trustRootsTempPath(t)
	dir := filepath.Dir(path)
	_, rawPub := writePubkeyPEM(t, dir, "k.pub")
	b64 := base64.StdEncoding.EncodeToString(rawPub)
	// `governnce_minimum` (typo) is unknown — strict mode should refuse.
	yaml := `trust_roots:
  - registry_url: https://aims.example.com/api/skills
    registry_keys:
      - id: k
        pubkey: ` + b64 + `
        issued: 2026-05-05
    identity_keys_authorized: from-registry
    governance_minimum: green
    governnce_minimum: yellow
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatalf("expected error on unknown field; got nil")
	}
}

func TestLoad_RejectsBadPubkeyLength(t *testing.T) {
	path := trustRootsTempPath(t)
	// 31-byte garbage, base64-encoded.
	short := base64.StdEncoding.EncodeToString(make([]byte, 31))
	yaml := `trust_roots:
  - registry_url: https://aims.example.com/api/skills
    registry_keys:
      - id: k
        pubkey: ` + short + `
        issued: 2026-05-05
    identity_keys_authorized: from-registry
    governance_minimum: green
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatalf("expected error on short pubkey")
	}
}

func TestLoad_RejectsInvalidGovernance(t *testing.T) {
	path := trustRootsTempPath(t)
	dir := filepath.Dir(path)
	_, rawPub := writePubkeyPEM(t, dir, "k.pub")
	b64 := base64.StdEncoding.EncodeToString(rawPub)
	yaml := `trust_roots:
  - registry_url: https://aims.example.com/api/skills
    registry_keys:
      - id: k
        pubkey: ` + b64 + `
        issued: 2026-05-05
    identity_keys_authorized: from-registry
    governance_minimum: red
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatalf("expected error for governance_minimum: red")
	}
	if !strings.Contains(err.Error(), "governance_minimum") {
		t.Errorf("error should mention governance_minimum: %v", err)
	}
}

// SPEC-0252 §6: the SAME shared govlevel.ValidFloor guard the self loader uses
// rejects a "red" floor case/whitespace-insensitively in the SPEC-0188 loader
// too — proving both loaders reject RED / Red / " red " identically from ONE
// helper (closes the SEC-L1 case-collapse class in both, not just registry).
func TestLoad_RejectsRedFloorAnyCase(t *testing.T) {
	for _, floor := range []string{"RED", "Red", " red ", "rEd"} {
		path := trustRootsTempPath(t)
		dir := filepath.Dir(path)
		_, rawPub := writePubkeyPEM(t, dir, "k.pub")
		b64 := base64.StdEncoding.EncodeToString(rawPub)
		yaml := `trust_roots:
  - registry_url: https://aims.example.com/api/skills
    registry_keys:
      - id: k
        pubkey: ` + b64 + `
        issued: 2026-05-05
    identity_keys_authorized: from-registry
    governance_minimum: "` + floor + `"
`
		if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Errorf("governance_minimum %q must be rejected (red is not a valid floor, any case)", floor)
		}
	}
}

func TestLoad_RejectsInvalidIdentityMode(t *testing.T) {
	path := trustRootsTempPath(t)
	dir := filepath.Dir(path)
	_, rawPub := writePubkeyPEM(t, dir, "k.pub")
	b64 := base64.StdEncoding.EncodeToString(rawPub)
	yaml := `trust_roots:
  - registry_url: https://aims.example.com/api/skills
    registry_keys:
      - id: k
        pubkey: ` + b64 + `
        issued: 2026-05-05
    identity_keys_authorized: trust-everyone
    governance_minimum: green
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatalf("expected error for unknown identity mode")
	}
}

func TestAddRegistry_DuplicateID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.yaml")
	pubPath, _ := writePubkeyPEM(t, dir, "k.pub")

	tr := &TrustRoots{Path: path}
	if err := tr.AddRegistry("https://r.example.com/api/skills", pubPath, "k1"); err != nil {
		t.Fatalf("first AddRegistry: %v", err)
	}
	// Same ID, different pubkey path → should fail (duplicate ID under same registry).
	pub2, _ := writePubkeyPEM(t, dir, "k2.pub")
	err := tr.AddRegistry("https://r.example.com/api/skills", pub2, "k1")
	if err == nil {
		t.Fatalf("expected duplicate-id error")
	}
}

func TestAddRegistry_DuplicatePubkey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.yaml")
	pubPath, _ := writePubkeyPEM(t, dir, "k.pub")

	tr := &TrustRoots{Path: path}
	if err := tr.AddRegistry("https://r.example.com/api/skills", pubPath, "k1"); err != nil {
		t.Fatalf("AddRegistry: %v", err)
	}
	// Same pubkey, different ID → should fail (would silently duplicate trust).
	if err := tr.AddRegistry("https://r.example.com/api/skills", pubPath, "k2"); err == nil {
		t.Fatalf("expected duplicate-pubkey error")
	}
}

func TestAddRegistry_DefaultID(t *testing.T) {
	dir := t.TempDir()
	pubPath, _ := writePubkeyPEM(t, dir, "k.pub")
	tr := &TrustRoots{Path: filepath.Join(dir, "trust.yaml")}
	if err := tr.AddRegistry("https://r.example.com/api/skills", pubPath, ""); err != nil {
		t.Fatalf("AddRegistry: %v", err)
	}
	got := tr.Roots[0].RegistryKeys[0].ID
	if !strings.HasPrefix(got, "key-") || len(got) != len("key-")+8 {
		t.Errorf("default ID format unexpected: %q", got)
	}
}

func TestFindRegistry(t *testing.T) {
	dir := t.TempDir()
	pubPath, _ := writePubkeyPEM(t, dir, "k.pub")
	tr := &TrustRoots{Path: filepath.Join(dir, "trust.yaml")}
	if err := tr.AddRegistry("https://r.example.com/api/skills", pubPath, "k1"); err != nil {
		t.Fatal(err)
	}

	if r := tr.FindRegistry("https://r.example.com/api/skills"); r == nil {
		t.Errorf("FindRegistry exact match returned nil")
	}
	if r := tr.FindRegistry("https://r.example.com/api/skills/"); r == nil {
		t.Errorf("FindRegistry with trailing slash returned nil (should normalize)")
	}
	if r := tr.FindRegistry("https://other.example.com/"); r != nil {
		t.Errorf("FindRegistry returned non-nil for unknown URL")
	}
	// Nil receiver safety.
	var nilT *TrustRoots
	if r := nilT.FindRegistry("https://x"); r != nil {
		t.Errorf("FindRegistry on nil receiver returned non-nil")
	}
}

func TestRemoveRegistry(t *testing.T) {
	dir := t.TempDir()
	pubPath, _ := writePubkeyPEM(t, dir, "k.pub")
	tr := &TrustRoots{Path: filepath.Join(dir, "trust.yaml")}
	if err := tr.AddRegistry("https://r.example.com/api/skills", pubPath, "k1"); err != nil {
		t.Fatal(err)
	}
	if err := tr.RemoveRegistry("https://r.example.com/api/skills/"); err != nil {
		t.Errorf("RemoveRegistry: %v", err)
	}
	if len(tr.Roots) != 0 {
		t.Errorf("Roots len after remove = %d, want 0", len(tr.Roots))
	}
	// Idempotent? No — we WANT the second remove to error so the user
	// notices a typo.
	if err := tr.RemoveRegistry("https://r.example.com/api/skills"); err == nil {
		t.Errorf("second RemoveRegistry should error")
	}
}

func TestValidateRegistryURL_Schemes(t *testing.T) {
	cases := []struct {
		url    string
		wantOK bool
		reason string
	}{
		{"https://aims.example.com/api/skills", true, "https is always fine"},
		{"http://localhost:5000/api/skills", true, "loopback by name"},
		{"http://127.0.0.1/api/skills", true, "loopback by IP"},
		{"http://127.5.6.7/api/skills", true, "127/8 is loopback"},
		{"http://192.168.0.131:9100", true, "RFC1918 home-lab MinIO"},
		{"http://10.0.0.5/api/skills", true, "RFC1918 10/8"},
		{"http://172.16.0.1/", true, "RFC1918 172.16/12 lower bound"},
		{"http://172.31.255.255/", true, "RFC1918 172.16/12 upper bound"},
		{"http://172.15.0.1/", false, "172.15 is NOT private"},
		{"http://172.32.0.1/", false, "172.32 is NOT private"},
		{"http://example.com/api/skills", false, "plain HTTP on public host"},
		{"http://1.2.3.4/", false, "plain HTTP on public IP"},
		{"ftp://example.com/", false, "unsupported scheme"},
		{"::1", false, "no scheme"},
	}
	for _, tc := range cases {
		t.Run(tc.url, func(t *testing.T) {
			err := validateRegistryURL(tc.url)
			if tc.wantOK && err != nil {
				t.Errorf("%s: want ok, got error: %v (%s)", tc.url, err, tc.reason)
			}
			if !tc.wantOK && err == nil {
				t.Errorf("%s: want error, got ok (%s)", tc.url, tc.reason)
			}
		})
	}
}

func TestSave_RefusesInvalid(t *testing.T) {
	tr := &TrustRoots{
		Path: filepath.Join(t.TempDir(), "trust.yaml"),
		Roots: []TrustRoot{{
			RegistryURL:            "http://nasty-public-host.example.com/", // public HTTP — invalid
			IdentityKeysAuthorized: "from-registry",
			GovernanceMinimum:      "green",
			RegistryKeys: []RegistryKey{
				{ID: "k", PubkeyB64: base64.StdEncoding.EncodeToString(make([]byte, 32)), Issued: "2026-05-05"},
			},
		}},
	}
	if err := tr.Save(); err == nil {
		t.Fatalf("Save should refuse invalid config")
	}
}

func TestSave_NilReceiver(t *testing.T) {
	var nilT *TrustRoots
	if err := nilT.Save(); err == nil {
		t.Errorf("Save on nil should error")
	}
}

func TestLoad_EmptyPath(t *testing.T) {
	if _, err := Load(""); err == nil {
		t.Errorf("Load(\"\") should error")
	}
}

func TestDefaultPath(t *testing.T) {
	p, err := DefaultPath()
	if err != nil {
		t.Fatalf("DefaultPath: %v", err)
	}
	if !strings.HasSuffix(p, ".claude/skill-trust-roots.yaml") {
		t.Errorf("DefaultPath suffix wrong: %s", p)
	}
	if !filepath.IsAbs(p) {
		t.Errorf("DefaultPath should be absolute: %s", p)
	}
}

func TestResolveAndValidatePath_TildeExpansion(t *testing.T) {
	// Force HOME to a known temp dir so the test is hermetic.
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	got, err := resolveAndValidatePath("~/.claude/skill-trust-roots.yaml")
	if err != nil {
		t.Fatalf("resolveAndValidatePath: %v", err)
	}
	want := filepath.Join(tmpHome, ".claude/skill-trust-roots.yaml")
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestRegistryKey_IsActive(t *testing.T) {
	if !(RegistryKey{}).IsActive() {
		t.Errorf("empty Retired should be active")
	}
	if (RegistryKey{Retired: "2026-01-01"}).IsActive() {
		t.Errorf("non-empty Retired should NOT be active")
	}
}

// SPEC-0277 §11.5 — require_agent_approver is a KNOWN field (strict loader
// accepts it) and is rejected fail-OPEN: setting it without a reviewers list
// (the approver/sign-off-human pin) must refuse, mirroring
// require_independent_review.
func TestLoad_RequireAgentApprover_NeedsReviewers(t *testing.T) {
	path := trustRootsTempPath(t)
	dir := filepath.Dir(path)
	_, rawPub := writePubkeyPEM(t, dir, "k.pub")
	b64 := base64.StdEncoding.EncodeToString(rawPub)
	yaml := `trust_roots:
  - registry_url: https://aims.example.com/api/skills
    registry_keys:
      - id: k
        pubkey: ` + b64 + `
        issued: 2026-05-05
    identity_keys_authorized: from-registry
    governance_minimum: green
    require_agent_approver: true
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("require_agent_approver with no reviewers must be refused (fail-OPEN guard)")
	}
}

// With a reviewers list present, require_agent_approver loads cleanly and the
// flag is surfaced on the root.
func TestLoad_RequireAgentApprover_WithReviewersOK(t *testing.T) {
	path := trustRootsTempPath(t)
	dir := filepath.Dir(path)
	_, regPub := writePubkeyPEM(t, dir, "reg.pub")
	_, revPub := writePubkeyPEM(t, dir, "rev.pub")
	regB64 := base64.StdEncoding.EncodeToString(regPub)
	revB64 := base64.StdEncoding.EncodeToString(revPub)
	yaml := `trust_roots:
  - registry_url: https://aims.example.com/api/skills
    registry_keys:
      - id: k
        pubkey: ` + regB64 + `
        issued: 2026-05-05
    identity_keys_authorized: from-registry
    governance_minimum: green
    require_agent_approver: true
    reviewers:
      - id: id:approver@m3c
        pubkey: ` + revB64 + `
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	tr, err := Load(path)
	if err != nil {
		t.Fatalf("expected clean load, got %v", err)
	}
	if !tr.Roots[0].RequireAgentApprover {
		t.Fatal("RequireAgentApprover should be true")
	}
}
