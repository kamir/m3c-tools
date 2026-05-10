package main

// Tests for the install + verify CLI runners. The heavy lifting lives in
// pkg/skillctl/install (which has its own e2e tests with httptest); these
// tests focus on:
//
//   - Flag parsing surface (usage on missing args, version pinning,
//     --allow-yellow / --ignore-deps wiring).
//   - parseNameAtVersion edge cases.
//   - loadAndPickRoot's three branches (single-pin shortcut, exact match
//     by --registry, ambiguity error).
//   - End-to-end: a happy install via httptest with a temp HOME so the
//     full CLI exit-code translation gets exercised.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// ----- parseNameAtVersion -----

func TestParseNameAtVersion(t *testing.T) {
	cases := []struct {
		in       string
		wantName string
		wantVer  string
		wantErr  bool
	}{
		{"fetch-contract", "fetch-contract", "", false},
		{"fetch-contract@1.0.0", "fetch-contract", "1.0.0", false},
		{"fetch-contract@sha256:abc", "fetch-contract", "sha256:abc", false},
		{"@1.0.0", "", "", true},
		{"name@", "", "", true},
		{"", "", "", true},
		{"  fetch-contract@1.0.0  ", "fetch-contract", "1.0.0", false},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			n, v, err := parseNameAtVersion(c.in)
			if c.wantErr {
				if err == nil {
					t.Errorf("expected error for %q", c.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if n != c.wantName || v != c.wantVer {
				t.Errorf("got (%q, %q), want (%q, %q)", n, v, c.wantName, c.wantVer)
			}
		})
	}
}

// ----- loadAndPickRoot -----

// withTempHome redirects HOME for the test, so verify.DefaultPath() resolves
// inside a writable temp dir.
func withTempHome(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	return tmp
}

// writeTrustRoots dumps the given YAML content to ~/.claude/skill-trust-roots.yaml.
func writeTrustRoots(t *testing.T, home, body string) {
	t.Helper()
	dir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir .claude: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "skill-trust-roots.yaml"), []byte(body), 0o600); err != nil {
		t.Fatalf("write trust-roots: %v", err)
	}
}

func TestLoadAndPickRoot_SinglePinShortcut(t *testing.T) {
	home := withTempHome(t)
	pubB64 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	writeTrustRoots(t, home, `trust_roots:
  - registry_url: https://reg.example/api/skills
    registry_keys:
      - id: k1
        pubkey: `+pubB64+`
        issued: "2026-05-05"
    identity_keys_authorized: from-registry
    governance_minimum: green
`)
	_, root, err := loadAndPickRoot("")
	if err != nil {
		t.Fatalf("loadAndPickRoot: %v", err)
	}
	if root.RegistryURL != "https://reg.example/api/skills" {
		t.Errorf("root.RegistryURL = %q", root.RegistryURL)
	}
}

func TestLoadAndPickRoot_AmbiguousNeedsFlag(t *testing.T) {
	home := withTempHome(t)
	pub1 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
	pub2 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32))
	writeTrustRoots(t, home, `trust_roots:
  - registry_url: https://prod.example/api/skills
    registry_keys:
      - id: k1
        pubkey: `+pub1+`
        issued: "2026-05-05"
    identity_keys_authorized: from-registry
    governance_minimum: green
  - registry_url: https://dev.example/api/skills
    registry_keys:
      - id: k2
        pubkey: `+pub2+`
        issued: "2026-05-05"
    identity_keys_authorized: from-registry
    governance_minimum: green
`)
	_, _, err := loadAndPickRoot("")
	if err == nil {
		t.Errorf("expected ambiguity error")
	} else if !strings.Contains(err.Error(), "multiple registries") {
		t.Errorf("error message = %v", err)
	}

	// With --registry it picks the right one.
	_, root, err := loadAndPickRoot("https://dev.example/api/skills")
	if err != nil {
		t.Fatalf("loadAndPickRoot: %v", err)
	}
	if root.RegistryURL != "https://dev.example/api/skills" {
		t.Errorf("picked %q", root.RegistryURL)
	}

	// And on a non-match, errors clearly.
	_, _, err = loadAndPickRoot("https://nope.example/api/skills")
	if err == nil {
		t.Errorf("expected error for unknown registry")
	}
}

func TestLoadAndPickRoot_NoFile(t *testing.T) {
	withTempHome(t) // no trust-roots file written
	_, _, err := loadAndPickRoot("")
	if err == nil {
		t.Errorf("expected error when trust-roots file is missing")
	}
}

// ----- runInstall: usage paths -----

func TestRunInstall_NoArgs_ExitsUsage(t *testing.T) {
	withTempHome(t)
	var stdout, stderr bytes.Buffer
	got := runInstall(nil, &stdout, &stderr)
	if got != exitUsage {
		t.Errorf("exit = %d, want %d", got, exitUsage)
	}
}

func TestRunInstall_BadName_ExitsUsage(t *testing.T) {
	withTempHome(t)
	var stdout, stderr bytes.Buffer
	got := runInstall([]string{"@1.0.0"}, &stdout, &stderr)
	if got != exitUsage {
		t.Errorf("exit = %d, want %d", got, exitUsage)
	}
}

func TestRunVerify_NameWithVersion_ExitsUsage(t *testing.T) {
	withTempHome(t)
	var stdout, stderr bytes.Buffer
	got := runVerify([]string{"fetch-contract@1.0.0"}, &stdout, &stderr)
	if got != exitUsage {
		t.Errorf("exit = %d, want %d", got, exitUsage)
	}
}

// ----- end-to-end install via CLI runner -----

func TestRunInstall_HappyPath_Exit0(t *testing.T) {
	home := withTempHome(t)

	// Build fixture bundle.
	authorPub, authorPriv, _ := ed25519.GenerateKey(rand.Reader)
	regPub, regPriv, _ := ed25519.GenerateKey(rand.Reader)
	blob := buildSkillBundleTGZ(t)
	digest := sha256.Sum256(blob)
	digestStr := "sha256:" + hex.EncodeToString(digest[:])

	authorSig := ed25519.Sign(authorPriv, digest[:])
	regSig := ed25519.Sign(regPriv, digest[:])

	mux := http.NewServeMux()
	mux.HandleFunc("/api/skills/by-name/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name": "fetch-contract",
			"versions": []map[string]any{
				{"version": "1.0.0", "digest": digestStr, "status": "admitted"},
			},
		})
	})
	mux.HandleFunc("/api/skills/bundles/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("meta") == "1" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"bundle": map[string]any{"bundle_digest": digestStr, "status": "admitted"},
				"signatures": []map[string]any{
					{"role": "author", "identity_id": "id:author@m3c", "signature_b64": base64.StdEncoding.EncodeToString(authorSig), "status": "active"},
					{"role": "registry", "identity_id": "id:registry@aims-core", "signature_b64": base64.StdEncoding.EncodeToString(regSig), "status": "active"},
				},
				"manifest":           map[string]any{"depends_on": []any{}},
				"current_governance": "green",
			})
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(blob)
	})
	mux.HandleFunc("/api/skills/identities/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":          "id:author@m3c",
			"pubkey_b64":  base64.StdEncoding.EncodeToString(authorPub),
			"auth_source": "manual",
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// Pin trust root.
	regKeyB64 := base64.StdEncoding.EncodeToString(regPub)
	writeTrustRoots(t, home, `trust_roots:
  - registry_url: `+srv.URL+`/api/skills
    registry_keys:
      - id: k1
        pubkey: `+regKeyB64+`
        issued: "2026-05-05"
    identity_keys_authorized: from-registry
    governance_minimum: green
`)

	var stdout, stderr bytes.Buffer
	got := runInstall(
		[]string{"--home", home, "fetch-contract@1.0.0"},
		&stdout, &stderr,
	)
	if got != exitOK {
		t.Fatalf("install exit = %d, want %d; stderr: %s", got, exitOK, stderr.String())
	}
	if !strings.Contains(stdout.String(), "installed:") {
		t.Errorf("expected 'installed:' in stdout, got: %s", stdout.String())
	}

	// Verify the install dir landed.
	target := filepath.Join(home, ".claude/skills/fetch-contract")
	if _, err := os.Stat(filepath.Join(target, "bundle.json")); err != nil {
		t.Errorf("bundle.json missing: %v", err)
	}

	// And `skillctl verify` on the same install should also exit 0.
	stdout.Reset()
	stderr.Reset()
	got = runVerify(
		[]string{"--home", home, "fetch-contract"},
		&stdout, &stderr,
	)
	if got != exitOK {
		t.Errorf("verify exit = %d, want %d; stderr: %s", got, exitOK, stderr.String())
	}
}

func TestRunInstall_TamperedBundle_Exit10(t *testing.T) {
	home := withTempHome(t)
	authorPub, authorPriv, _ := ed25519.GenerateKey(rand.Reader)
	regPub, regPriv, _ := ed25519.GenerateKey(rand.Reader)

	blob := buildSkillBundleTGZ(t)
	origDigest := sha256.Sum256(blob)
	origDigestStr := "sha256:" + hex.EncodeToString(origDigest[:])

	// Tamper the served blob; metadata still references origDigestStr.
	tampered := make([]byte, len(blob))
	copy(tampered, blob)
	tampered[5] ^= 0x80

	authorSig := ed25519.Sign(authorPriv, origDigest[:])
	regSig := ed25519.Sign(regPriv, origDigest[:])

	mux := http.NewServeMux()
	mux.HandleFunc("/api/skills/by-name/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name": "fetch-contract",
			"versions": []map[string]any{
				{"version": "1.0.0", "digest": origDigestStr, "status": "admitted"},
			},
		})
	})
	mux.HandleFunc("/api/skills/bundles/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("meta") == "1" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"bundle": map[string]any{"bundle_digest": origDigestStr, "status": "admitted"},
				"signatures": []map[string]any{
					{"role": "author", "identity_id": "id:a", "signature_b64": base64.StdEncoding.EncodeToString(authorSig), "status": "active"},
					{"role": "registry", "identity_id": "id:r", "signature_b64": base64.StdEncoding.EncodeToString(regSig), "status": "active"},
				},
				"manifest":           map[string]any{},
				"current_governance": "green",
			})
			return
		}
		_, _ = w.Write(tampered)
	})
	mux.HandleFunc("/api/skills/identities/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":          "id:a",
			"pubkey_b64":  base64.StdEncoding.EncodeToString(authorPub),
			"auth_source": "manual",
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	regKeyB64 := base64.StdEncoding.EncodeToString(regPub)
	writeTrustRoots(t, home, `trust_roots:
  - registry_url: `+srv.URL+`/api/skills
    registry_keys:
      - id: k1
        pubkey: `+regKeyB64+`
        issued: "2026-05-05"
    identity_keys_authorized: from-registry
    governance_minimum: green
`)

	var stdout, stderr bytes.Buffer
	got := runInstall([]string{"--home", home, "fetch-contract@1.0.0"}, &stdout, &stderr)
	if got != verify.ExitDigestMismatch {
		t.Errorf("exit = %d, want %d; stderr: %s", got, verify.ExitDigestMismatch, stderr.String())
	}
}

// ----- helpers -----

// buildSkillBundleTGZ returns a minimal but valid SPEC §3.1 layout tarball
// for a skill named fetch-contract@1.0.0. Tests use this when they need
// the bundle bytes (digest + extraction).
func buildSkillBundleTGZ(t *testing.T) []byte {
	t.Helper()
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	tw := tar.NewWriter(gw)
	root := "fetch-contract-1.0.0"

	if err := tw.WriteHeader(&tar.Header{Name: root + "/", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
		t.Fatalf("tar dir: %v", err)
	}
	files := map[string]string{
		"bundle.json": `{"name":"fetch-contract","version":"1.0.0"}` + "\n",
		"SKILL.md":    "# fetch-contract\n",
	}
	for path, content := range files {
		hdr := &tar.Header{
			Name:     root + "/" + path,
			Mode:     0o644,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar header %s: %v", path, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("tar write: %v", err)
		}
	}
	_ = tw.Close()
	_ = gw.Close()
	return gzBuf.Bytes()
}

// ----- SPEC-0188 §7 step 5.5: --tenant resolution precedence -----

// TestResolveTenant_CLIBeatsTrustRoots locks the SPEC-0188 §4.4 G-18
// precedence rule: --tenant <id> wins over the trust-roots tenant_scope:
// value. Both empty → empty (verifier treats as untenanted).
func TestResolveTenant_CLIBeatsTrustRoots(t *testing.T) {
	cases := []struct {
		name    string
		cli     string
		yaml    string
		want    string
	}{
		{"both-empty", "", "", ""},
		{"cli-only", "kup-berlin", "", "kup-berlin"},
		{"yaml-only", "", "kup-berlin", "kup-berlin"},
		{"cli-wins", "cflt", "kup-berlin", "cflt"},
		{"cli-trim", "  kup-berlin  ", "ignored", "kup-berlin"},
		{"yaml-trim", "", "  kup-berlin  ", "kup-berlin"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tr := &verify.TrustRoots{TenantScope: c.yaml}
			if got := resolveTenant(c.cli, tr); got != c.want {
				t.Errorf("resolveTenant(%q, yaml=%q) = %q, want %q", c.cli, c.yaml, got, c.want)
			}
		})
	}
}

// TestResolveTenant_NilTrustRoots: defensive — if the CLI ever calls
// resolveTenant before loadAndPickRoot returns a valid TrustRoots, the
// helper must not panic.
func TestResolveTenant_NilTrustRoots(t *testing.T) {
	if got := resolveTenant("kup-berlin", nil); got != "kup-berlin" {
		t.Errorf("resolveTenant with nil TrustRoots = %q, want kup-berlin", got)
	}
	if got := resolveTenant("", nil); got != "" {
		t.Errorf("resolveTenant nil/empty = %q, want empty", got)
	}
}
