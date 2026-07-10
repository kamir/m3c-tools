package verify

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeRootsFile writes raw YAML to a temp trust-roots path and returns it.
func writeRootsFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "skill-trust-roots.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// minimalRegistry is a valid trust_roots block we prepend so the file is
// otherwise well-formed when we exercise the logs block.
const minimalRegistry = `trust_roots:
  - registry_url: https://aims.example.com/api/skills
    registry_keys:
      - id: k1
        pubkey: %s
        issued: 2026-06-24
    identity_keys_authorized: from-registry
    governance_minimum: green
`

func validPubkeyB64(t *testing.T) string {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(nil)
	return base64.StdEncoding.EncodeToString(pub)
}

func TestLoad_LogsBlock_Valid(t *testing.T) {
	regKey := validPubkeyB64(t)
	logKey := validPubkeyB64(t)
	body := strings_sprintf(minimalRegistry, regKey) + `require_log_inclusion: true
logs:
  - log_id: skillctl-log-1
    log_key: ` + logKey + `
    pinned_sths:
      - tree_size: 5
        root_hash: ` + strings.Repeat("ab", 32) + `
        timestamp: 2026-06-24T12:00:00Z
        log_id: skillctl-log-1
        signature: ` + strings.Repeat("cd", 64) + `
`
	path := writeRootsFile(t, body)
	tr, err := Load(path)
	if err != nil {
		t.Fatalf("valid logs block should load: %v", err)
	}
	if !tr.RequireLogInclusion {
		t.Fatal("require_log_inclusion should be true")
	}
	lt := tr.FindLog("skillctl-log-1")
	if lt == nil {
		t.Fatal("FindLog should resolve the pinned log")
	}
	if len(lt.LogKey) != ed25519.PublicKeySize {
		t.Fatalf("LogKey not hydrated: len=%d", len(lt.LogKey))
	}
	if len(lt.PinnedSTHs) != 1 || lt.PinnedSTHs[0].TreeSize != 5 {
		t.Fatalf("pinned STH not parsed: %+v", lt.PinnedSTHs)
	}
}

func TestLoad_LogsBlock_RejectsBadKey(t *testing.T) {
	regKey := validPubkeyB64(t)
	body := strings_sprintf(minimalRegistry, regKey) + `logs:
  - log_id: log-1
    log_key: not-base64!!!
`
	if _, err := Load(writeRootsFile(t, body)); err == nil {
		t.Fatal("expected error for non-base64 log_key")
	}
}

func TestLoad_LogsBlock_RejectsMismatchedSTHLogID(t *testing.T) {
	regKey := validPubkeyB64(t)
	logKey := validPubkeyB64(t)
	body := strings_sprintf(minimalRegistry, regKey) + `logs:
  - log_id: log-1
    log_key: ` + logKey + `
    pinned_sths:
      - tree_size: 1
        root_hash: ` + strings.Repeat("ab", 32) + `
        timestamp: 2026-06-24T12:00:00Z
        log_id: DIFFERENT-log
        signature: ` + strings.Repeat("cd", 64) + `
`
	if _, err := Load(writeRootsFile(t, body)); err == nil {
		t.Fatal("expected error when pinned STH log_id != parent log_id")
	}
}

func TestLoad_LogsBlock_RejectsUnknownField(t *testing.T) {
	// Strict loader: an unknown field under logs must be refused (a typo in
	// a security policy field must fail loudly, not silently disable a key).
	regKey := validPubkeyB64(t)
	logKey := validPubkeyB64(t)
	body := strings_sprintf(minimalRegistry, regKey) + `logs:
  - log_id: log-1
    log_key: ` + logKey + `
    bogus_field: oops
`
	if _, err := Load(writeRootsFile(t, body)); err == nil {
		t.Fatal("strict loader must reject unknown field under logs")
	}
}

func TestLoad_NoLogsBlock_Backcompat(t *testing.T) {
	// A trust-roots file with NO logs block must still load (the L1 feature
	// is additive; existing files keep working).
	regKey := validPubkeyB64(t)
	body := strings_sprintf(minimalRegistry, regKey)
	tr, err := Load(writeRootsFile(t, body))
	if err != nil {
		t.Fatalf("file without logs block should still load: %v", err)
	}
	if len(tr.Logs) != 0 || tr.RequireLogInclusion {
		t.Fatal("absent logs block should yield empty Logs and require=false")
	}
}

// strings_sprintf is a tiny local Sprintf-of-one-%s to avoid importing fmt
// just for the test fixtures (and to keep the substitution obvious).
func strings_sprintf(tmpl, a string) string {
	return strings.Replace(tmpl, "%s", a, 1)
}
