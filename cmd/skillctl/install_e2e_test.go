package main

// Subprocess-driven integration tests for the SPEC-0188 §11 exit-code
// matrix. Each test:
//
//   1. Stands up an httptest mux that serves the registry surface
//      (by-name, bundles, identities) shaped to trigger ONE specific
//      failure mode.
//   2. Writes a trust-roots.yaml under a per-test temp HOME pinning that
//      mux's URL.
//   3. Invokes the freshly-built skillctl binary as a subprocess with
//      HOME=<temp> so the trust-roots resolution + verifier algorithm
//      run end-to-end.
//   4. Asserts the process exit code matches the SPEC-0188 §11 row.
//
// In-process tests (install_cmds_test.go) cover the same paths via the
// runInstall() function, but ONLY the subprocess form proves that
// runWithExit + os.Exit translate the verifier's sentinel error into the
// numbered process exit code. CI consumers branch on $? — we test that
// surface directly.
//
// Skipped codes: none. All eight (0/10/11/12/13/14/15/16/17) are exercised.
// Exit 17 (BUG-0144, 2026-05-11): SPEC-0198 §3 author-identity revocation
// now wires through to ErrIdentityRevoked; see
// TestInstall_RevokedAuthor_Exit17 below.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// ----- binary build (one per `go test` invocation) -----

var (
	binPathOnce sync.Once
	binPath     string
	binPathErr  error
)

// skillctlBin builds the skillctl binary once per test process and returns
// its path. Subsequent tests reuse the same binary; t.Cleanup is per-test
// so we cannot tie the binary lifetime to a single t — the build happens
// in TestMain via the once.Do guard, the binary lives until the test
// process exits and is tidied by the OS temp-dir reaper.
func skillctlBin(t *testing.T) string {
	t.Helper()
	binPathOnce.Do(func() {
		dir, err := os.MkdirTemp("", "skillctl-e2e-bin-")
		if err != nil {
			binPathErr = err
			return
		}
		out := filepath.Join(dir, "skillctl")
		if runtime.GOOS == "windows" {
			out += ".exe" // Windows needs the .exe suffix to exec the built binary
		}
		// Build from the cmd/skillctl package (CWD here).
		cmd := exec.Command("go", "build", "-o", out, ".")
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			binPathErr = err
			return
		}
		binPath = out
	})
	if binPathErr != nil {
		t.Fatalf("build skillctl: %v", binPathErr)
	}
	return binPath
}

// runSkillctl invokes the built binary as a subprocess. Returns
// (exitCode, stdout, stderr). HOME is forced to home so trust-roots
// resolution stays scoped to the test temp dir.
func runSkillctl(t *testing.T, home string, args ...string) (int, string, string) {
	t.Helper()
	bin := skillctlBin(t)
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(),
		"HOME="+home,
		// On Linux, os.UserHomeDir prefers $HOME; Darwin same. Belt:
		// also unset XDG so nothing overrides the trust-roots path.
		"XDG_CONFIG_HOME=",
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("run skillctl: %v", err)
		}
	}
	return code, stdout.String(), stderr.String()
}

// ----- shared fixture builder -----

// e2eFixture bundles everything the test mux needs: keys, a valid blob,
// canonical signatures, and the digest string callers paste into the JSON
// envelopes. Individual tests then mutate ONE field (e.g. swap the served
// blob, swap the author sig) to trigger a specific exit code.
type e2eFixture struct {
	authorPub  ed25519.PublicKey
	authorPriv ed25519.PrivateKey
	regPub     ed25519.PublicKey
	regPriv    ed25519.PrivateKey
	blob       []byte
	digest     [sha256.Size]byte
	digestStr  string
	authorSig  []byte
	regSig     []byte
}

func newFixture(t *testing.T) *e2eFixture {
	t.Helper()
	authorPub, authorPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("authorKey: %v", err)
	}
	regPub, regPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("regKey: %v", err)
	}
	blob := buildSkillBundleTGZ(t)
	digest := sha256.Sum256(blob)
	digestStr := "sha256:" + hex.EncodeToString(digest[:])
	return &e2eFixture{
		authorPub:  authorPub,
		authorPriv: authorPriv,
		regPub:     regPub,
		regPriv:    regPriv,
		blob:       blob,
		digest:     digest,
		digestStr:  digestStr,
		authorSig:  ed25519.Sign(authorPriv, digest[:]),
		regSig:     ed25519.Sign(regPriv, digest[:]),
	}
}

// pinTrust writes a trust-roots.yaml that pins srvURL with the registry
// pubkey from f. The yamlExtra string lets a test inject additional
// top-level fields (e.g. tenant_scope: kup-berlin).
func (f *e2eFixture) pinTrust(t *testing.T, home, srvURL, yamlExtra string) {
	t.Helper()
	regKeyB64 := base64.StdEncoding.EncodeToString(f.regPub)
	body := yamlExtra + `trust_roots:
  - registry_url: ` + srvURL + `/api/skills
    registry_keys:
      - id: k1
        pubkey: ` + regKeyB64 + `
        issued: "2026-05-05"
    identity_keys_authorized: from-registry
    governance_minimum: green
`
	writeTrustRoots(t, home, body)
}

// happyMux returns a mux serving the canonical happy-path responses for
// the fixture. Tests can override individual handlers with mux.Handle to
// inject failure shapes.
func (f *e2eFixture) happyMux(t *testing.T, manifest map[string]any, currentGovernance string, attestations []map[string]any) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/skills/by-name/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name": "fetch-contract",
			"versions": []map[string]any{
				{"version": "1.0.0", "digest": f.digestStr, "status": "admitted"},
			},
		})
	})
	mux.HandleFunc("/api/skills/bundles/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("meta") == "1" {
			payload := map[string]any{
				"bundle": map[string]any{"bundle_digest": f.digestStr, "status": "admitted"},
				"signatures": []map[string]any{
					{"role": "author", "identity_id": "id:author@m3c", "signature_b64": base64.StdEncoding.EncodeToString(f.authorSig), "status": "active"},
					{"role": "registry", "identity_id": "id:registry@aims-core", "signature_b64": base64.StdEncoding.EncodeToString(f.regSig), "status": "active"},
				},
				"manifest":           manifest,
				"current_governance": currentGovernance,
			}
			if attestations != nil {
				payload["attestations"] = attestations
			}
			_ = json.NewEncoder(w).Encode(payload)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(f.blob)
	})
	mux.HandleFunc("/api/skills/identities/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":          "id:author@m3c",
			"pubkey_b64":  base64.StdEncoding.EncodeToString(f.authorPub),
			"auth_source": "manual",
		})
	})
	return mux
}

// ----- happy path -----

func TestInstall_GoodBundle_Exit0(t *testing.T) {
	home := t.TempDir()
	f := newFixture(t)
	mux := f.happyMux(t, map[string]any{"depends_on": []any{}}, "green", nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	f.pinTrust(t, home, srv.URL, "")

	code, stdout, stderr := runSkillctl(t, home, "install", "--home", home, "fetch-contract@1.0.0")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "installed:") {
		t.Errorf("stdout missing 'installed:'; got: %s", stdout)
	}
}

// ----- 10: digest mismatch -----

func TestInstall_TamperedBundle_Exit10(t *testing.T) {
	home := t.TempDir()
	f := newFixture(t)
	tampered := append([]byte(nil), f.blob...)
	tampered[5] ^= 0x80

	mux := http.NewServeMux()
	mux.HandleFunc("/api/skills/by-name/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name": "fetch-contract",
			"versions": []map[string]any{
				{"version": "1.0.0", "digest": f.digestStr, "status": "admitted"},
			},
		})
	})
	mux.HandleFunc("/api/skills/bundles/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("meta") == "1" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"bundle": map[string]any{"bundle_digest": f.digestStr, "status": "admitted"},
				"signatures": []map[string]any{
					{"role": "author", "identity_id": "id:a", "signature_b64": base64.StdEncoding.EncodeToString(f.authorSig), "status": "active"},
					{"role": "registry", "identity_id": "id:r", "signature_b64": base64.StdEncoding.EncodeToString(f.regSig), "status": "active"},
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
			"pubkey_b64":  base64.StdEncoding.EncodeToString(f.authorPub),
			"auth_source": "manual",
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	f.pinTrust(t, home, srv.URL, "")

	code, _, stderr := runSkillctl(t, home, "install", "--home", home, "fetch-contract@1.0.0")
	if code != verify.ExitDigestMismatch {
		t.Errorf("exit = %d, want %d; stderr: %s", code, verify.ExitDigestMismatch, stderr)
	}
}

// ----- 11: author signature invalid -----

func TestInstall_BadAuthorSig_Exit11(t *testing.T) {
	home := t.TempDir()
	f := newFixture(t)

	// Sign with a different key than the one the registry advertises.
	_, badPriv, _ := ed25519.GenerateKey(rand.Reader)
	badAuthorSig := ed25519.Sign(badPriv, f.digest[:])

	mux := http.NewServeMux()
	mux.HandleFunc("/api/skills/by-name/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name": "fetch-contract",
			"versions": []map[string]any{
				{"version": "1.0.0", "digest": f.digestStr, "status": "admitted"},
			},
		})
	})
	mux.HandleFunc("/api/skills/bundles/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("meta") == "1" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"bundle": map[string]any{"bundle_digest": f.digestStr, "status": "admitted"},
				"signatures": []map[string]any{
					{"role": "author", "identity_id": "id:a", "signature_b64": base64.StdEncoding.EncodeToString(badAuthorSig), "status": "active"},
					{"role": "registry", "identity_id": "id:r", "signature_b64": base64.StdEncoding.EncodeToString(f.regSig), "status": "active"},
				},
				"manifest":           map[string]any{},
				"current_governance": "green",
			})
			return
		}
		_, _ = w.Write(f.blob)
	})
	mux.HandleFunc("/api/skills/identities/", func(w http.ResponseWriter, r *http.Request) {
		// Identity advertises the GOOD authorPub; the signature is over
		// digest by a DIFFERENT key — verify must reject.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":          "id:a",
			"pubkey_b64":  base64.StdEncoding.EncodeToString(f.authorPub),
			"auth_source": "manual",
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	f.pinTrust(t, home, srv.URL, "")

	code, _, stderr := runSkillctl(t, home, "install", "--home", home, "fetch-contract@1.0.0")
	if code != verify.ExitAuthorSigInvalid {
		t.Errorf("exit = %d, want %d; stderr: %s", code, verify.ExitAuthorSigInvalid, stderr)
	}
}

// ----- 12: registry not in trust roots -----

func TestInstall_UntrustedRegistry_Exit12(t *testing.T) {
	home := t.TempDir()
	f := newFixture(t)

	// Sign the registry signature with a key NOT pinned in trust-roots.
	_, otherRegPriv, _ := ed25519.GenerateKey(rand.Reader)
	badRegSig := ed25519.Sign(otherRegPriv, f.digest[:])

	mux := http.NewServeMux()
	mux.HandleFunc("/api/skills/by-name/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name": "fetch-contract",
			"versions": []map[string]any{
				{"version": "1.0.0", "digest": f.digestStr, "status": "admitted"},
			},
		})
	})
	mux.HandleFunc("/api/skills/bundles/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("meta") == "1" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"bundle": map[string]any{"bundle_digest": f.digestStr, "status": "admitted"},
				"signatures": []map[string]any{
					{"role": "author", "identity_id": "id:a", "signature_b64": base64.StdEncoding.EncodeToString(f.authorSig), "status": "active"},
					{"role": "registry", "identity_id": "id:r", "signature_b64": base64.StdEncoding.EncodeToString(badRegSig), "status": "active"},
				},
				"manifest":           map[string]any{},
				"current_governance": "green",
			})
			return
		}
		_, _ = w.Write(f.blob)
	})
	mux.HandleFunc("/api/skills/identities/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":          "id:a",
			"pubkey_b64":  base64.StdEncoding.EncodeToString(f.authorPub),
			"auth_source": "manual",
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	// Trust-roots pins f.regPub — the registry signed with otherRegPriv,
	// so no active trust-root key matches → ErrRegistryNotTrusted (12).
	f.pinTrust(t, home, srv.URL, "")

	code, _, stderr := runSkillctl(t, home, "install", "--home", home, "fetch-contract@1.0.0")
	if code != verify.ExitRegistryNotTrusted {
		t.Errorf("exit = %d, want %d; stderr: %s", code, verify.ExitRegistryNotTrusted, stderr)
	}
}

// ----- 13: governance below minimum -----

func TestInstall_BelowGovMin_Exit13(t *testing.T) {
	home := t.TempDir()
	f := newFixture(t)
	// Trust root requires green; bundle current_governance is yellow.
	mux := f.happyMux(t, map[string]any{}, "yellow", nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	f.pinTrust(t, home, srv.URL, "")

	code, _, stderr := runSkillctl(t, home, "install", "--home", home, "fetch-contract@1.0.0")
	if code != verify.ExitGovernanceBelowMin {
		t.Errorf("exit = %d, want %d; stderr: %s", code, verify.ExitGovernanceBelowMin, stderr)
	}
}

// ----- 14: depends_on unsatisfied -----

func TestInstall_DepsUnsatisfied_Exit14(t *testing.T) {
	home := t.TempDir()
	f := newFixture(t)
	// Malformed depends_on entry (missing kind) → stepResolveDeps fails.
	manifest := map[string]any{
		"depends_on": []any{
			map[string]any{"name": "click"}, // missing 'kind'
		},
	}
	mux := f.happyMux(t, manifest, "green", nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	f.pinTrust(t, home, srv.URL, "")

	code, _, stderr := runSkillctl(t, home, "install", "--home", home, "fetch-contract@1.0.0")
	if code != verify.ExitDepsUnsatisfied {
		t.Errorf("exit = %d, want %d; stderr: %s", code, verify.ExitDepsUnsatisfied, stderr)
	}
}

// ----- 15: blob missing -----

func TestInstall_BlobMissing_Exit15(t *testing.T) {
	home := t.TempDir()
	f := newFixture(t)

	// by-name resolves cleanly, but the blob endpoint 404s. install.go
	// translates that into verify.ErrBlobMissing → exit 15.
	mux := http.NewServeMux()
	mux.HandleFunc("/api/skills/by-name/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name": "fetch-contract",
			"versions": []map[string]any{
				{"version": "1.0.0", "digest": f.digestStr, "status": "admitted"},
			},
		})
	})
	mux.HandleFunc("/api/skills/bundles/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	f.pinTrust(t, home, srv.URL, "")

	code, _, stderr := runSkillctl(t, home, "install", "--home", home, "fetch-contract@1.0.0")
	if code != verify.ExitBlobMissing {
		t.Errorf("exit = %d, want %d; stderr: %s", code, verify.ExitBlobMissing, stderr)
	}
}

// ----- 16: tenant blocked (post-PR-#17 surface) -----

func TestInstall_TenantBlocked_Exit16(t *testing.T) {
	home := t.TempDir()
	f := newFixture(t)
	// Bundle is globally green AND has a tenant-scoped red attestation
	// for tenant kup-berlin. With --tenant kup-berlin the verifier's
	// step 5.5 fails closed.
	attestations := []map[string]any{
		{
			"attestation_id": "att-block-001",
			"reviewer_id":    "id:ciso@kup",
			"attested_at":    "2026-05-06T12:00:00Z",
			"tenant_scope":   "kup-berlin",
			"level":          "red",
			"status":         "active",
		},
	}
	mux := f.happyMux(t, map[string]any{}, "green", attestations)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	f.pinTrust(t, home, srv.URL, "")

	code, _, stderr := runSkillctl(t, home,
		"install", "--home", home, "--tenant", "kup-berlin", "fetch-contract@1.0.0",
	)
	if code != verify.ExitTenantBlocked {
		t.Errorf("exit = %d, want %d; stderr: %s", code, verify.ExitTenantBlocked, stderr)
	}
}

// ----- 17: revoked author identity (SPEC-0198 §3 / BUG-0144) -----
//
// The identity endpoint returns a row with `revoked_at` set; the verifier
// must refuse with ErrIdentityRevoked (exit 17). Pre-BUG-0144 the same
// row produced exit 11 (ErrAuthorSigInvalid) which conflated revocation
// with cryptographic tampering — operators couldn't distinguish.

func TestInstall_RevokedAuthor_Exit17(t *testing.T) {
	home := t.TempDir()
	f := newFixture(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/skills/by-name/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name": "fetch-contract",
			"versions": []map[string]any{
				{"version": "1.0.0", "digest": f.digestStr, "status": "admitted"},
			},
		})
	})
	mux.HandleFunc("/api/skills/bundles/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("meta") == "1" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"bundle": map[string]any{"bundle_digest": f.digestStr, "status": "admitted"},
				"signatures": []map[string]any{
					{"role": "author", "identity_id": "id:revoked-author", "signature_b64": base64.StdEncoding.EncodeToString(f.authorSig), "status": "active"},
					{"role": "registry", "identity_id": "id:r", "signature_b64": base64.StdEncoding.EncodeToString(f.regSig), "status": "active"},
				},
				"manifest":           map[string]any{},
				"current_governance": "green",
			})
			return
		}
		_, _ = w.Write(f.blob)
	})
	mux.HandleFunc("/api/skills/identities/", func(w http.ResponseWriter, r *http.Request) {
		// Identity row carries revoked_at — the verifier MUST surface
		// ErrIdentityRevoked (exit 17), not ErrAuthorSigInvalid (exit 11).
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":               "id:revoked-author",
			"pubkey_b64":       base64.StdEncoding.EncodeToString(f.authorPub),
			"auth_source":      "manual",
			"revoked_at":       "2026-05-09T00:00:00Z",
			"revoke_rationale": "key compromised in trainer laptop theft",
			"status":           "revoked",
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	f.pinTrust(t, home, srv.URL, "")

	code, _, stderr := runSkillctl(t, home, "install", "--home", home, "fetch-contract@1.0.0")
	if code != 17 {
		t.Errorf("exit = %d, want 17 (RevokeIdentityRevoked); stderr: %s", code, stderr)
	}
	// Defense-in-depth: the stderr must mention the revoke so operators
	// can correlate with the SPEC-0198 audit row.
	if !strings.Contains(stderr, "revoked") {
		t.Errorf("stderr does not mention 'revoked'; got: %s", stderr)
	}
}
