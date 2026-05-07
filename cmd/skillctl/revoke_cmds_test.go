package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/signing"
)

// marshalPrivateKeyPEM mirrors signing.GenerateKeyPair's encoding —
// PKCS#8 DER wrapped in `BEGIN PRIVATE KEY` PEM. Test-local helper.
func marshalPrivateKeyPEM(priv ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// TestRunRevoke_DispatchesPositionalDigestAndFlags verifies the
// surface-level flag/argument plumbing without making any assumptions
// about the registry response.
func TestRunRevoke_DispatchesPositionalDigestAndFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer

	// Missing digest → exit 2.
	if got := runRevoke([]string{"--reason", "vulnerability"}, &stdout, &stderr); got != exitUsage {
		t.Errorf("missing digest: got %d, want %d. stderr=%q", got, exitUsage, stderr.String())
	}
	if !strings.Contains(stderr.String(), "bundle digest argument is required") {
		t.Errorf("stderr should mention digest requirement; got: %q", stderr.String())
	}

	// Bad reason → exit 2.
	stderr.Reset()
	digest := "sha256:" + strings.Repeat("a", 64)
	if got := runRevoke([]string{digest, "--reason", "i_just_felt_like_it"}, &stdout, &stderr); got != exitUsage {
		t.Errorf("bad reason: got %d, want %d", got, exitUsage)
	}

	// Bad role → exit 2.
	stderr.Reset()
	if got := runRevoke([]string{digest, "--reason", "vulnerability", "--role", "rogue_admin"}, &stdout, &stderr); got != exitUsage {
		t.Errorf("bad role: got %d, want %d", got, exitUsage)
	}
}

// TestRunRevoke_RegistryOperatorPath_NoSignature exercises the
// registry_operator path (no signature). Asserts the wire request the
// server actually receives.
func TestRunRevoke_RegistryOperatorPath_NoSignature(t *testing.T) {
	digest := "sha256:" + strings.Repeat("b", 64)
	var got revokeRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "wrong method", http.StatusMethodNotAllowed)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/bundles/"+digest+"/revoke") {
			http.Error(w, "wrong path: "+r.URL.Path, http.StatusBadRequest)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"revoked","bundle_digest":"` + digest + `","revoked_at":"2026-05-06T15:00:00Z","revoked_reason":"vulnerability","revoked_by":"system","revoked_by_role":"registry_operator"}`))
	}))
	defer srv.Close()

	regURL := srv.URL + "/api/skills"
	// httptest URLs are http://127.0.0.1:PORT; validateRegistryURL
	// permits private/loopback HTTP per attest_cmds.go convention.
	u, _ := url.Parse(regURL)
	if !strings.HasPrefix(u.Host, "127.0.0.1") {
		t.Skipf("test server is not on loopback (got %q); validateRegistryURL would refuse", u.Host)
	}

	var stdout, stderr bytes.Buffer
	args := []string{
		digest,
		"--reason", "vulnerability",
		"--role", "registry_operator",
		"--registry", regURL,
	}
	if code := runRevoke(args, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit = %d, want 0; stderr=%q", code, stderr.String())
	}

	if got.ActorRole != "registry_operator" {
		t.Errorf("actor_role = %q, want registry_operator", got.ActorRole)
	}
	if got.Reason != "vulnerability" {
		t.Errorf("reason = %q, want vulnerability", got.Reason)
	}
	if got.RequestSignatureB64 != "" {
		t.Errorf("registry_operator path should send NO signature, got %q", got.RequestSignatureB64)
	}
	if !strings.Contains(stdout.String(), "status:        revoked") {
		t.Errorf("stdout should include revoked status; got: %q", stdout.String())
	}
}

// TestRunRevoke_OriginalAuthorPath_SignsRequest exercises the
// original_author path (signed). Asserts the signature verifies against
// the canonical revocation message under the loaded private key.
func TestRunRevoke_OriginalAuthorPath_SignsRequest(t *testing.T) {
	// Generate keypair + write PEM to a temp file (matching what
	// signing.LoadPrivateKey expects).
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	tmp := t.TempDir()
	keyPath := filepath.Join(tmp, "author.key")
	pemBytes, err := marshalPrivateKeyPEM(priv)
	if err != nil {
		t.Fatalf("marshal pem: %v", err)
	}
	if err := os.WriteFile(keyPath, pemBytes, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	digest := "sha256:" + strings.Repeat("c", 64)
	var got revokeRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"revoked","bundle_digest":"` + digest + `","revoked_at":"2026-05-06T15:00:00Z","revoked_reason":"author_request","revoked_by":"id:tester@m3c","revoked_by_role":"original_author"}`))
	}))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	args := []string{
		digest,
		"--reason", "author_request",
		"--role", "original_author",
		"--actor-identity", "id:tester@m3c",
		"--key", keyPath,
		"--registry", srv.URL + "/api/skills",
	}
	if code := runRevoke(args, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit = %d, want 0; stderr=%q", code, stderr.String())
	}

	// Verify the captured signature against the canonical message.
	if got.RequestSignatureB64 == "" {
		t.Fatalf("original_author path MUST send a signature; got empty")
	}
	sig, err := base64.StdEncoding.DecodeString(got.RequestSignatureB64)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	msg, err := signing.CanonicalizeRevocationMessage(digest, got.RevocationTimestamp, "original_author")
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if !ed25519.Verify(pub, msg, sig) {
		t.Errorf("captured signature does not verify against the canonical message")
	}

	if got.ActorIdentity != "id:tester@m3c" {
		t.Errorf("actor_identity = %q, want id:tester@m3c", got.ActorIdentity)
	}
}

// TestRunRevoke_ServerErrorMapping covers the 4 distinct exit-code
// outcomes from the server's status taxonomy.
func TestRunRevoke_ServerErrorMapping(t *testing.T) {
	digest := "sha256:" + strings.Repeat("d", 64)
	cases := []struct {
		name        string
		serverCode  int
		serverBody  string
		wantExit    int
	}{
		{"already_revoked_409", http.StatusConflict, `{"error":"already revoked","code":"CONFLICT","reason":"already_revoked"}`, 15},
		{"not_admitted_404", http.StatusNotFound, `{"error":"not admitted","code":"NOT_FOUND","reason":"not_admitted"}`, 15},
		{"identity_mismatch_403", http.StatusForbidden, `{"error":"identity mismatch","code":"FORBIDDEN","reason":"identity_mismatch"}`, exitGeneric},
		{"validation_400", http.StatusBadRequest, `{"error":"bad request","code":"VALIDATION_ERROR","reason":"reason_invalid"}`, exitUsage},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.serverCode)
				_, _ = w.Write([]byte(tc.serverBody))
			}))
			defer srv.Close()

			var stdout, stderr bytes.Buffer
			args := []string{
				digest,
				"--reason", "vulnerability",
				"--role", "registry_operator",
				"--registry", srv.URL + "/api/skills",
			}
			if got := runRevoke(args, &stdout, &stderr); got != tc.wantExit {
				t.Errorf("got exit %d, want %d; stderr=%q", got, tc.wantExit, stderr.String())
			}
		})
	}
}
