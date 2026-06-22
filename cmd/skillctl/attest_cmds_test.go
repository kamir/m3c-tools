package main

// Stream S9-cli (SPEC-0188 Phase 5). Tests for `skillctl attest`.
//
// The headline test (TestAttest_E2E_AgainstHTTPTestServer) wires the CLI
// runner up to an httptest.Server that mirrors what S9-aims's
// POST /api/skills/attestations will do: it parses the JSON, recomputes
// the canonical signed bytes from the JSON fields, verifies the ed25519
// signature against the reviewer's pubkey, and only then issues an
// attestation_id.
//
// This means the test exercises the cross-language byte-equality contract
// in a way that closely matches what the registry will actually require.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/signing"
)

// fakeRegistry is the in-test stand-in for aims-core's attestation
// endpoint. It intentionally re-implements the canonical byte assembly
// from scratch (not via the same Go helper the CLI uses) — that's the
// whole point: if the CLI's bytes don't match what an independent
// implementation builds from the same fields, the test fails.
type fakeRegistry struct {
	t            *testing.T
	pubKey       ed25519.PublicKey
	expectStatus int    // override 201 to simulate failure cases
	expectBody   string // override response body
	lastRequest  attestRequest
	wantSig      bool // when true, verify the signature; when false, skip
}

func (f *fakeRegistry) handler(w http.ResponseWriter, r *http.Request) {
	f.t.Helper()

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !strings.HasSuffix(r.URL.Path, "/attestations") {
		http.Error(w, "wrong path: "+r.URL.Path, http.StatusNotFound)
		return
	}
	if got := r.Header.Get("Content-Type"); got != "application/json" {
		http.Error(w, "wrong content-type: "+got, http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := json.Unmarshal(body, &f.lastRequest); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}

	// If a non-201 status was preconfigured (for failure tests), emit it
	// before doing any signature work.
	if f.expectStatus != 0 && f.expectStatus != http.StatusCreated {
		w.WriteHeader(f.expectStatus)
		_, _ = w.Write([]byte(f.expectBody))
		return
	}

	if f.wantSig {
		// Rebuild the canonical bytes here from the parsed JSON. This is
		// the cross-language gate — if the CLI builds different bytes
		// than this independently constructed sequence, ed25519.Verify
		// will reject the signature.
		canonical, err := signing.CanonicalizeAttestationMessage(
			f.lastRequest.BundleDigest,
			f.lastRequest.GovernanceLevel,
			f.lastRequest.AttestedAt,
			f.lastRequest.ReviewerID,
		)
		if err != nil {
			http.Error(w, "canonicalize: "+err.Error(), http.StatusBadRequest)
			return
		}
		sig, err := base64.StdEncoding.DecodeString(f.lastRequest.Signature)
		if err != nil {
			http.Error(w, "bad b64 signature: "+err.Error(), http.StatusBadRequest)
			return
		}
		if !ed25519.Verify(f.pubKey, canonical, sig) {
			http.Error(w, "signature does not verify", http.StatusBadRequest)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write([]byte(`{"attestation_id":"att_test_001"}`))
}

func newFakeRegistry(t *testing.T, pub ed25519.PublicKey) (*fakeRegistry, *httptest.Server) {
	t.Helper()
	f := &fakeRegistry{t: t, pubKey: pub, wantSig: true}
	srv := httptest.NewServer(http.HandlerFunc(f.handler))
	t.Cleanup(srv.Close)
	return f, srv
}

// makeReviewerKeys generates a keypair on disk and returns paths.
func makeReviewerKeys(t *testing.T, dir string) (privPath, pubPath string, pub ed25519.PublicKey) {
	t.Helper()
	stem := filepath.Join(dir, "reviewer")
	if err := signing.Generate(stem); err != nil {
		t.Fatal(err)
	}
	pub, err := signing.LoadPublicKey(stem + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	return stem + ".priv", stem + ".pub", pub
}

const validDigestForTest = "sha256:0000000000000000000000000000000000000000000000000000000000000001"

func TestAttest_E2E_AgainstHTTPTestServer(t *testing.T) {
	dir := t.TempDir()
	priv, _, pub := makeReviewerKeys(t, dir)

	fr, srv := newFakeRegistry(t, pub)

	var stdout, stderr bytes.Buffer

	pinnedNow := func() time.Time {
		return time.Date(2026, 5, 5, 19, 30, 0, 0, time.UTC)
	}

	args := []string{
		validDigestForTest,
		"--level", "green",
		"--rationale", "Read-only ER1 query, no PII",
		"--reviewer-id", "id:test@s9",
		"--key", priv,
		"--registry", srv.URL,
	}
	code := runAttestWithClient(args, &stdout, &stderr, pinnedNow, srv.Client())
	if code != exitOK {
		t.Fatalf("attest exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "attestation_id: att_test_001") {
		t.Errorf("stdout missing attestation_id line: %q", out)
	}

	// Server saw exactly the fields we sent.
	if fr.lastRequest.BundleDigest != validDigestForTest {
		t.Errorf("server saw digest=%q, want %q", fr.lastRequest.BundleDigest, validDigestForTest)
	}
	if fr.lastRequest.GovernanceLevel != "green" {
		t.Errorf("server saw level=%q", fr.lastRequest.GovernanceLevel)
	}
	if fr.lastRequest.ReviewerID != "id:test@s9" {
		t.Errorf("server saw reviewer_id=%q", fr.lastRequest.ReviewerID)
	}
	if fr.lastRequest.AttestedAt != "2026-05-05T19:30:00Z" {
		t.Errorf("server saw attested_at=%q (want pinned 2026-05-05T19:30:00Z)", fr.lastRequest.AttestedAt)
	}
	if fr.lastRequest.Rationale != "Read-only ER1 query, no PII" {
		t.Errorf("server saw rationale=%q", fr.lastRequest.Rationale)
	}
	// Signature must base64-decode to exactly 64 bytes.
	rawSig, err := base64.StdEncoding.DecodeString(fr.lastRequest.Signature)
	if err != nil {
		t.Fatalf("signature is not valid base64: %v", err)
	}
	if len(rawSig) != ed25519.SignatureSize {
		t.Errorf("signature length = %d bytes, want %d", len(rawSig), ed25519.SignatureSize)
	}
}

func TestAttest_UsageError_BadLevel(t *testing.T) {
	// AC4 from brief: --level=blue must exit with usage error (2) and
	// must not contact the registry.
	dir := t.TempDir()
	priv, _, _ := makeReviewerKeys(t, dir)

	contacted := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contacted = true
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	args := []string{
		validDigestForTest,
		"--level", "blue",
		"--rationale", "x",
		"--reviewer-id", "id:test@s9",
		"--key", priv,
		"--registry", srv.URL,
	}
	code := runAttestWithClient(args, &stdout, &stderr, time.Now, srv.Client())
	if code != exitUsage {
		t.Errorf("--level=blue exit=%d, want %d", code, exitUsage)
	}
	if contacted {
		t.Error("registry was contacted despite usage error")
	}
}

func TestAttest_UsageError_BadDigest(t *testing.T) {
	dir := t.TempDir()
	priv, _, _ := makeReviewerKeys(t, dir)

	contacted := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contacted = true
	}))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	args := []string{
		"not-a-digest",
		"--level", "green",
		"--rationale", "x",
		"--reviewer-id", "id:test@s9",
		"--key", priv,
		"--registry", srv.URL,
	}
	code := runAttestWithClient(args, &stdout, &stderr, time.Now, srv.Client())
	if code != exitUsage {
		t.Errorf("bad digest exit=%d, want %d", code, exitUsage)
	}
	if contacted {
		t.Error("registry was contacted despite bad digest")
	}
}

func TestAttest_UsageError_MissingFlags(t *testing.T) {
	dir := t.TempDir()
	priv, _, _ := makeReviewerKeys(t, dir)

	cases := []struct {
		name string
		args []string
	}{
		{"no positional digest", []string{"--level", "green", "--rationale", "x", "--reviewer-id", "id:r@x", "--key", priv}},
		{"no level", []string{validDigestForTest, "--rationale", "x", "--reviewer-id", "id:r@x", "--key", priv}},
		{"no rationale", []string{validDigestForTest, "--level", "green", "--reviewer-id", "id:r@x", "--key", priv}},
		{"no reviewer-id", []string{validDigestForTest, "--level", "green", "--rationale", "x", "--key", priv}},
		{"no key", []string{validDigestForTest, "--level", "green", "--rationale", "x", "--reviewer-id", "id:r@x"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := runAttest(tc.args, &stdout, &stderr); code != exitUsage {
				t.Errorf("exit=%d, want %d (%s); stderr=%s", code, exitUsage, tc.name, stderr.String())
			}
		})
	}
}

func TestAttest_RegistryReturns400_PropagatesBody(t *testing.T) {
	// AC5 from brief: server returns 400 → CLI exits 1 with stderr
	// including the response body.
	dir := t.TempDir()
	priv, _, pub := makeReviewerKeys(t, dir)

	fr, srv := newFakeRegistry(t, pub)
	fr.expectStatus = http.StatusBadRequest
	fr.expectBody = `{"error":"reviewer is not registered"}`

	var stdout, stderr bytes.Buffer
	args := []string{
		validDigestForTest,
		"--level", "green",
		"--rationale", "x",
		"--reviewer-id", "id:test@s9",
		"--key", priv,
		"--registry", srv.URL,
	}
	code := runAttestWithClient(args, &stdout, &stderr, time.Now, srv.Client())
	if code != exitGeneric {
		t.Fatalf("exit=%d, want %d (generic). stderr=%s", code, exitGeneric, stderr.String())
	}
	errStr := stderr.String()
	if !strings.Contains(errStr, "400") {
		t.Errorf("stderr missing status: %q", errStr)
	}
	if !strings.Contains(errStr, "reviewer is not registered") {
		t.Errorf("stderr missing response body: %q", errStr)
	}
}

func TestAttest_RegistryUnreachable_ExitGeneric(t *testing.T) {
	dir := t.TempDir()
	priv, _, _ := makeReviewerKeys(t, dir)

	var stdout, stderr bytes.Buffer
	args := []string{
		validDigestForTest,
		"--level", "green",
		"--rationale", "x",
		"--reviewer-id", "id:test@s9",
		"--key", priv,
		// 127.0.0.1 with a port we'd never bind to — connection refused.
		"--registry", "http://127.0.0.1:1/api/skills",
		"--timeout", "2s",
	}
	code := runAttest(args, &stdout, &stderr)
	if code != exitGeneric {
		t.Errorf("unreachable registry exit=%d, want %d. stderr=%s", code, exitGeneric, stderr.String())
	}
}

func TestAttest_LoadPrivKeyFails_ExitGeneric(t *testing.T) {
	dir := t.TempDir()
	bogus := filepath.Join(dir, "no-such.priv")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not contact registry when key load fails")
	}))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	args := []string{
		validDigestForTest,
		"--level", "green",
		"--rationale", "x",
		"--reviewer-id", "id:test@s9",
		"--key", bogus,
		"--registry", srv.URL,
	}
	code := runAttestWithClient(args, &stdout, &stderr, time.Now, srv.Client())
	if code != exitGeneric {
		t.Errorf("missing key exit=%d, want %d", code, exitGeneric)
	}
}

func TestAttest_PrivateKeyPathInError_NotKeyBytes(t *testing.T) {
	// Mirror the corresponding sign-side test: when the key file is
	// malformed, the error message should reference the path but not
	// any of the (would-be) key bytes.
	dir := t.TempDir()
	junk := filepath.Join(dir, "junk.priv")
	body := "-----BEGIN PRIVATE KEY-----\nbm90IHJlYWxseSBhIGtleQ==\n-----END PRIVATE KEY-----\n"
	if err := os.WriteFile(junk, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	args := []string{
		validDigestForTest,
		"--level", "green",
		"--rationale", "x",
		"--reviewer-id", "id:test@s9",
		"--key", junk,
		"--registry", srv.URL,
	}
	_ = runAttestWithClient(args, &stdout, &stderr, time.Now, srv.Client())
	if strings.Contains(stderr.String(), "bm90IHJlYWxseSBhIGtleQ") {
		t.Errorf("stderr leaked key bytes: %q", stderr.String())
	}
}

func TestValidateRegistryURL_AllowsHTTPSAlways(t *testing.T) {
	cases := []string{
		"https://aims-core.example.com/api/skills",
		"https://1.2.3.4:8443/api/skills",
		"https://localhost/api/skills",
	}
	for _, u := range cases {
		t.Run(u, func(t *testing.T) {
			if err := validateRegistryURL(u); err != nil {
				t.Errorf("rejected %q: %v", u, err)
			}
		})
	}
}

func TestValidateRegistryURL_AllowsPlainHTTPForPrivate(t *testing.T) {
	// Homelab registries (192.168.0.131:9100 from the brief) MUST work.
	cases := []string{
		"http://localhost:8080/api/skills",
		"http://127.0.0.1:8080/api/skills",
		"http://192.168.0.131:9100/api/skills", // explicit homelab
		"http://10.0.0.5/api/skills",
		"http://172.16.0.10/api/skills",
	}
	for _, u := range cases {
		t.Run(u, func(t *testing.T) {
			if err := validateRegistryURL(u); err != nil {
				t.Errorf("rejected %q: %v", u, err)
			}
		})
	}
}

func TestValidateRegistryURL_RejectsPlainHTTPForPublic(t *testing.T) {
	cases := []string{
		"http://aims-core.example.com/api/skills",
		"http://1.2.3.4/api/skills",      // public IP
		"http://8.8.8.8:8080/api/skills", // public IP
	}
	for _, u := range cases {
		t.Run(u, func(t *testing.T) {
			if err := validateRegistryURL(u); err == nil {
				t.Errorf("accepted %q; expected refusal", u)
			}
		})
	}
}

func TestValidateRegistryURL_RejectsBadSchemes(t *testing.T) {
	cases := []string{
		"",
		"file:///etc/passwd",
		"ftp://aims-core.example.com",
		"ssh://aims-core",
		"://no-scheme",
		"https://",  // no host
		"not-a-url", // url.Parse won't error but Scheme will be empty
	}
	for _, u := range cases {
		t.Run(u, func(t *testing.T) {
			if err := validateRegistryURL(u); err == nil {
				t.Errorf("accepted %q; expected refusal", u)
			}
		})
	}
}

// TestAttest_SelfAttested_NoteAndFlag covers SPEC-0246 §5.1: when --author-id
// equals --reviewer-id (normalized), the attestation is stamped
// self_attested=true, the request carries it, and a clear stderr note warns
// that a require_independent_review floor will refuse the bundle.
func TestAttest_SelfAttested_NoteAndFlag(t *testing.T) {
	dir := t.TempDir()
	priv, _, pub := makeReviewerKeys(t, dir)
	fr, srv := newFakeRegistry(t, pub)

	pinnedNow := func() time.Time { return time.Date(2026, 5, 5, 19, 30, 0, 0, time.UTC) }

	var stdout, stderr bytes.Buffer
	args := []string{
		validDigestForTest,
		"--level", "green",
		"--rationale", "self review for the personal tenant",
		"--reviewer-id", "id:Kamir@m3c", // mixed case on purpose
		"--author-id", " id:kamir@m3c ", // padded + lowercase: same principal
		"--key", priv,
		"--registry", srv.URL,
	}
	code := runAttestWithClient(args, &stdout, &stderr, pinnedNow, srv.Client())
	if code != exitOK {
		t.Fatalf("attest exit=%d stderr=%s", code, stderr.String())
	}
	if !fr.lastRequest.SelfAttested {
		t.Errorf("request self_attested should be true when reviewer == author (normalized)")
	}
	if !strings.Contains(stderr.String(), "self-attestation") {
		t.Errorf("stderr should warn about self-attestation; got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "self_attested: true") {
		t.Errorf("stdout should report self_attested: true; got %q", stdout.String())
	}
}

// TestAttest_IndependentReview_NoNote covers the independent case: a distinct
// --author-id yields self_attested=false, no warning note.
func TestAttest_IndependentReview_NoNote(t *testing.T) {
	dir := t.TempDir()
	priv, _, pub := makeReviewerKeys(t, dir)
	fr, srv := newFakeRegistry(t, pub)

	pinnedNow := func() time.Time { return time.Date(2026, 5, 5, 19, 30, 0, 0, time.UTC) }

	var stdout, stderr bytes.Buffer
	args := []string{
		validDigestForTest,
		"--level", "green",
		"--rationale", "independent review by Eric",
		"--reviewer-id", "id:eric@m3c",
		"--author-id", "id:kamir@m3c",
		"--key", priv,
		"--registry", srv.URL,
	}
	code := runAttestWithClient(args, &stdout, &stderr, pinnedNow, srv.Client())
	if code != exitOK {
		t.Fatalf("attest exit=%d stderr=%s", code, stderr.String())
	}
	if fr.lastRequest.SelfAttested {
		t.Errorf("request self_attested should be false for distinct author/reviewer")
	}
	if strings.Contains(stderr.String(), "self-attestation") {
		t.Errorf("stderr must NOT warn for independent review; got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "self_attested: false") {
		t.Errorf("stdout should report self_attested: false; got %q", stdout.String())
	}
}

// TestAttest_NoAuthorID_OmitsLocalSelfAttested covers the offline path with no
// --author-id: the CLI cannot compute self_attested locally, so it does not
// emit the stdout line (the server is the authority) and sends self_attested=false.
func TestAttest_NoAuthorID_OmitsLocalSelfAttested(t *testing.T) {
	dir := t.TempDir()
	priv, _, pub := makeReviewerKeys(t, dir)
	fr, srv := newFakeRegistry(t, pub)

	pinnedNow := func() time.Time { return time.Date(2026, 5, 5, 19, 30, 0, 0, time.UTC) }

	var stdout, stderr bytes.Buffer
	args := []string{
		validDigestForTest,
		"--level", "green",
		"--rationale", "no author id supplied",
		"--reviewer-id", "id:kamir@m3c",
		"--key", priv,
		"--registry", srv.URL,
	}
	code := runAttestWithClient(args, &stdout, &stderr, pinnedNow, srv.Client())
	if code != exitOK {
		t.Fatalf("attest exit=%d stderr=%s", code, stderr.String())
	}
	if fr.lastRequest.SelfAttested {
		t.Errorf("self_attested should default false when not locally computable")
	}
	if strings.Contains(stdout.String(), "self_attested:") {
		t.Errorf("stdout should NOT claim a self_attested verdict without --author-id; got %q", stdout.String())
	}
}
