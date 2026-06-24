package main

// SPEC-0276 R4.2 — end-to-end tests for `skillctl verify --bundle`. These
// drive the real CLI runner with on-disk crypto material and assert the
// canonical exit codes, proving the trustless third-party path works with no
// install state and no network (the trust-roots file is a temp pinned file; no
// HTTP server is ever started).

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// bundleFixture is a fully-wired, self-consistent --bundle scenario on disk.
type bundleFixture struct {
	skbPath  string
	metaPath string
	trPath   string
	dir      string
	digest   string // "sha256:<hex>"
	authorID string
	regURL   string
	regPriv  ed25519.PrivateKey // pins this; used to sign a revocation list
}

// buildBundleFixture writes a .skb blob, its signed BundleMeta sidecar, and a
// pinned trust-roots file into a temp dir. mutate lets a test perturb the YAML
// (e.g. flip to from-registry) before it is written.
func buildBundleFixture(t *testing.T) bundleFixture {
	t.Helper()
	dir := t.TempDir()

	authorPub, authorPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("author keygen: %v", err)
	}
	regPub, regPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("reg keygen: %v", err)
	}

	// The .skb blob — arbitrary bytes; the verifier only sees them via sha256.
	skbPath := filepath.Join(dir, "demo@1.0.0.skb")
	content := []byte("a perfectly ordinary signed skill bundle blob")
	if err := os.WriteFile(skbPath, content, 0o644); err != nil {
		t.Fatalf("write skb: %v", err)
	}
	dRaw := sha256.Sum256(content)
	digestStr := "sha256:" + hex.EncodeToString(dRaw[:])

	authorID := "id:kamir@m3c"
	regURL := "https://reg.example/api/skills"

	meta := registry.BundleMeta{
		Bundle: map[string]any{
			"bundle_digest": digestStr,
			"name":          "demo",
			"version":       "1.0.0",
			"status":        "admitted",
		},
		Signatures: []registry.SignatureRow{
			{Role: "author", IdentityID: authorID, SignatureB64: signB64(authorPriv, dRaw), Status: "active"},
			{Role: "registry", IdentityID: "id:registry@aims-core", SignatureB64: signB64(regPriv, dRaw), Status: "active"},
		},
		CurrentGovernance: "green",
	}
	metaJSON, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		t.Fatalf("marshal meta: %v", err)
	}
	metaPath := filepath.Join(dir, "demo@1.0.0.skbmeta.json")
	if err := os.WriteFile(metaPath, metaJSON, 0o644); err != nil {
		t.Fatalf("write meta: %v", err)
	}

	trPath := filepath.Join(dir, "trust-roots.pinned.yaml")
	writePinnedTrustRoots(t, trPath, regURL,
		base64.StdEncoding.EncodeToString(regPub),
		authorID, base64.StdEncoding.EncodeToString(authorPub))

	return bundleFixture{
		skbPath: skbPath, metaPath: metaPath, trPath: trPath, dir: dir,
		digest: digestStr, authorID: authorID, regURL: regURL, regPriv: regPriv,
	}
}

func signB64(priv ed25519.PrivateKey, digest [32]byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, digest[:]))
}

func writePinnedTrustRoots(t *testing.T, path, regURL, regPubB64, authorID, authorPubB64 string) {
	t.Helper()
	body := "" +
		"trust_roots:\n" +
		"  - registry_url: " + regURL + "\n" +
		"    registry_keys:\n" +
		"      - id: reg-key-1\n" +
		"        pubkey: " + regPubB64 + "\n" +
		"    identity_keys_authorized: pinned\n" +
		"    governance_minimum: green\n" +
		"    authors:\n" +
		"      - id: " + authorID + "\n" +
		"        pubkey: " + authorPubB64 + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write trust-roots: %v", err)
	}
}

func TestVerifyBundle_HappyPath(t *testing.T) {
	f := buildBundleFixture(t)
	var out, errBuf bytes.Buffer
	code := runVerify([]string{"--bundle", f.skbPath, "--trust-roots", f.trPath}, &out, &errBuf)
	if code != exitOK {
		t.Fatalf("want exit 0, got %d; stderr=%s", code, errBuf.String())
	}
	if !bytes.Contains(out.Bytes(), []byte("offline, bundle")) {
		t.Errorf("missing offline marker; stdout=%s", out.String())
	}
	if !bytes.Contains(out.Bytes(), []byte(f.authorID)) {
		t.Errorf("chain summary should name the author; stdout=%s", out.String())
	}
}

func TestVerifyBundle_RepackDetected(t *testing.T) {
	f := buildBundleFixture(t)
	// Append a byte to the .skb AFTER the meta was signed → digest mismatch.
	skb, _ := os.ReadFile(f.skbPath)
	if err := os.WriteFile(f.skbPath, append(skb, 'X'), 0o644); err != nil {
		t.Fatalf("repack: %v", err)
	}
	var out, errBuf bytes.Buffer
	code := runVerify([]string{"--bundle", f.skbPath, "--trust-roots", f.trPath}, &out, &errBuf)
	if code != 10 {
		t.Fatalf("want exit 10 (digest mismatch), got %d; stderr=%s", code, errBuf.String())
	}
}

func TestVerifyBundle_WrongPinnedAuthor(t *testing.T) {
	f := buildBundleFixture(t)
	// Rewrite trust-roots to pin a DIFFERENT author key under the same id.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	regPubB64 := readRegPubB64(t, f.trPath)
	writePinnedTrustRoots(t, f.trPath, f.regURL, regPubB64, f.authorID,
		base64.StdEncoding.EncodeToString(otherPub))

	var out, errBuf bytes.Buffer
	code := runVerify([]string{"--bundle", f.skbPath, "--trust-roots", f.trPath}, &out, &errBuf)
	if code != 11 {
		t.Fatalf("want exit 11 (author sig invalid), got %d; stderr=%s", code, errBuf.String())
	}
}

func TestVerifyBundle_FromRegistryRootRefused(t *testing.T) {
	f := buildBundleFixture(t)
	regPubB64 := readRegPubB64(t, f.trPath)
	// A from-registry root has no pinned authors → --bundle can't verify
	// offline → actionable refusal (exitGeneric), not a crypto exit code.
	body := "" +
		"trust_roots:\n" +
		"  - registry_url: " + f.regURL + "\n" +
		"    registry_keys:\n" +
		"      - id: reg-key-1\n" +
		"        pubkey: " + regPubB64 + "\n" +
		"    identity_keys_authorized: from-registry\n" +
		"    governance_minimum: green\n"
	if err := os.WriteFile(f.trPath, []byte(body), 0o600); err != nil {
		t.Fatalf("rewrite tr: %v", err)
	}
	var out, errBuf bytes.Buffer
	code := runVerify([]string{"--bundle", f.skbPath, "--trust-roots", f.trPath}, &out, &errBuf)
	if code != exitGeneric {
		t.Fatalf("want exitGeneric, got %d", code)
	}
	if !bytes.Contains(errBuf.Bytes(), []byte("identity_keys_authorized: pinned")) {
		t.Errorf("expected actionable message; stderr=%s", errBuf.String())
	}
}

func TestVerifyBundle_MissingSidecar(t *testing.T) {
	f := buildBundleFixture(t)
	if err := os.Remove(f.metaPath); err != nil {
		t.Fatalf("rm meta: %v", err)
	}
	var out, errBuf bytes.Buffer
	code := runVerify([]string{"--bundle", f.skbPath, "--trust-roots", f.trPath}, &out, &errBuf)
	if code != exitGeneric {
		t.Fatalf("want exitGeneric for missing sidecar, got %d", code)
	}
	if !bytes.Contains(errBuf.Bytes(), []byte("sidecar not found")) {
		t.Errorf("expected sidecar-not-found message; stderr=%s", errBuf.String())
	}
}

func TestVerifyBundle_JSONOutput(t *testing.T) {
	f := buildBundleFixture(t)
	var out, errBuf bytes.Buffer
	code := runVerify([]string{"--bundle", f.skbPath, "--trust-roots", f.trPath, "--json"}, &out, &errBuf)
	if code != exitOK {
		t.Fatalf("want exit 0, got %d; stderr=%s", code, errBuf.String())
	}
	var res bundleVerifyResult
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("json parse: %v; out=%s", err, out.String())
	}
	if !res.OK || res.ExitCode != 0 || res.Digest != f.digest {
		t.Errorf("unexpected json result: %+v", res)
	}
}

// writeRevocations marshals a (possibly forged) revocation list to a path.
func writeRevocations(t *testing.T, dir string, list *verify.RevocationList) string {
	t.Helper()
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		t.Fatalf("marshal revocations: %v", err)
	}
	p := filepath.Join(dir, "revocations.json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatalf("write revocations: %v", err)
	}
	return p
}

func TestVerifyBundle_RevokedDigest(t *testing.T) {
	f := buildBundleFixture(t)
	// A revocation list, signed by the PINNED registry key, that contains this
	// bundle's digest → exit 17.
	list, err := verify.NewSignedRevocationList(f.regURL, "2026-06-22T10:00:00Z", 1, []string{f.digest}, f.regPriv)
	if err != nil {
		t.Fatal(err)
	}
	revPath := writeRevocations(t, f.dir, list)

	var out, errBuf bytes.Buffer
	code := runVerify([]string{"--bundle", f.skbPath, "--trust-roots", f.trPath, "--revocations", revPath}, &out, &errBuf)
	if code != 17 {
		t.Fatalf("want exit 17 (revoked), got %d; stderr=%s", code, errBuf.String())
	}
}

func TestVerifyBundle_NotRevoked(t *testing.T) {
	f := buildBundleFixture(t)
	// Properly signed list that does NOT contain this digest → still exit 0.
	other := sha256.Sum256([]byte("a different bundle"))
	otherDigest := "sha256:" + hex.EncodeToString(other[:])
	list, err := verify.NewSignedRevocationList(f.regURL, "2026-06-22T10:00:00Z", 1, []string{otherDigest}, f.regPriv)
	if err != nil {
		t.Fatal(err)
	}
	revPath := writeRevocations(t, f.dir, list)

	var out, errBuf bytes.Buffer
	code := runVerify([]string{"--bundle", f.skbPath, "--trust-roots", f.trPath, "--revocations", revPath}, &out, &errBuf)
	if code != exitOK {
		t.Fatalf("want exit 0 (not revoked), got %d; stderr=%s", code, errBuf.String())
	}
}

func TestVerifyBundle_ForgedRevocationListRefused(t *testing.T) {
	f := buildBundleFixture(t)
	// A list signed by an attacker key (not the pinned registry key). Must be
	// fail-closed: exit 12, NOT silently ignored.
	_, attackerPriv, _ := ed25519.GenerateKey(rand.Reader)
	list, err := verify.NewSignedRevocationList(f.regURL, "2026-06-22T10:00:00Z", 1, []string{f.digest}, attackerPriv)
	if err != nil {
		t.Fatal(err)
	}
	revPath := writeRevocations(t, f.dir, list)

	var out, errBuf bytes.Buffer
	code := runVerify([]string{"--bundle", f.skbPath, "--trust-roots", f.trPath, "--revocations", revPath}, &out, &errBuf)
	if code != 12 {
		t.Fatalf("want exit 12 (untrusted revocation list), got %d; stderr=%s", code, errBuf.String())
	}
}

// --- SPEC-0279 P4 — verify --bundle freshness contract ---

// writePinnedTrustRootsFresh is writePinnedTrustRoots plus a freshness policy
// (max_staleness + fail_policy), for the SPEC-0279 verify-bundle tests.
func writePinnedTrustRootsFresh(t *testing.T, path, regURL, regPubB64, authorID, authorPubB64, maxStaleness, failPolicy string) {
	t.Helper()
	body := "" +
		"trust_roots:\n" +
		"  - registry_url: " + regURL + "\n" +
		"    registry_keys:\n" +
		"      - id: reg-key-1\n" +
		"        pubkey: " + regPubB64 + "\n" +
		"    identity_keys_authorized: pinned\n" +
		"    governance_minimum: green\n" +
		"    max_staleness: " + maxStaleness + "\n" +
		"    fail_policy: " + failPolicy + "\n" +
		"    authors:\n" +
		"      - id: " + authorID + "\n" +
		"        pubkey: " + authorPubB64 + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write trust-roots: %v", err)
	}
}

// freshBundleISO returns an RFC3339 timestamp `age` in the past.
func freshBundleISO(age time.Duration) string {
	return time.Now().UTC().Add(-age).Format(time.RFC3339)
}

// A bundle with no declared data-scopes is HIGH-risk (fail-safe). A STALE
// revocation snapshot past max_staleness therefore fails closed → exit 22.
func TestVerifyBundle_StaleHighRiskFailsClosed(t *testing.T) {
	f := buildBundleFixture(t)
	regPubB64 := readRegPubB64(t, f.trPath)
	authorPubB64 := readAuthorPubB64(t, f.trPath)
	writePinnedTrustRootsFresh(t, f.trPath, f.regURL, regPubB64, f.authorID, authorPubB64, "24h", "open")

	list, err := verify.NewSignedRevocationList(f.regURL, freshBundleISO(48*time.Hour), 1, []string{otherDigest()}, f.regPriv)
	if err != nil {
		t.Fatal(err)
	}
	revPath := writeRevocations(t, f.dir, list)

	var out, errBuf bytes.Buffer
	code := runVerify([]string{"--bundle", f.skbPath, "--trust-roots", f.trPath, "--revocations", revPath}, &out, &errBuf)
	if code != verify.ExitRevocationStale {
		t.Fatalf("stale high-risk bundle must exit %d, got %d; stderr=%s", verify.ExitRevocationStale, code, errBuf.String())
	}
}

// A fresh snapshot allows the bundle.
func TestVerifyBundle_FreshSnapshotAllows(t *testing.T) {
	f := buildBundleFixture(t)
	regPubB64 := readRegPubB64(t, f.trPath)
	authorPubB64 := readAuthorPubB64(t, f.trPath)
	writePinnedTrustRootsFresh(t, f.trPath, f.regURL, regPubB64, f.authorID, authorPubB64, "24h", "closed")

	list, err := verify.NewSignedRevocationList(f.regURL, freshBundleISO(1*time.Hour), 1, []string{otherDigest()}, f.regPriv)
	if err != nil {
		t.Fatal(err)
	}
	revPath := writeRevocations(t, f.dir, list)

	var out, errBuf bytes.Buffer
	code := runVerify([]string{"--bundle", f.skbPath, "--trust-roots", f.trPath, "--revocations", revPath}, &out, &errBuf)
	if code != exitOK {
		t.Fatalf("fresh bundle must exit 0, got %d; stderr=%s", code, errBuf.String())
	}
}

// A fresh signed checkpoint resets the staleness clock for a stale list.
func TestVerifyBundle_CheckpointResets(t *testing.T) {
	f := buildBundleFixture(t)
	regPubB64 := readRegPubB64(t, f.trPath)
	authorPubB64 := readAuthorPubB64(t, f.trPath)
	writePinnedTrustRootsFresh(t, f.trPath, f.regURL, regPubB64, f.authorID, authorPubB64, "24h", "closed")

	list, err := verify.NewSignedRevocationList(f.regURL, freshBundleISO(48*time.Hour), 2, []string{otherDigest()}, f.regPriv)
	if err != nil {
		t.Fatal(err)
	}
	revPath := writeRevocations(t, f.dir, list)

	cp, err := verify.NewSignedFreshnessCheckpoint(f.regURL, 2, freshBundleISO(1*time.Hour), f.regPriv)
	if err != nil {
		t.Fatal(err)
	}
	cpPath := filepath.Join(f.dir, "checkpoint.json")
	if b, _ := json.MarshalIndent(cp, "", "  "); os.WriteFile(cpPath, b, 0o644) != nil {
		t.Fatal("write checkpoint")
	}

	var out, errBuf bytes.Buffer
	code := runVerify([]string{"--bundle", f.skbPath, "--trust-roots", f.trPath, "--revocations", revPath, "--checkpoint", cpPath}, &out, &errBuf)
	if code != exitOK {
		t.Fatalf("checkpoint must reset clock → exit 0, got %d; stderr=%s", code, errBuf.String())
	}
}

// An emergency deny-list naming the bundle's digest denies immediately (exit 17),
// even with a fresh snapshot.
func TestVerifyBundle_EmergencyDeniesDigest(t *testing.T) {
	f := buildBundleFixture(t)
	regPubB64 := readRegPubB64(t, f.trPath)
	authorPubB64 := readAuthorPubB64(t, f.trPath)
	writePinnedTrustRootsFresh(t, f.trPath, f.regURL, regPubB64, f.authorID, authorPubB64, "24h", "open")

	list, err := verify.NewSignedRevocationList(f.regURL, freshBundleISO(1*time.Hour), 1, []string{otherDigest()}, f.regPriv)
	if err != nil {
		t.Fatal(err)
	}
	revPath := writeRevocations(t, f.dir, list)

	em, err := verify.NewSignedEmergencyDenyList(f.regURL, freshBundleISO(30*time.Minute), 1, []string{f.digest}, f.regPriv)
	if err != nil {
		t.Fatal(err)
	}
	emPath := filepath.Join(f.dir, "emergency.json")
	if b, _ := json.MarshalIndent(em, "", "  "); os.WriteFile(emPath, b, 0o644) != nil {
		t.Fatal("write emergency")
	}

	var out, errBuf bytes.Buffer
	code := runVerify([]string{"--bundle", f.skbPath, "--trust-roots", f.trPath, "--revocations", revPath, "--emergency", emPath}, &out, &errBuf)
	if code != exitBundleRevoked {
		t.Fatalf("emergency must deny digest with exit %d, got %d; stderr=%s", exitBundleRevoked, code, errBuf.String())
	}
}

// otherDigest is a deterministic non-matching digest for the freshness tests.
func otherDigest() string {
	d := sha256.Sum256([]byte("some other bundle entirely"))
	return "sha256:" + hex.EncodeToString(d[:])
}

// readAuthorPubB64 extracts the pinned author pubkey b64 (the SECOND pubkey line).
func readAuthorPubB64(t *testing.T, trPath string) string {
	t.Helper()
	data, err := os.ReadFile(trPath)
	if err != nil {
		t.Fatalf("read tr: %v", err)
	}
	var pubkeys []string
	for _, line := range bytes.Split(data, []byte("\n")) {
		s := bytes.TrimSpace(line)
		if bytes.HasPrefix(s, []byte("pubkey:")) {
			pubkeys = append(pubkeys, string(bytes.TrimSpace(bytes.TrimPrefix(s, []byte("pubkey:")))))
		}
	}
	if len(pubkeys) < 2 {
		t.Fatalf("expected >=2 pubkey lines (reg + author), got %d", len(pubkeys))
	}
	return pubkeys[1]
}

// readRegPubB64 extracts the pinned registry pubkey b64 from a trust-roots file
// so a rewrite can keep the same registry key while changing the author pin.
func readRegPubB64(t *testing.T, trPath string) string {
	t.Helper()
	data, err := os.ReadFile(trPath)
	if err != nil {
		t.Fatalf("read tr: %v", err)
	}
	for _, line := range bytes.Split(data, []byte("\n")) {
		s := bytes.TrimSpace(line)
		// The registry key line is the first "pubkey:" under registry_keys;
		// the author pubkey appears later. Take the first match.
		if bytes.HasPrefix(s, []byte("pubkey:")) {
			return string(bytes.TrimSpace(bytes.TrimPrefix(s, []byte("pubkey:"))))
		}
	}
	t.Fatal("no pubkey line in trust-roots")
	return ""
}
