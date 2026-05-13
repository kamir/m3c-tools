package registry

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/er1"
)

// pullFake records nothing on POST (we don't use it) but answers
// /memory/<ctx>/search with seeded items, picking by tag substring.
type pullFake struct {
	mu    sync.Mutex
	items []map[string]any
	srv   *httptest.Server
}

func newPullFake(t *testing.T) *pullFake {
	f := &pullFake{}
	mux := http.NewServeMux()
	mux.HandleFunc("/upload_2", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"doc_id": "doc-x", "message": "ok"})
	})
	mux.HandleFunc("/memory/", func(w http.ResponseWriter, r *http.Request) {
		tagsQ := r.URL.Query().Get("tags")
		f.mu.Lock()
		defer f.mu.Unlock()
		var out []any
		for _, item := range f.items {
			tags, _ := item["tags"].(string)
			match := true
			for _, want := range strings.Split(tagsQ, ",") {
				want = strings.TrimSpace(want)
				if want == "" {
					continue
				}
				if !strings.Contains(tags, want) {
					match = false
					break
				}
			}
			if match {
				out = append(out, item)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"items": out})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *pullFake) cfg() *er1.Config {
	return &er1.Config{
		APIURL:    f.srv.URL + "/upload_2",
		APIKey:    "k",
		ContextID: "skills",
		VerifySSL: false,
	}
}

func (f *pullFake) addItem(item map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.items = append(f.items, item)
}

// ─── Test helpers ──────────────────────────────────────────────────────────

func mintBundleBytes(content string) (skb []byte, digest string, digestBytes []byte) {
	skb = []byte(content)
	d := sha256.Sum256(skb)
	return skb, "sha256:" + hex.EncodeToString(d[:]), d[:]
}

// mintAdmitItem builds a real admit ER1 item (signed envelope, with the .skb
// bytes embedded inline) the pull path can verify against.
func mintAdmitItem(t *testing.T, priv ed25519.PrivateKey, name, version, content string) (item map[string]any, digest string) {
	t.Helper()
	skb, d, dbytes := mintBundleBytes(content)
	// Real signature over the digest bytes — gate 3 must pass.
	sig := ed25519.Sign(priv, dbytes)
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	pubFP := selfFingerprint(priv.Public().(ed25519.PublicKey))
	ev, err := BuildBundleAdmittedEvent(AdmittedEventInput{
		BundleDigest:       d,
		Name:               name,
		Version:            version,
		AuthorIntent:       "green",
		AdmittedByIdentity: "id:test@m3c",
		AdmittedAt:         testTime(),
		Signatures: []SignatureRef{
			{Role: "author", IdentityID: "id:test@m3c", SignatureB64: sigB64, PubKeyFingerprint: pubFP},
			{Role: "registry", IdentityID: "id:test@m3c", SignatureB64: sigB64, PubKeyFingerprint: pubFP},
		},
	})
	if err != nil {
		t.Fatalf("Build admit: %v", err)
	}
	if _, err := SignEnvelopeSignature(priv, ev); err != nil {
		t.Fatalf("Sign envelope: %v", err)
	}
	body := renderTestAdmitBody(ev, skb)
	tags := strings.Join([]string{
		"m3c-skill-bundle",
		"skb-transport-version:1",
		"skill:" + name,
		"skill-version:" + name + "@" + version,
		"skill-digest:" + d,
		"skill-event:" + EventKindAdmitted,
		"skill-registry:self",
		"skill-author:id:test@m3c",
		"governance:green",
		"host:testhost",
		"transport:er1-inline",
		"claude-code.skill-registry",
	}, ",")
	return map[string]any{
		"doc_id":     "admit-" + version,
		"tags":       tags,
		"transcript": body,
	}, d
}

func mintAttestItem(t *testing.T, priv ed25519.PrivateKey, name, version, digest, level, rationale string) map[string]any {
	t.Helper()
	ev, err := BuildAttestationPublishedEvent(AttestedEventInput{
		BundleDigest:    digest,
		ReviewerID:      "id:test@m3c",
		GovernanceLevel: level,
		Rationale:       rationale,
		OccurredAt:      testTime(),
	})
	if err != nil {
		t.Fatalf("Build attest: %v", err)
	}
	if _, err := SignEnvelopeSignature(priv, ev); err != nil {
		t.Fatalf("Sign attest: %v", err)
	}
	body := renderTestEventBody(ev, "attested")
	tags := strings.Join([]string{
		"m3c-skill-bundle",
		"skb-transport-version:1",
		"skill:" + name,
		"skill-version:" + name + "@" + version,
		"skill-digest:" + digest,
		"skill-event:" + EventKindAttested,
		"skill-registry:self",
		"governance:" + level,
		"claude-code.skill-registry",
	}, ",")
	return map[string]any{
		"doc_id":     "attest-" + version + "-" + level,
		"tags":       tags,
		"transcript": body,
	}
}

func mintRevokeItem(t *testing.T, priv ed25519.PrivateKey, name, version, digest, reason string) map[string]any {
	t.Helper()
	ev, err := BuildBundleRevokedEvent(RevokedEventInput{
		BundleDigest: digest,
		ReasonCode:   reason,
		RevokedBy:    "id:test@m3c",
		OccurredAt:   testTime(),
	})
	if err != nil {
		t.Fatalf("Build revoke: %v", err)
	}
	if _, err := SignEnvelopeSignature(priv, ev); err != nil {
		t.Fatalf("Sign revoke: %v", err)
	}
	body := renderTestEventBody(ev, "revoked")
	tags := strings.Join([]string{
		"m3c-skill-bundle",
		"skill:" + name,
		"skill-version:" + name + "@" + version,
		"skill-digest:" + digest,
		"skill-event:" + EventKindRevoked,
		"skill-registry:self",
	}, ",")
	return map[string]any{
		"doc_id":     "revoke-" + version,
		"tags":       tags,
		"transcript": body,
	}
}

func renderTestAdmitBody(ev map[string]any, skb []byte) string {
	envBytes, _ := json.MarshalIndent(ev, "", "  ")
	return "# admit\n\n```json\n" + string(envBytes) + "\n```\n\n```skb-base64\n" + base64.StdEncoding.EncodeToString(skb) + "\n```\n"
}

func renderTestEventBody(ev map[string]any, kind string) string {
	envBytes, _ := json.MarshalIndent(ev, "", "  ")
	return "# " + kind + "\n\n```json\n" + string(envBytes) + "\n```\n"
}

func testTime() time.Time {
	return time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
}

// ─── Tests ─────────────────────────────────────────────────────────────────

func writeTrustRoots(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "trust-roots.yaml")
	fp := selfFingerprint(pub)
	body := fmt.Sprintf("registry: self\npubkey_b64: %s\nfingerprint: %s\ngovernance_minimum: green\n",
		base64.StdEncoding.EncodeToString(pub), fp)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write trust-roots: %v", err)
	}
	return path
}

func TestLoadSelfTrustRoots_FingerprintRecomputedWhenAbsent(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	dir := t.TempDir()
	path := filepath.Join(dir, "trust-roots.yaml")
	body := "registry: self\npubkey_b64: " + base64.StdEncoding.EncodeToString(pub) + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	tr, err := LoadSelfTrustRoots(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !strings.HasPrefix(tr.Fingerprint, "sha256:") {
		t.Errorf("fingerprint not computed: %q", tr.Fingerprint)
	}
}

func TestLoadSelfTrustRoots_FingerprintMismatchRefuses(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	dir := t.TempDir()
	path := filepath.Join(dir, "trust-roots.yaml")
	body := "registry: self\npubkey_b64: " + base64.StdEncoding.EncodeToString(pub) + "\nfingerprint: sha256:WRONG\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadSelfTrustRoots(path)
	if err == nil || !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Errorf("err = %v, want fingerprint mismatch", err)
	}
}

func TestSelfTrustRoots_MeetsFloor(t *testing.T) {
	tr := &SelfTrustRoots{GovernanceMinimum: "green"}
	if !tr.MeetsFloor("green") {
		t.Error("green should meet green floor")
	}
	if tr.MeetsFloor("yellow") {
		t.Error("yellow should NOT meet green floor")
	}
	tr.GovernanceMinimum = "yellow"
	if !tr.MeetsFloor("green") {
		t.Error("green should meet yellow floor (green is stricter)")
	}
	if !tr.MeetsFloor("yellow") {
		t.Error("yellow should meet yellow floor")
	}
}

func TestPullBundles_HappyPath_AllGatesPass(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	f := newPullFake(t)
	admit, digest := mintAdmitItem(t, priv, "fetch-contract", "1.0.0", "PRETEND-SKB-BYTES")
	attest := mintAttestItem(t, priv, "fetch-contract", "1.0.0", digest, "green", "ok")
	f.addItem(admit)
	f.addItem(attest)

	trPath := writeTrustRoots(t, pub)
	tr, err := LoadSelfTrustRoots(trPath)
	if err != nil {
		t.Fatalf("trust-roots: %v", err)
	}

	// Redirect the cache root into TempDir so the test doesn't write to ~/.cache.
	t.Setenv("M3C_SKILL_CACHE_DIR", t.TempDir())

	res, err := PullBundles(f.cfg(), "skills", tr, PullOpts{})
	if err != nil {
		t.Fatalf("PullBundles: %v", err)
	}
	if len(res.Staged) != 1 {
		t.Fatalf("staged = %d, want 1; skipped = %+v", len(res.Staged), res.Skipped)
	}
	if len(res.Skipped) != 0 {
		t.Fatalf("skipped = %+v, want 0", res.Skipped)
	}
	s := res.Staged[0]
	if s.Digest != digest || s.Name != "fetch-contract" || s.Version != "1.0.0" || s.Governance != "green" {
		t.Errorf("staged = %+v", s)
	}
	if _, err := os.Stat(s.StagedSkbPath); err != nil {
		t.Errorf("staged .skb missing: %v", err)
	}
}

func TestPullBundles_GovernanceFloor_RejectsUnattested(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	f := newPullFake(t)
	admit, _ := mintAdmitItem(t, priv, "x", "1.0.0", "skb")
	f.addItem(admit) // no attest

	trPath := writeTrustRoots(t, pub)
	tr, _ := LoadSelfTrustRoots(trPath)
	t.Setenv("M3C_SKILL_CACHE_DIR", t.TempDir())

	res, err := PullBundles(f.cfg(), "skills", tr, PullOpts{})
	if err != nil {
		t.Fatalf("PullBundles: %v", err)
	}
	if len(res.Skipped) != 1 || !errors.Is(res.Skipped[0].Gate, ErrGateGovernance) {
		t.Fatalf("expected ErrGateGovernance, got skipped=%+v staged=%+v", res.Skipped, res.Staged)
	}
}

func TestPullBundles_Revoked_RejectsAtGate5(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	f := newPullFake(t)
	admit, digest := mintAdmitItem(t, priv, "x", "1.0.0", "skb")
	attest := mintAttestItem(t, priv, "x", "1.0.0", digest, "green", "ok")
	revoke := mintRevokeItem(t, priv, "x", "1.0.0", digest, "deprecated")
	f.addItem(admit)
	f.addItem(attest)
	f.addItem(revoke)

	trPath := writeTrustRoots(t, pub)
	tr, _ := LoadSelfTrustRoots(trPath)
	t.Setenv("M3C_SKILL_CACHE_DIR", t.TempDir())

	res, err := PullBundles(f.cfg(), "skills", tr, PullOpts{})
	if err != nil {
		t.Fatalf("PullBundles: %v", err)
	}
	if len(res.Skipped) != 1 || !errors.Is(res.Skipped[0].Gate, ErrGateRevoked) {
		t.Fatalf("expected ErrGateRevoked, got skipped=%+v", res.Skipped)
	}
}

func TestPullBundles_WrongKey_RejectsAtGate1(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	otherPub, _, _ := ed25519.GenerateKey(nil)
	f := newPullFake(t)
	admit, digest := mintAdmitItem(t, priv, "x", "1.0.0", "skb")
	f.addItem(admit)
	f.addItem(mintAttestItem(t, priv, "x", "1.0.0", digest, "green", "ok"))

	trPath := writeTrustRoots(t, otherPub) // wrong key!
	tr, _ := LoadSelfTrustRoots(trPath)
	t.Setenv("M3C_SKILL_CACHE_DIR", t.TempDir())

	res, err := PullBundles(f.cfg(), "skills", tr, PullOpts{})
	if err != nil {
		t.Fatalf("PullBundles: %v", err)
	}
	if len(res.Skipped) != 1 || !errors.Is(res.Skipped[0].Gate, ErrGateEnvelope) {
		t.Fatalf("expected ErrGateEnvelope, got %+v", res.Skipped)
	}
}

func TestListRegistry_LatestSkipsRevoked(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	f := newPullFake(t)
	admit, digest := mintAdmitItem(t, priv, "good", "1.0.0", "skb")
	admitR, digestR := mintAdmitItem(t, priv, "bad", "1.0.0", "skb2")
	f.addItem(admit)
	f.addItem(mintAttestItem(t, priv, "good", "1.0.0", digest, "green", "ok"))
	f.addItem(admitR)
	f.addItem(mintAttestItem(t, priv, "bad", "1.0.0", digestR, "green", "ok"))
	f.addItem(mintRevokeItem(t, priv, "bad", "1.0.0", digestR, "deprecated"))

	listing, err := ListRegistry(f.cfg(), "skills", ListOpts{OnlyLatest: true})
	if err != nil {
		t.Fatalf("ListRegistry: %v", err)
	}
	names := map[string]bool{}
	for _, s := range listing.Skills {
		names[s.Name] = true
		if s.IsRevoked {
			t.Errorf("--latest returned a revoked skill %q", s.Name)
		}
	}
	if !names["good"] {
		t.Error("expected `good` in --latest listing")
	}
	if names["bad"] {
		t.Error("`bad` is revoked — must NOT appear in --latest listing")
	}
}

func TestShowSkill_RendersTimeline(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	f := newPullFake(t)
	admit, digest := mintAdmitItem(t, priv, "x", "1.0.0", "skb")
	f.addItem(admit)
	f.addItem(mintAttestItem(t, priv, "x", "1.0.0", digest, "green", "ok"))
	view, err := ShowSkill(f.cfg(), "skills", "x")
	if err != nil {
		t.Fatalf("ShowSkill: %v", err)
	}
	if view.Name != "x" || view.LatestDigest != digest {
		t.Errorf("view = %+v", view)
	}
	kinds := map[string]bool{}
	for _, e := range view.Events {
		kinds[e.Kind] = true
	}
	if !kinds["admitted"] || !kinds["attested"] {
		t.Errorf("missing event kinds: %v", kinds)
	}
}

// keep the io import nominally referenced (used implicitly via the test
// helpers and the httptest server elsewhere).
var _ = io.Discard
