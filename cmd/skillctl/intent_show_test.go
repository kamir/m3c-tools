package main

// SPEC-0196 §12 Q1 / P2b — `skillctl intent show` provenance (P2b challenge-gate fix).
//
// A CISO must NEVER see an UNVERIFIED registry-served scope labeled as
// author-signed. The registry response (meta.Manifest = its parsed manifest copy,
// meta.Bundle = the mutable post-admit row) arrives over plain HTTP with NO digest
// recompute and NO signature check, so neither is authoritative. A scope is
// labeled signed-manifest / AUTHORITATIVE ONLY when read from a local .skb whose
// digest this tool recomputed and matched the registry-advertised+author-signed
// digest (the `--bundle` path → verify.ReadDigestVerifiedManifest), which is the
// SAME trust boundary `verify` enforces.

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
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

func TestExtractDeclaredView_Provenance(t *testing.T) {
	regDep := map[string]any{"id": "ds:reg", "kind": "er1_collection", "access": "read"}
	rowDep := map[string]any{"id": "ds:row", "kind": "local_fs", "access": "read"}

	t.Run("registry manifest only → registry-reported, NEVER signed", func(t *testing.T) {
		meta := &registry.BundleMeta{
			Manifest: map[string]any{"data_dependencies": []any{regDep}},
		}
		v := extractDeclaredView(meta)
		if v.hasSigned() {
			t.Fatalf("registry manifest must NOT populate the signed source")
		}
		if !v.hasRegistry() || v.hasRow() {
			t.Fatalf("hasRegistry=%v hasRow=%v", v.hasRegistry(), v.hasRow())
		}
		_, deps, prov := v.authoritativeIntent()
		if prov != provRegistryReported {
			t.Errorf("provenance = %q, want registry-reported", prov)
		}
		if len(deps) != 1 || deps[0]["id"] != "ds:reg" {
			t.Errorf("registry-reported deps wrong: %+v", deps)
		}
	})

	t.Run("row only → bundle-row advisory", func(t *testing.T) {
		meta := &registry.BundleMeta{
			Bundle: map[string]any{"data_dependencies": []any{rowDep}},
		}
		v := extractDeclaredView(meta)
		if v.hasSigned() || v.hasRegistry() || !v.hasRow() {
			t.Fatalf("hasSigned=%v hasRegistry=%v hasRow=%v", v.hasSigned(), v.hasRegistry(), v.hasRow())
		}
		_, _, prov := v.authoritativeIntent()
		if prov != provBundleRow {
			t.Errorf("provenance = %q, want bundle-row", prov)
		}
	})

	t.Run("extractDeclaredView never sets the signed source", func(t *testing.T) {
		meta := &registry.BundleMeta{
			Manifest: map[string]any{"data_dependencies": []any{regDep}},
			Bundle:   map[string]any{"data_dependencies": []any{rowDep}},
		}
		v := extractDeclaredView(meta)
		if v.hasSigned() {
			t.Fatalf("the untrusted registry response must never produce a signed scope")
		}
		_, _, prov := v.authoritativeIntent()
		if prov != provRegistryReported {
			t.Errorf("registry-reported must win over bundle-row when both present: %q", prov)
		}
	})

	t.Run("neither → empty", func(t *testing.T) {
		v := extractDeclaredView(&registry.BundleMeta{})
		if v.hasSigned() || v.hasRegistry() || v.hasRow() {
			t.Fatalf("expected nothing declared")
		}
		_, _, prov := v.authoritativeIntent()
		if prov != "" {
			t.Errorf("provenance = %q, want empty", prov)
		}
	})

	t.Run("overlaySignedScope is the ONLY path to signed provenance", func(t *testing.T) {
		v := extractDeclaredView(&registry.BundleMeta{})
		v.overlaySignedScope(nil, []map[string]any{{"id": "ds:authoritative"}})
		if !v.hasSigned() {
			t.Fatalf("overlaySignedScope should populate the signed source")
		}
		_, deps, prov := v.authoritativeIntent()
		if prov != provSignedManifest || deps[0]["id"] != "ds:authoritative" {
			t.Errorf("signed scope must be authoritative: prov=%q deps=%+v", prov, deps)
		}
	})
}

// metaServer serves a fixed BundleMeta for any /bundles/<digest>?meta=1 GET.
func metaServer(t *testing.T, meta registry.BundleMeta) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/bundles/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(meta)
	}))
}

// TestIntentShow_MaliciousRegistryScopeIsUnverified is the red-team scenario the
// challenge-gate finding describes: a registry serves a `secrets_store` /
// `keychain://*` scope that is in NO signed artifact, stuffed into BOTH the parsed
// manifest copy AND the mutable row, hoping `intent show` displays it to a CISO as
// author-signed. With NO --bundle, the tool has only the untrusted registry view,
// so the scope MUST print registry-reported / UNVERIFIED — never AUTHORITATIVE /
// author-signature-covered.
func TestIntentShow_MaliciousRegistryScopeIsUnverified(t *testing.T) {
	evil := map[string]any{
		"id":     "ds:secrets/keychain",
		"kind":   "secrets_store",
		"access": "read",
		"scope":  "keychain://*",
		"reason": "smuggled by a malicious registry",
	}
	meta := registry.BundleMeta{
		Bundle: map[string]any{
			"bundle_digest":     "sha256:" + strings.Repeat("ab", 32),
			"status":            "admitted",
			"data_dependencies": []any{evil}, // mutable row
		},
		CurrentGovernance: "yellow",
		Manifest: map[string]any{ // untrusted parsed-manifest copy
			"data_dependencies": []any{evil},
		},
	}
	srv := metaServer(t, meta)
	defer srv.Close()

	for _, asJSON := range []bool{false, true} {
		var stdout, stderr bytes.Buffer
		args := []string{"@sha256:" + strings.Repeat("ab", 32), "--registry", srv.URL}
		if asJSON {
			args = append(args, "--json")
		}
		code := runIntentShow(args, &stdout, &stderr)
		if code != exitOK {
			t.Fatalf("intent show exit=%d, stderr=%s", code, stderr.String())
		}
		out := stdout.String()
		// The smuggled scope IS surfaced (transparency) ...
		if !strings.Contains(out, "keychain://*") {
			t.Errorf("(json=%v) expected the registry scope to be surfaced, got:\n%s", asJSON, out)
		}
		if asJSON {
			// In JSON the security claim is the STRUCTURED verdict, not text: the
			// authoritative declaration must be registry-reported, not signed, and
			// the signed-manifest source must be empty (nothing digest-verified).
			var got map[string]any
			if err := json.Unmarshal([]byte(out), &got); err != nil {
				t.Fatalf("intent show --json not valid JSON: %v\n%s", err, out)
			}
			if got["declaration_provenance"] != provRegistryReported {
				t.Errorf("declaration_provenance = %v, want registry-reported", got["declaration_provenance"])
			}
			if got["authoritative"] != false {
				t.Errorf("authoritative = %v, want false", got["authoritative"])
			}
			sources, _ := got["sources"].(map[string]any)
			signed, _ := sources[provSignedManifest].(map[string]any)
			if signed == nil || signed["data_dependencies"] != nil {
				t.Errorf("signed-manifest source must be empty (no digest-verified scope): %+v", sources[provSignedManifest])
			}
		} else {
			// In the human-readable view the smuggled scope must NEVER be labeled
			// AUTHORITATIVE / author-signature-covered.
			if strings.Contains(out, "AUTHORITATIVE") || strings.Contains(out, "author-signature-covered") {
				t.Errorf("UNSIGNED registry scope shown as AUTHORITATIVE:\n%s", out)
			}
			if !strings.Contains(out, "registry-reported (UNVERIFIED") {
				t.Errorf("expected registry-reported/UNVERIFIED provenance line, got:\n%s", out)
			}
		}
	}
}

// TestIntentShow_BundleRowOnlyIsAdvisory: a scope present only on the mutable row
// (no signed scope) is advisory, never author-signed.
func TestIntentShow_BundleRowOnlyIsAdvisory(t *testing.T) {
	meta := registry.BundleMeta{
		Bundle: map[string]any{
			"bundle_digest": "sha256:" + strings.Repeat("cd", 32),
			"status":        "admitted",
			"data_dependencies": []any{
				map[string]any{"id": "ds:er1/x", "kind": "er1_collection", "access": "read"},
			},
		},
		CurrentGovernance: "yellow",
		Manifest:          map[string]any{}, // no registry-manifest scope
	}
	srv := metaServer(t, meta)
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := runIntentShow([]string{"@sha256:" + strings.Repeat("cd", 32), "--registry", srv.URL}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("intent show exit=%d, stderr=%s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "bundle-row (ADVISORY") {
		t.Errorf("expected bundle-row provenance line, got:\n%s", out)
	}
	if strings.Contains(out, "AUTHORITATIVE") {
		t.Errorf("bundle-row scope must NOT be reported as author-signed, got:\n%s", out)
	}
}

// packIntentBundle packs a real .skb whose signed bundle.json carries the given
// data_dependencies and returns (path, "sha256:hex").
func packIntentBundle(t *testing.T, deps []skillbundle.DataDependency) (string, string) {
	t.Helper()
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "SKILL.md"), []byte("---\nname: t\n---\n# t\n"), 0o644); err != nil {
		t.Fatalf("write SKILL.md: %v", err)
	}
	out := filepath.Join(t.TempDir(), "scoped.skb")
	m := skillbundle.BundleManifest{
		Name:                   "scoped",
		Version:                "1.0.0",
		AuthorGovernanceIntent: "yellow",
		DataDependencies:       deps,
	}
	if _, err := skillbundle.Pack(src, out, skillbundle.PackOptions{Manifest: m, BuiltBy: "skillctl/test"}); err != nil {
		t.Fatalf("pack: %v", err)
	}
	blob, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read packed: %v", err)
	}
	d := sha256.Sum256(blob)
	return out, "sha256:" + hex.EncodeToString(d[:])
}

// signedIntentFixture is a fully-wired `intent show --bundle` scenario on disk:
// a real packed .skb carrying a typed data-scope, signed by an author key whose
// pubkey is PINNED in trust-roots, with a BundleMeta (served by an httptest
// registry) carrying the author + registry signature rows. This is the (b)
// scenario the re-challenge requires — and the substrate the Attack-d test
// perturbs by swapping in an attacker-signed bundle the pinned author never
// signed.
type signedIntentFixture struct {
	bundlePath string
	digest     string // "sha256:<hex>"
	authorID   string
	regURL     string
	trPath     string
	authorPriv ed25519.PrivateKey
	regPriv    ed25519.PrivateKey
	srv        *httptest.Server
}

// buildSignedIntentFixture packs+signs a scoped bundle and stands up a registry
// that advertises its digest + signatures. The trust-roots pin the author key, so
// verify.Verify can validate the author signature fully offline (pinned mode).
func buildSignedIntentFixture(t *testing.T, deps []skillbundle.DataDependency) signedIntentFixture {
	t.Helper()
	bundlePath, digest := packIntentBundle(t, deps)

	authorPub, authorPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("author keygen: %v", err)
	}
	regPub, regPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("reg keygen: %v", err)
	}
	authorID := "id:kamir@m3c"

	dRaw := digestRaw(t, digest)
	meta := registry.BundleMeta{
		Bundle: map[string]any{
			"bundle_digest": digest,
			"name":          "scoped",
			"version":       "1.0.0",
			"status":        "admitted",
		},
		Signatures: []registry.SignatureRow{
			{Role: "author", IdentityID: authorID, SignatureB64: signB64(authorPriv, dRaw), Status: "active"},
			{Role: "registry", IdentityID: "id:registry@aims-core", SignatureB64: signB64(regPriv, dRaw), Status: "active"},
		},
		CurrentGovernance: "green",
		Manifest:          map[string]any{},
	}
	srv := metaServer(t, meta)
	t.Cleanup(srv.Close)

	// The trust-root is matched by the live --registry URL, so it MUST pin the
	// httptest server URL (known only after the server starts).
	trPath := filepath.Join(t.TempDir(), "trust-roots.pinned.yaml")
	writePinnedTrustRoots(t, trPath, srv.URL,
		base64.StdEncoding.EncodeToString(regPub),
		authorID, base64.StdEncoding.EncodeToString(authorPub))

	return signedIntentFixture{
		bundlePath: bundlePath, digest: digest, authorID: authorID, regURL: srv.URL,
		trPath: trPath, authorPriv: authorPriv, regPriv: regPriv, srv: srv,
	}
}

// digestRaw decodes a "sha256:<hex>" digest back to its 32 raw bytes for signing.
func digestRaw(t *testing.T, digest string) [32]byte {
	t.Helper()
	hexPart := strings.TrimPrefix(digest, "sha256:")
	raw, err := hex.DecodeString(hexPart)
	if err != nil || len(raw) != 32 {
		t.Fatalf("bad digest %q: %v", digest, err)
	}
	var out [32]byte
	copy(out[:], raw)
	return out
}

// servePinnedMeta restands a registry that serves a custom BundleMeta but reuses
// the fixture's registry URL pin (so the trust-root still matches). Used by
// Attack-d to swap in attacker signatures while keeping the same --registry pin.
func servePinnedMeta(t *testing.T, meta registry.BundleMeta) *httptest.Server {
	t.Helper()
	srv := metaServer(t, meta)
	t.Cleanup(srv.Close)
	return srv
}

// TestIntentShow_PinnedAuthorSignedBundleIsAuthoritative (re-challenge scenario b):
// a genuinely author-signed bundle whose author key IS pinned in trust-roots is
// shown as signed-manifest / AUTHORITATIVE — and ONLY because the author signature
// verified, not because a digest happened to match.
func TestIntentShow_PinnedAuthorSignedBundleIsAuthoritative(t *testing.T) {
	deps := []skillbundle.DataDependency{
		{ID: "ds:fs/cwd", Kind: "local_fs", Access: "read", Scope: "<cwd>/decks/**", Reason: "read decks"},
	}
	f := buildSignedIntentFixture(t, deps)

	for _, asJSON := range []bool{false, true} {
		var stdout, stderr bytes.Buffer
		args := []string{"@" + f.digest, "--registry", f.srv.URL, "--bundle", f.bundlePath, "--trust-roots", f.trPath}
		if asJSON {
			args = append(args, "--json")
		}
		code := runIntentShow(args, &stdout, &stderr)
		if code != exitOK {
			t.Fatalf("(json=%v) intent show exit=%d, stderr=%s", asJSON, code, stderr.String())
		}
		out := stdout.String()
		if !strings.Contains(out, "ds:fs/cwd") {
			t.Errorf("(json=%v) expected the signed scope printed, got:\n%s", asJSON, out)
		}
		if asJSON {
			var got map[string]any
			if err := json.Unmarshal([]byte(out), &got); err != nil {
				t.Fatalf("not JSON: %v\n%s", err, out)
			}
			if got["authoritative"] != true {
				t.Errorf("authoritative=%v, want true (author sig pinned+verified)", got["authoritative"])
			}
			if got["declaration_provenance"] != provSignedManifest {
				t.Errorf("declaration_provenance=%v, want signed-manifest", got["declaration_provenance"])
			}
		} else if !strings.Contains(out, "signed-manifest (AUTHORITATIVE") {
			t.Errorf("pinned-author-signed scope must be AUTHORITATIVE, got:\n%s", out)
		}
	}
}

// TestIntentShow_AttackD_MaliciousRegistryUnsignedBundle (re-challenge scenario a,
// the MERGE-BLOCKER): an attacker packs their OWN .skb (carrying a scope the pinned
// author never signed) and a malicious registry advertises ITS digest — but there
// is NO valid pinned-author signature over those bytes. `intent show --bundle` must
// print digest-matched / UNVERIFIED, authoritative:false, and NEVER
// author-signature-covered / AUTHORITATIVE.
func TestIntentShow_AttackD_MaliciousRegistryUnsignedBundle(t *testing.T) {
	// The attacker's bundle carries a scope a CISO would refuse if it looked signed.
	evil := []skillbundle.DataDependency{
		{ID: "ds:secrets/keychain", Kind: "secrets_store", Access: "read", Scope: "keychain://*", Reason: "smuggled scope"},
	}
	attackerBundle, attackerDigest := packIntentBundle(t, evil)

	// A legitimate pinned-author trust-root exists, but the attacker bundle was
	// NOT signed by that author. The malicious registry advertises the attacker's
	// digest and stuffs an ATTACKER-signed author row (a key the trust-root does
	// NOT pin) hoping it passes for author-signed.
	authorPub, _, _ := ed25519.GenerateKey(rand.Reader)    // pinned author (never signed the attacker bundle)
	_, attackerPriv, _ := ed25519.GenerateKey(rand.Reader) // attacker key (not pinned)
	regPub, regPriv, _ := ed25519.GenerateKey(rand.Reader) // registry key (pinned, so the chain reaches author)
	authorID := "id:kamir@m3c"
	dRaw := digestRaw(t, attackerDigest)

	meta := registry.BundleMeta{
		Bundle: map[string]any{
			"bundle_digest": attackerDigest, // registry advertises ITS bundle's digest
			"status":        "admitted",
		},
		Signatures: []registry.SignatureRow{
			// Author row signed by the ATTACKER key, claiming the pinned author's id.
			{Role: "author", IdentityID: authorID, SignatureB64: signB64(attackerPriv, dRaw), Status: "active"},
			{Role: "registry", IdentityID: "id:registry@aims-core", SignatureB64: signB64(regPriv, dRaw), Status: "active"},
		},
		CurrentGovernance: "green",
		Manifest: map[string]any{
			"data_dependencies": []any{map[string]any{
				"id": "ds:secrets/keychain", "kind": "secrets_store", "access": "read", "scope": "keychain://*",
			}},
		},
	}
	srv := servePinnedMeta(t, meta)

	// Pin the live server URL so the trust-root matches the --registry passed below.
	trPath := filepath.Join(t.TempDir(), "trust-roots.pinned.yaml")
	writePinnedTrustRoots(t, trPath, srv.URL,
		base64.StdEncoding.EncodeToString(regPub),
		authorID, base64.StdEncoding.EncodeToString(authorPub))

	for _, asJSON := range []bool{false, true} {
		var stdout, stderr bytes.Buffer
		args := []string{"@" + attackerDigest, "--registry", srv.URL, "--bundle", attackerBundle, "--trust-roots", trPath}
		if asJSON {
			args = append(args, "--json")
		}
		code := runIntentShow(args, &stdout, &stderr)
		if code != exitOK {
			t.Fatalf("(json=%v) intent show exit=%d, stderr=%s", asJSON, code, stderr.String())
		}
		out := stdout.String()
		if asJSON {
			var got map[string]any
			if err := json.Unmarshal([]byte(out), &got); err != nil {
				t.Fatalf("not JSON: %v\n%s", err, out)
			}
			if got["authoritative"] != false {
				t.Errorf("Attack-d: authoritative=%v, want false (no valid pinned-author signature)", got["authoritative"])
			}
			if got["declaration_provenance"] == provSignedManifest {
				t.Errorf("Attack-d: declaration_provenance must NOT be signed-manifest")
			}
			sources, _ := got["sources"].(map[string]any)
			signed, _ := sources[provSignedManifest].(map[string]any)
			if signed == nil || signed["data_dependencies"] != nil {
				t.Errorf("Attack-d: signed-manifest source must be EMPTY (author sig not verified): %+v", signed)
			}
		} else {
			if strings.Contains(out, "AUTHORITATIVE") || strings.Contains(out, "author-signature-covered") {
				t.Errorf("Attack-d: attacker bundle shown as AUTHORITATIVE:\n%s", out)
			}
			if !strings.Contains(out, "digest-matched (author signature NOT verified") {
				t.Errorf("Attack-d: expected digest-matched/UNVERIFIED label, got:\n%s", out)
			}
		}
	}
}

// TestIntentShow_AttackD_NoTrustRootsIsUnverified (re-challenge scenario d): an
// honest @sha256 out-of-band digest pin WITHOUT trust-roots configured is NOT
// author-signature verification — it is a user-asserted digest. Without a pinned
// author key the scope must be digest-matched / UNVERIFIED, never
// author-signature-covered.
func TestIntentShow_AttackD_NoTrustRootsIsUnverified(t *testing.T) {
	// Point HOME at an empty dir so the DEFAULT trust-roots path does not exist.
	t.Setenv("HOME", t.TempDir())

	deps := []skillbundle.DataDependency{
		{ID: "ds:fs/cwd", Kind: "local_fs", Access: "read", Scope: "<cwd>/decks/**", Reason: "read decks"},
	}
	bundlePath, digest := packIntentBundle(t, deps)
	meta := registry.BundleMeta{
		Bundle: map[string]any{
			"bundle_digest": digest, // honest registry, real digest
			"status":        "admitted",
		},
		CurrentGovernance: "yellow",
		Manifest:          map[string]any{},
	}
	srv := servePinnedMeta(t, meta)

	var stdout, stderr bytes.Buffer
	// No --trust-roots flag → default path (under the empty HOME) → none configured.
	code := runIntentShow([]string{"@" + digest, "--registry", srv.URL, "--bundle", bundlePath}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("intent show exit=%d, stderr=%s", code, stderr.String())
	}
	out := stdout.String()
	if strings.Contains(out, "AUTHORITATIVE") || strings.Contains(out, "author-signature-covered") {
		t.Errorf("no trust-roots: out-of-band digest pin must NOT be author-signature-covered:\n%s", out)
	}
	if !strings.Contains(out, "digest-matched (author signature NOT verified") {
		t.Errorf("no trust-roots: expected digest-matched/UNVERIFIED label, got:\n%s", out)
	}
	if !strings.Contains(stderr.String(), "trust-roots not usable") {
		t.Errorf("expected an actionable trust-roots reason on stderr, got:\n%s", stderr.String())
	}
}

// TestIntentShow_AttackD_DigestMismatchNotAuthoritative (re-challenge scenario c):
// a --bundle whose digest does NOT match the registry-advertised digest (the
// adversary swapped bytes after signing) fails closed — the swapped scope is NEVER
// shown as authoritative; only the UNVERIFIED registry view stands.
func TestIntentShow_AttackD_DigestMismatchNotAuthoritative(t *testing.T) {
	deps := []skillbundle.DataDependency{
		{ID: "ds:fs/cwd", Kind: "local_fs", Access: "read", Scope: "<cwd>/decks/**", Reason: "read decks"},
	}
	f := buildSignedIntentFixture(t, deps)

	// Append a byte to the .skb AFTER the meta was signed → digest mismatch.
	skb, _ := os.ReadFile(f.bundlePath)
	if err := os.WriteFile(f.bundlePath, append(skb, 'X'), 0o644); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := runIntentShow([]string{"@" + f.digest, "--registry", f.srv.URL, "--bundle", f.bundlePath, "--trust-roots", f.trPath}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("intent show exit=%d, stderr=%s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "AUTHORITATIVE") {
		t.Errorf("a digest-mismatched bundle must NOT be shown as authoritative:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "did not digest-match") {
		t.Errorf("expected a digest-match failure note, got stderr:\n%s", stderr.String())
	}
}
