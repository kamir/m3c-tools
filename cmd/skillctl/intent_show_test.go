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
	"crypto/sha256"
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

// TestIntentShow_DigestVerifiedBundleIsAuthoritative: when --bundle points at a
// .skb whose digest matches the registry-advertised digest, its signed scope is
// shown as signed-manifest / AUTHORITATIVE.
func TestIntentShow_DigestVerifiedBundleIsAuthoritative(t *testing.T) {
	deps := []skillbundle.DataDependency{
		{ID: "ds:fs/cwd", Kind: "local_fs", Access: "read", Scope: "<cwd>/decks/**", Reason: "read decks"},
	}
	bundlePath, digest := packIntentBundle(t, deps)

	meta := registry.BundleMeta{
		Bundle: map[string]any{
			"bundle_digest": digest, // honest registry advertises the real digest
			"status":        "admitted",
		},
		CurrentGovernance: "yellow",
		Manifest:          map[string]any{},
	}
	srv := metaServer(t, meta)
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := runIntentShow([]string{"@" + digest, "--registry", srv.URL, "--bundle", bundlePath}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("intent show exit=%d, stderr=%s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "signed-manifest (AUTHORITATIVE") {
		t.Errorf("digest-verified bundle scope must be AUTHORITATIVE, got:\n%s", out)
	}
	if !strings.Contains(out, "ds:fs/cwd") {
		t.Errorf("expected the signed scope to be printed, got:\n%s", out)
	}
}

// TestIntentShow_BundleDigestMismatchFailsClosed: a --bundle whose digest does NOT
// match the registry-advertised digest (the adversary swapped bytes) must fail
// closed — NOT silently show the tampered scope as authoritative.
func TestIntentShow_BundleDigestMismatchFailsClosed(t *testing.T) {
	deps := []skillbundle.DataDependency{
		{ID: "ds:fs/cwd", Kind: "local_fs", Access: "read", Scope: "<cwd>/decks/**", Reason: "read decks"},
	}
	bundlePath, _ := packIntentBundle(t, deps)

	// Registry advertises a DIFFERENT digest than the local .skb actually has.
	meta := registry.BundleMeta{
		Bundle: map[string]any{
			"bundle_digest": "sha256:" + strings.Repeat("ff", 32),
			"status":        "admitted",
		},
		CurrentGovernance: "yellow",
		Manifest:          map[string]any{},
	}
	srv := metaServer(t, meta)
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := runIntentShow([]string{"@sha256:" + strings.Repeat("ff", 32), "--registry", srv.URL, "--bundle", bundlePath}, &stdout, &stderr)
	if code == exitOK {
		t.Fatalf("digest mismatch must NOT exit 0; stdout=%s", stdout.String())
	}
	if strings.Contains(stdout.String(), "AUTHORITATIVE") {
		t.Errorf("a digest-mismatched bundle must NOT be shown as authoritative:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "did not digest-verify") {
		t.Errorf("expected a digest-verify failure message, got stderr:\n%s", stderr.String())
	}
}
