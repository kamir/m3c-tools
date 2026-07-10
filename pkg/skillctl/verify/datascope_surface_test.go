package verify

// SPEC-0196 §12 Q1 / P2b — the verifier surfaces declared data-scope WITH
// provenance: a scope read from the author-signed bundle.json INSIDE the
// digest-verified .skb is "signed-manifest" (authoritative); a scope on the
// mutable post-admit registry row is "bundle-row" (advisory). These tests prove
// the verifier distinguishes the two and that a bundle-row scope can NEVER
// masquerade as signed-manifest.

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

// packBundleWithScope packs a real .skb whose signed bundle.json carries the
// given data_dependencies, and returns (path, rawDigest, "sha256:hex").
func packBundleWithScope(t *testing.T, deps []skillbundle.DataDependency, intent *skillbundle.Intent) (string, [32]byte, string) {
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
		Intent:                 intent,
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
	return out, d, "sha256:" + hexLower(d[:])
}

// scopedOpts wires a complete pinned-mode VerifyOpts around a real packed .skb,
// optionally seeding a bundle-row scope on meta.Bundle.
func scopedOpts(t *testing.T, signedDeps []skillbundle.DataDependency, intent *skillbundle.Intent, bundleRowDeps []any) VerifyOpts {
	t.Helper()
	authorKey := mustKeypair(t)
	regKey := mustKeypair(t)
	bundlePath, digestRaw, digestStr := packBundleWithScope(t, signedDeps, intent)
	authorSig := signOver(t, authorKey.priv, digestRaw)
	regSig := signOver(t, regKey.priv, digestRaw)
	authorID := "id:author@m3c"

	meta := &registry.BundleMeta{
		Bundle: map[string]any{
			"bundle_digest": digestStr,
			"name":          "scoped",
			"version":       "1.0.0",
			"status":        "admitted",
		},
		Signatures: []registry.SignatureRow{
			{Role: "author", IdentityID: authorID, SignatureB64: authorSig, Status: "active"},
			{Role: "registry", IdentityID: "id:registry@aims-core", SignatureB64: regSig, Status: "active"},
		},
		Manifest:          map[string]any{"depends_on": []any{}},
		CurrentGovernance: "yellow",
		Attestations: []registry.AttestationRow{
			{Level: "yellow", ReviewerID: "id:reviewer@m3c", AttestedAt: "2026-05-05T20:00:00Z"},
		},
	}
	if bundleRowDeps != nil {
		meta.Bundle["data_dependencies"] = bundleRowDeps
	}

	return VerifyOpts{
		BundlePath: bundlePath,
		BundleMeta: meta,
		TrustRoot:  goodTrustRoot(t, regKey.pub, "yellow"),
		IdentityFetcher: &fakeFetcher{identities: map[string]*registry.Identity{
			authorID: {ID: authorID, PubkeyB64: authorKey.b64, AuthSource: "manual"},
		}},
	}
}

// TestVerify_SurfacesSignedManifestScope: a pack-time scope is surfaced with
// signed-manifest provenance.
func TestVerify_SurfacesSignedManifestScope(t *testing.T) {
	deps := []skillbundle.DataDependency{
		{ID: "ds:fs/cwd", Kind: "local_fs", Access: "write", Scope: "<cwd>/decks/**", Reason: "write decks"},
	}
	opts := scopedOpts(t, deps, &skillbundle.Intent{Destructive: true, SideEffects: []string{"fs:write"}}, nil)

	res, err := Verify(opts)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(res.DataScopes) != 1 {
		t.Fatalf("want 1 surfaced scope, got %d", len(res.DataScopes))
	}
	s := res.DataScopes[0]
	if s.Provenance != ScopeProvenanceSignedManifest {
		t.Fatalf("want signed-manifest provenance, got %q", s.Provenance)
	}
	if id, _ := s.Raw["id"].(string); id != "ds:fs/cwd" {
		t.Errorf("scope id not surfaced: %+v", s.Raw)
	}
	if scope, _ := s.Raw["scope"].(string); scope != "<cwd>/decks/**" {
		t.Errorf("scope specifier not surfaced: %+v", s.Raw)
	}
}

// TestVerify_SurfacesBundleRowScope: a PATCH-only scope (present only on the
// registry row, NOT in the signed manifest) is surfaced as bundle-row.
func TestVerify_SurfacesBundleRowScope(t *testing.T) {
	// Signed manifest carries NO scope; only the mutable registry row does.
	bundleRow := []any{
		map[string]any{"id": "ds:er1/x", "kind": "er1_collection", "access": "read", "reason": "post-admit declare"},
	}
	opts := scopedOpts(t, nil, nil, bundleRow)

	res, err := Verify(opts)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(res.DataScopes) != 1 {
		t.Fatalf("want 1 surfaced scope, got %d", len(res.DataScopes))
	}
	s := res.DataScopes[0]
	if s.Provenance != ScopeProvenanceBundleRow {
		t.Fatalf("want bundle-row provenance, got %q", s.Provenance)
	}
	if id, _ := s.Raw["id"].(string); id != "ds:er1/x" {
		t.Errorf("bundle-row scope id not surfaced: %+v", s.Raw)
	}
}

// TestVerify_BundleRowCannotMasqueradeAsSigned: the red-team scenario — a
// bundle-row scope that DIFFERS from the (absent) signed manifest must NOT be
// reported as signed-manifest. The signed-manifest provenance is reserved for
// scope read from the digest-verified .skb; a registry that injects a scope into
// meta.Manifest (the untrusted parsed copy) cannot get it past the verifier as
// author-bound.
func TestVerify_BundleRowCannotMasqueradeAsSigned(t *testing.T) {
	bundleRow := []any{
		map[string]any{"id": "ds:evil", "kind": "local_fs", "access": "write", "scope": "<cwd>/**", "reason": "smuggled"},
	}
	opts := scopedOpts(t, nil, nil, bundleRow)
	// Adversary also stuffs the SAME scope into the untrusted parsed manifest
	// copy, hoping the verifier reads scope from there and labels it signed.
	opts.BundleMeta.Manifest["data_dependencies"] = bundleRow

	res, err := Verify(opts)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	for _, s := range res.DataScopes {
		if s.Provenance == ScopeProvenanceSignedManifest {
			t.Fatalf("a non-signed scope was reported as signed-manifest: %+v", s.Raw)
		}
	}
	// And it IS still surfaced — as the advisory bundle-row it really is.
	if len(res.DataScopes) != 1 || res.DataScopes[0].Provenance != ScopeProvenanceBundleRow {
		t.Fatalf("want exactly one bundle-row scope, got %+v", res.DataScopes)
	}
}

// TestVerify_NoScopeUnchanged: a bundle with no declared scope surfaces none —
// back-compat (an old bundle verifies exactly as before, DataScopes empty).
func TestVerify_NoScopeUnchanged(t *testing.T) {
	opts := scopedOpts(t, nil, nil, nil)
	res, err := Verify(opts)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(res.DataScopes) != 0 {
		t.Fatalf("want no surfaced scope, got %d: %+v", len(res.DataScopes), res.DataScopes)
	}
}

// TestVerify_BothScopesSurfacedSignedFirst: when BOTH a signed-manifest scope
// and a bundle-row scope exist, both surface and the authoritative
// signed-manifest one is listed first.
func TestVerify_BothScopesSurfacedSignedFirst(t *testing.T) {
	signed := []skillbundle.DataDependency{
		{ID: "ds:signed", Kind: "er1_collection", Access: "read", Reason: "author-bound"},
	}
	bundleRow := []any{
		map[string]any{"id": "ds:row", "kind": "er1_collection", "access": "read", "reason": "post-admit"},
	}
	opts := scopedOpts(t, signed, nil, bundleRow)

	res, err := Verify(opts)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(res.DataScopes) != 2 {
		t.Fatalf("want 2 surfaced scopes, got %d", len(res.DataScopes))
	}
	if res.DataScopes[0].Provenance != ScopeProvenanceSignedManifest {
		t.Errorf("authoritative signed-manifest scope must be listed first, got %q", res.DataScopes[0].Provenance)
	}
	if res.DataScopes[1].Provenance != ScopeProvenanceBundleRow {
		t.Errorf("second entry should be bundle-row, got %q", res.DataScopes[1].Provenance)
	}
}
