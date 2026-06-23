package main

// SPEC-0196 §12 Q1 / P2b — `skillctl intent show` provenance.
//
// A CISO must see at a glance whether a declared scope is author-signed
// (signed-manifest, from the parsed bundle.json) or post-admit (bundle-row, the
// mutable `intent declare` PATCH target). These tests cover the provenance
// classifier (extractDeclaredView) and the end-to-end `intent show` rendering.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

func TestExtractDeclaredView_Provenance(t *testing.T) {
	signedDep := map[string]any{"id": "ds:signed", "kind": "er1_collection", "access": "read"}
	rowDep := map[string]any{"id": "ds:row", "kind": "local_fs", "access": "read"}

	t.Run("manifest only → signed-manifest authoritative", func(t *testing.T) {
		meta := &registry.BundleMeta{
			Manifest: map[string]any{"data_dependencies": []any{signedDep}},
		}
		v := extractDeclaredView(meta)
		if !v.hasSigned() || v.hasRow() {
			t.Fatalf("hasSigned=%v hasRow=%v", v.hasSigned(), v.hasRow())
		}
		_, deps, prov := v.authoritativeIntent()
		if prov != provSignedManifest {
			t.Errorf("provenance = %q, want signed-manifest", prov)
		}
		if len(deps) != 1 || deps[0]["id"] != "ds:signed" {
			t.Errorf("authoritative deps wrong: %+v", deps)
		}
	})

	t.Run("row only → bundle-row authoritative", func(t *testing.T) {
		meta := &registry.BundleMeta{
			Bundle: map[string]any{"data_dependencies": []any{rowDep}},
		}
		v := extractDeclaredView(meta)
		if v.hasSigned() || !v.hasRow() {
			t.Fatalf("hasSigned=%v hasRow=%v", v.hasSigned(), v.hasRow())
		}
		_, _, prov := v.authoritativeIntent()
		if prov != provBundleRow {
			t.Errorf("provenance = %q, want bundle-row", prov)
		}
	})

	t.Run("both → signed-manifest wins as authoritative", func(t *testing.T) {
		meta := &registry.BundleMeta{
			Manifest: map[string]any{"data_dependencies": []any{signedDep}},
			Bundle:   map[string]any{"data_dependencies": []any{rowDep}},
		}
		v := extractDeclaredView(meta)
		if !v.hasSigned() || !v.hasRow() {
			t.Fatalf("expected both present")
		}
		_, deps, prov := v.authoritativeIntent()
		if prov != provSignedManifest || deps[0]["id"] != "ds:signed" {
			t.Errorf("signed-manifest must win: prov=%q deps=%+v", prov, deps)
		}
	})

	t.Run("neither → empty", func(t *testing.T) {
		v := extractDeclaredView(&registry.BundleMeta{})
		if v.hasSigned() || v.hasRow() {
			t.Fatalf("expected nothing declared")
		}
		_, _, prov := v.authoritativeIntent()
		if prov != "" {
			t.Errorf("provenance = %q, want empty", prov)
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

// TestIntentShow_SignedManifestProvenance: a scope present in the parsed
// bundle.json is rendered as signed-manifest / AUTHORITATIVE.
func TestIntentShow_SignedManifestProvenance(t *testing.T) {
	meta := registry.BundleMeta{
		Bundle:            map[string]any{"bundle_digest": "sha256:abc", "status": "admitted"},
		CurrentGovernance: "yellow",
		Manifest: map[string]any{
			"data_dependencies": []any{
				map[string]any{"id": "ds:fs/cwd", "kind": "local_fs", "access": "write", "scope": "<cwd>/decks/**"},
			},
		},
	}
	srv := metaServer(t, meta)
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := runIntentShow([]string{"@sha256:abc", "--registry", srv.URL}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("intent show exit=%d, stderr=%s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "provenance: signed-manifest (AUTHORITATIVE") {
		t.Errorf("expected signed-manifest provenance line, got:\n%s", out)
	}
	if !strings.Contains(out, "ds:fs/cwd") {
		t.Errorf("expected the scope to be printed, got:\n%s", out)
	}
}

// TestIntentShow_BundleRowProvenance: a scope present ONLY on the mutable
// registry row is rendered as bundle-row / ADVISORY, never as author-signed.
func TestIntentShow_BundleRowProvenance(t *testing.T) {
	meta := registry.BundleMeta{
		Bundle: map[string]any{
			"bundle_digest": "sha256:abc",
			"status":        "admitted",
			"data_dependencies": []any{
				map[string]any{"id": "ds:er1/x", "kind": "er1_collection", "access": "read"},
			},
		},
		CurrentGovernance: "yellow",
		Manifest:          map[string]any{}, // no signed scope
	}
	srv := metaServer(t, meta)
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := runIntentShow([]string{"@sha256:abc", "--registry", srv.URL}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("intent show exit=%d, stderr=%s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "provenance: bundle-row (ADVISORY") {
		t.Errorf("expected bundle-row provenance line, got:\n%s", out)
	}
	if strings.Contains(out, "signed-manifest (AUTHORITATIVE") {
		t.Errorf("bundle-row scope must NOT be reported as author-signed, got:\n%s", out)
	}
}

// TestIntentShow_BothProvenancesShownSignedAuthoritative: when both exist, both
// are listed and the note flags signed-manifest as authoritative.
func TestIntentShow_BothProvenancesShown(t *testing.T) {
	meta := registry.BundleMeta{
		Bundle: map[string]any{
			"bundle_digest": "sha256:abc",
			"status":        "admitted",
			"data_dependencies": []any{
				map[string]any{"id": "ds:row", "kind": "er1_collection", "access": "read"},
			},
		},
		CurrentGovernance: "yellow",
		Manifest: map[string]any{
			"data_dependencies": []any{
				map[string]any{"id": "ds:signed", "kind": "er1_collection", "access": "read"},
			},
		},
	}
	srv := metaServer(t, meta)
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := runIntentShow([]string{"@sha256:abc", "--registry", srv.URL, "--json"}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("intent show exit=%d, stderr=%s", code, stderr.String())
	}
	var got map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("intent show --json not valid JSON: %v\n%s", err, stdout.String())
	}
	if got["declaration_provenance"] != provSignedManifest {
		t.Errorf("declaration_provenance = %v, want signed-manifest", got["declaration_provenance"])
	}
	sources, _ := got["sources"].(map[string]any)
	if sources == nil || sources[provSignedManifest] == nil || sources[provBundleRow] == nil {
		t.Errorf("both provenance sources must be present in --json: %+v", got["sources"])
	}
}
