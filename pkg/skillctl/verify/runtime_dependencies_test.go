package verify

import (
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

func runtimeAssessmentFixture(t *testing.T, deps []skillbundle.Dependency) VerifyOpts {
	t.Helper()
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "SKILL.md"), []byte("# synthetic runtime assessment\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "runtime.skb")
	_, err := skillbundle.Pack(src, path, skillbundle.PackOptions{Manifest: skillbundle.BundleManifest{Name: "synthetic-runtime", Version: "1.0.0", DependsOn: deps}})
	if err != nil {
		t.Fatal(err)
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw := sha256.Sum256(blob)
	digest := "sha256:" + hexLower(raw[:])
	author, reg := mustKeypair(t), mustKeypair(t)
	const authorID = "id:bob@example"
	return VerifyOpts{BundlePath: path, BundleMeta: goodMeta(digest, authorID, signOver(t, author.priv, raw), signOver(t, reg.priv, raw), "green"), TrustRoot: goodTrustRoot(t, reg.pub, "green"), IdentityFetcher: &fakeFetcher{identities: map[string]*registry.Identity{authorID: {ID: authorID, PubkeyB64: author.b64, AuthSource: "manual"}}}}
}

func TestRuntimeAssessmentBoundManifestIgnoresUnsignedProjection(t *testing.T) {
	manifestReaderHome(t)
	for _, signedHasDeps := range []bool{false, true} {
		name := "signed-none-unsigned-dependency"
		var deps []skillbundle.Dependency
		want := skillbundle.RuntimeDependenciesNone
		if signedHasDeps {
			name = "signed-dependency-unsigned-none"
			deps = []skillbundle.Dependency{{Kind: "python", Name: "synthetic-missing", Constraint: ">=999"}}
			want = skillbundle.RuntimeDependenciesUnresolved
		}
		t.Run(name, func(t *testing.T) {
			opts := runtimeAssessmentFixture(t, deps)
			if signedHasDeps {
				opts.BundleMeta.Manifest = map[string]any{"depends_on": []any{}}
			} else {
				opts.BundleMeta.Manifest = map[string]any{"depends_on": []any{map[string]any{"kind": "system", "name": "unsigned-decoy"}}}
			}
			verified, err := Verify(opts)
			if err != nil {
				t.Fatalf("actual signature verification failed: %v", err)
			}
			got, err := AssessBundleRuntimeDependencies(opts.BundlePath, verified.Digest)
			if err != nil || got.Status != want || got.Source != "digest_bound_manifest" || got.Digest != verified.Digest || got.Scope != "runtime_dependencies" {
				t.Fatalf("signed declaration replaced by metadata: %+v %v", got, err)
			}
			if signedHasDeps && (len(got.Declarations) != 1 || got.Declarations[0].Name != "synthetic-missing") {
				t.Fatalf("signed declarations not preserved: %+v", got)
			}
		})
	}
}

func TestRuntimeAssessmentBindingErrors(t *testing.T) {
	manifestReaderHome(t)
	opts := runtimeAssessmentFixture(t, nil)
	verified, err := Verify(opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, digest := range []string{"", "sha256:invalid", "sha256:" + strings.Repeat("0", 64)} {
		got, err := AssessBundleRuntimeDependencies(opts.BundlePath, digest)
		if got != nil || !errors.Is(err, ErrDigestMismatch) {
			t.Fatalf("missing/wrong binding accepted: %+v %v", got, err)
		}
	}
	if got, err := AssessBundleRuntimeDependencies(filepath.Join(t.TempDir(), "missing.skb"), verified.Digest); got != nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("IO failure lost or turned into none: %v", err)
	}
	if err := os.WriteFile(opts.BundlePath, []byte("substituted bundle"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := AssessBundleRuntimeDependencies(opts.BundlePath, verified.Digest); got != nil || !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("swapped bundle accepted: %v", err)
	}
}

func TestRuntimeAssessmentInvalidBoundDeclarations(t *testing.T) {
	manifestReaderHome(t)
	for _, tc := range []struct {
		raw         string
		readerError bool
	}{
		{`{"depends_on":[{"kind":"unknown","name":"x"}]}`, false},
		{`{"depends_on":[{"kind":"skill","name":1}]}`, false},
		{`{"depends_on":{},"data_dependencies":[]}`, false},
		{`{"depends_on":[],"depends_on":[{"kind":"skill","name":"x"}]}`, true},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			blob, digest := manifestReaderArchive(t, []string{"bundle.json"}, tc.raw)
			path := filepath.Join(t.TempDir(), "runtime.skb")
			if err := os.WriteFile(path, blob, 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := AssessBundleRuntimeDependencies(path, digest)
			if tc.readerError {
				if err == nil || got != nil {
					t.Fatal("duplicate keys became a declaration assessment")
				}
			} else if err != nil || got.Status != skillbundle.RuntimeDependenciesInvalid {
				t.Fatalf("invalid declaration accepted: %+v %v", got, err)
			}
		})
	}
}

func TestRuntimeAssessmentBoundManifestCaseAliases(t *testing.T) {
	manifestReaderHome(t)
	for _, raw := range []string{
		`{"Depends_On":[{"kind":"skill","name":"synthetic"}]}`,
		`{"depends_on":[],"Depends_On":[{"kind":"skill","name":"synthetic"}]}`,
		`{"PACKAGE_DEPENDENCIES":[],"depends_on":[]}`,
		`{"depends_on":[{"kind":"skill","Kind":"python","name":"synthetic"}]}`,
		`{"depends_on":[{"Kind":"skill","name":"synthetic"}]}`,
		`{"depends_on":[{"kind":"skill","name":"decoy","Name":"synthetic"}]}`,
		`{"depends_on":[{"kind":"python","name":"synthetic","constraint":"","Constraint":">=999"}]}`,
	} {
		t.Run(raw, func(t *testing.T) {
			blob, digest := manifestReaderArchive(t, []string{"bundle.json"}, raw)
			path := filepath.Join(t.TempDir(), "case-alias.skb")
			if err := os.WriteFile(path, blob, 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := AssessBundleRuntimeDependencies(path, digest)
			if err != nil || got.Status != skillbundle.RuntimeDependenciesInvalid || got.Source != "digest_bound_manifest" {
				t.Fatalf("bound case alias became no dependencies: %+v %v", got, err)
			}
		})
	}
}
