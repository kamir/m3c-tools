package verify

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

func manifestReaderHome(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("M3C_TOKEN_STORE", "file")
	t.Setenv("M3C_TEST_KEYCHAIN", "0")
}

func manifestReaderArchive(t *testing.T, names []string, manifest string) ([]byte, string) {
	t.Helper()
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	for _, name := range names {
		header := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(manifest))}
		if strings.HasSuffix(name, "/") {
			header.Typeflag, header.Size = tar.TypeDir, 0
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Typeflag != tar.TypeDir {
			if _, err := io.WriteString(tw, manifest); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	blob := out.Bytes()
	digest := sha256.Sum256(blob)
	return blob, "sha256:" + hexLower(digest[:])
}

func TestBoundManifestJSON(t *testing.T) {
	manifestReaderHome(t)
	for _, tc := range []struct {
		name, raw string
		valid     bool
	}{
		{"valid", `{"name":"synthetic","depends_on":[],"n":1,"extension":{"n":2},"items":[{"name":"a"},{"name":"b"}]}`, true},
		{"null-dependencies", `{"depends_on":null}`, true},
		{"escaped-distinct", `{"a":1,"\u0062":2}`, true},
		{"duplicate-root", `{"depends_on":[{"kind":"skill","name":"x"}],"depends_on":[]}`, false},
		{"duplicate-equal", `{"name":"x","name":"x"}`, false},
		{"escaped-alias", `{"name":"x","\u006eame":"y"}`, false},
		{"surrogate-alias", `{"😀":1,"\ud83d\ude00":2}`, false},
		{"nested", `{"policy":{"enabled":true,"enabled":false}}`, false},
		{"array-object", `{"depends_on":[{"kind":"skill","name":"x","name":"y"}]}`, false},
		{"nested-array", `{"x":[[{"a":1,"a":2}]]}`, false},
		{"root-null", `null`, false},
		{"root-array", `[]`, false},
		{"root-scalar", `"name"`, false},
		{"trailing-object", `{} {}`, false},
		{"trailing-invalid", `{} x`, false},
		{"truncated", `{"a":`, false},
		{"empty", ``, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			blob, digest := manifestReaderArchive(t, []string{"bundle.json"}, tc.raw)
			got, err := readDigestVerifiedManifest(bytes.NewReader(blob), digest, registry.MaxBlobSize)
			if tc.valid {
				if err != nil || got == nil {
					t.Fatalf("valid manifest rejected: %v", err)
				}
				if tc.name == "valid" {
					if got["n"] != float64(1) || got["extension"].(map[string]any)["n"] != float64(2) {
						t.Fatal("numeric or unknown-field compatibility changed")
					}
				}
			} else if err == nil || got != nil {
				t.Fatalf("ambiguous/invalid manifest accepted: %v", got)
			}
		})
	}
}

func TestBoundManifestArchiveSelection(t *testing.T) {
	manifestReaderHome(t)
	for _, tc := range []struct {
		name  string
		names []string
		valid bool
	}{
		{"flat", []string{"bundle.json"}, true},
		{"wrapped", []string{"synthetic/bundle.json"}, true},
		{"missing", []string{"other.json"}, false},
		{"directory", []string{"bundle.json/"}, false},
		{"duplicate", []string{"bundle.json", "bundle.json"}, false},
		{"wrapped-duplicate", []string{"synthetic/bundle.json", "synthetic/bundle.json"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			blob, digest := manifestReaderArchive(t, tc.names, `{"name":"synthetic"}`)
			got, err := readDigestVerifiedManifest(bytes.NewReader(blob), digest, registry.MaxBlobSize)
			if tc.valid && (err != nil || got["name"] != "synthetic") {
				t.Fatalf("valid manifest failed: %v", err)
			}
			if !tc.valid && (err == nil || got != nil) {
				t.Fatal("ambiguous or missing archive manifest accepted")
			}
		})
	}
}

func TestBoundManifestPackedDigest(t *testing.T) {
	manifestReaderHome(t)
	path, _, digest := packBundleWithScope(t, nil, nil)
	got, err := ReadDigestVerifiedManifest(path, digest)
	if err != nil || got["name"] != "scoped" {
		t.Fatalf("real packed bytes failed: %v", err)
	}
	for _, expected := range []string{"", "sha256:invalid", "sha256:" + strings.Repeat("0", 64)} {
		got, err := ReadDigestVerifiedManifest(path, expected)
		if got != nil || !errors.Is(err, ErrDigestMismatch) {
			t.Fatalf("invalid digest not rejected with identity: %v", err)
		}
	}
	if _, err := ReadDigestVerifiedManifest("", digest); err == nil {
		t.Fatal("empty path accepted")
	}
	if _, err := ReadDigestVerifiedManifest(filepath.Join(t.TempDir(), "missing.skb"), digest); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing-file cause lost: %v", err)
	}
}

type manifestFailReader struct{ err error }

func (r manifestFailReader) Read([]byte) (int, error) { return 0, r.err }

func TestBoundManifestReadFailureAndCaps(t *testing.T) {
	manifestReaderHome(t)
	blob, digest := manifestReaderArchive(t, []string{"bundle.json"}, `{"name":"synthetic"}`)
	for _, tc := range []struct {
		name  string
		limit int64
		valid bool
	}{
		{"at-cap", int64(len(blob)), true},
		{"cap-plus-one", int64(len(blob) - 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readDigestVerifiedManifest(bytes.NewReader(blob), digest, tc.limit)
			if tc.valid && (err != nil || got == nil) {
				t.Fatalf("at-cap archive rejected: %v", err)
			}
			if !tc.valid && (err == nil || got != nil || !strings.Contains(err.Error(), "exceeds")) {
				t.Fatalf("oversize archive accepted: %v", err)
			}
		})
	}
	sentinel := errors.New("synthetic read failure")
	reader := io.MultiReader(bytes.NewReader(blob[:len(blob)/2]), manifestFailReader{sentinel})
	got, err := readDigestVerifiedManifest(reader, digest, registry.MaxBlobSize)
	if got != nil || !errors.Is(err, sentinel) {
		t.Fatalf("partial read escaped or cause lost: %v", err)
	}
	emptyDigest := sha256.Sum256(nil)
	if got, err := readDigestVerifiedManifest(bytes.NewReader(nil), "sha256:"+hexLower(emptyDigest[:]), registry.MaxBlobSize); !errors.Is(err, ErrDigestMismatch) || got != nil {
		t.Fatalf("empty archive lost mismatch identity: %v", err)
	}
}

type manifestReplacingReader struct {
	*bytes.Reader
	path        string
	replacement []byte
	err         error
	replaced    bool
}

func (r *manifestReplacingReader) Read(p []byte) (int, error) {
	if !r.replaced {
		r.replaced = true
		r.err = os.WriteFile(r.path, r.replacement, 0o600)
		if r.err != nil {
			return 0, r.err
		}
	}
	return r.Reader.Read(p)
}

func TestBoundManifestUsesHashedSnapshot(t *testing.T) {
	manifestReaderHome(t)
	original, digest := manifestReaderArchive(t, []string{"bundle.json"}, `{"name":"original"}`)
	replacement, _ := manifestReaderArchive(t, []string{"bundle.json"}, `{"name":"replacement","data_dependencies":[{"id":"substituted"}]}`)
	path := filepath.Join(t.TempDir(), "bundle.skb")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	reader := &manifestReplacingReader{Reader: bytes.NewReader(original), path: path, replacement: replacement}
	got, err := readDigestVerifiedManifest(reader, digest, registry.MaxBlobSize)
	if err != nil || reader.err != nil || !reader.replaced || got["name"] != "original" {
		t.Fatalf("did not parse original hashed snapshot: %v", err)
	}
	if got, err := ReadDigestVerifiedManifest(path, digest); got != nil || !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("substituted path did not fail binding: %v", err)
	}
	meta := &registry.BundleMeta{}
	if scopes := collectDeclaredScopes(path, digest, meta, nil); len(scopes) != 0 {
		t.Fatal("substituted digest-mismatched manifest labeled signed")
	}
}

func TestBoundManifestDuplicateScopesStayAdvisory(t *testing.T) {
	manifestReaderHome(t)
	blob, digest := manifestReaderArchive(t, []string{"bundle.json"}, `{"data_dependencies":[{"id":"first"}],"data_dependencies":[{"id":"second"}]}`)
	path := filepath.Join(t.TempDir(), "bundle.skb")
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	meta := &registry.BundleMeta{Bundle: map[string]any{"data_dependencies": []any{map[string]any{"id": "unsigned"}}}}
	scopes := collectDeclaredScopes(path, digest, meta, nil)
	if len(scopes) != 1 || scopes[0].Provenance != ScopeProvenanceBundleRow || scopes[0].Raw["id"] != "unsigned" {
		t.Fatalf("ambiguous signed scope surfaced or advisory row lost: %+v", scopes)
	}
}

type manifestSwappingFetcher struct {
	delegate identityFetcher
	path     string
	blob     []byte
}

func (f manifestSwappingFetcher) GetIdentity(ctx context.Context, id string) (*registry.Identity, error) {
	if err := os.WriteFile(f.path, f.blob, 0o600); err != nil {
		return nil, err
	}
	return f.delegate.GetIdentity(ctx, id)
}

func TestBoundManifestVerifyScopeAfterPathSwap(t *testing.T) {
	manifestReaderHome(t)
	opts := scopedOpts(t, nil, nil, []any{map[string]any{"id": "unsigned"}})
	substitute, _ := manifestReaderArchive(t, []string{"bundle.json"}, `{"data_dependencies":[{"id":"substituted"}]}`)
	opts.IdentityFetcher = manifestSwappingFetcher{delegate: opts.IdentityFetcher, path: opts.BundlePath, blob: substitute}
	res, err := Verify(opts)
	if err != nil {
		t.Fatalf("advisory manifest failure changed existing chain verdict: %v", err)
	}
	if len(res.DataScopes) != 1 || res.DataScopes[0].Provenance != ScopeProvenanceBundleRow || res.DataScopes[0].Raw["id"] != "unsigned" {
		t.Fatalf("swapped bytes surfaced as signed scope or unsigned row lost: %+v", res.DataScopes)
	}
}
