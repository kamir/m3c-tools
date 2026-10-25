package verify

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

func snapshotFixture(t *testing.T, manifest string) (VerifyOpts, []byte) {
	t.Helper()
	manifestReaderHome(t)
	blob, _ := manifestReaderArchive(t, []string{"bundle.json"}, manifest)
	return snapshotSignedOpts(t, blob), blob
}
func snapshotSignedOpts(t *testing.T, blob []byte) VerifyOpts {
	t.Helper()
	author, reg := mustKeypair(t), mustKeypair(t)
	digest := sha256.Sum256(blob)
	id := "id:snapshot-author@synthetic"
	meta := goodMeta("sha256:"+hexLower(digest[:]), id, signOver(t, author.priv, digest), signOver(t, reg.priv, digest), "green")
	return VerifyOpts{BundleMeta: meta, TrustRoot: pinnedTrustRoot(id, author.pub, reg.pub, "green"), Ctx: context.Background()}
}
func snapshotInflated(t *testing.T, blob []byte) int64 {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(gz)
	if err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return int64(len(raw))
}

type snapshotCallbackWriter struct {
	once     bool
	callback func()
}

func (w *snapshotCallbackWriter) Write(p []byte) (int, error) {
	if !w.once {
		w.once = true
		w.callback()
	}
	return len(p), nil
}

type snapshotScopeCancelWriter struct {
	cancel context.CancelFunc
	called bool
}

func (w *snapshotScopeCancelWriter) Write(p []byte) (int, error) {
	if strings.Contains(string(p), "datascope_ok") {
		w.called = true
		w.cancel()
	}
	return len(p), nil
}

func TestSnapshotSameBytesScopes(t *testing.T) {
	manifest := `{"name":"snapshot","version":"1.0.0","data_dependencies":[{"id":"signed-original","kind":"local_fs","access":"read","scope":"<cwd>/**"}]}`
	opts, blob := snapshotFixture(t, manifest)
	original := append([]byte{}, blob...)
	opts.BundleMeta.Bundle["data_dependencies"] = []any{map[string]any{"id": "unsigned-advisory"}}
	callback := &snapshotCallbackWriter{callback: func() { clear(blob) }}
	opts.Logger = callback
	got, err := VerifySnapshot(opts, blob, 1<<20)
	if err != nil || got == nil || got.Verification == nil {
		t.Fatalf("real signed snapshot failed: %v", err)
	}
	hash := sha256.Sum256(original)
	if !callback.once || bytes.Equal(blob, original) || got.Verification.Digest != "sha256:"+hexLower(hash[:]) || got.Manifest["name"] != "snapshot" || len(got.Entries) != 1 || !bytes.Equal(got.Entries[0].Content, []byte(manifest)) {
		t.Fatal("digest, manifest and returned entries did not bind the private original bytes")
	}
	signed, row := false, false
	for _, scope := range got.Verification.DataScopes {
		if scope.Provenance == ScopeProvenanceSignedManifest && scope.Raw["id"] == "signed-original" {
			signed = true
		}
		if scope.Provenance == ScopeProvenanceBundleRow && scope.Raw["id"] == "unsigned-advisory" {
			row = true
		}
	}
	if !signed || !row {
		t.Fatalf("signed/advisory scope provenance lost: %+v", got.Verification.DataScopes)
	}
	got.Manifest["name"] = "caller-mutated"
	got.Entries[0].Content[0] = '!'
	opts.Logger = nil
	again, err := VerifySnapshot(opts, original, 1<<20)
	if err != nil || again.Manifest["name"] != "snapshot" || again.Entries[0].Content[0] != '{' {
		t.Fatal("returned caller data leaked into another invocation")
	}
	tampered := append([]byte{}, original...)
	tampered[0] ^= 1
	if bad, err := VerifySnapshot(opts, tampered, 1<<20); !errors.Is(err, ErrDigestMismatch) || (bad != nil && bad.Verification != nil) {
		t.Fatalf("tampered signed input accepted: %v", err)
	}
}

func TestSnapshotRejectsPathReopen(t *testing.T) {
	opts, blob := snapshotFixture(t, `{"name":"retained","version":"1.0.0"}`)
	for _, path := range []string{filepath.Join(t.TempDir(), "missing.skb"), filepath.Join(t.TempDir(), "other.skb")} {
		if filepath.Base(path) == "other.skb" {
			if err := os.WriteFile(path, []byte("unrelated path bytes"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		opts.BundlePath = path
		called := false
		opts.Logger = &snapshotCallbackWriter{callback: func() { called = true }}
		result, err := VerifySnapshot(opts, blob, 1<<20)
		if !errors.Is(err, ErrDigestMismatch) || (result != nil && result.Verification != nil) || called {
			t.Fatalf("snapshot path input was reopened/accepted: %v", err)
		}
	}
	opts.BundlePath = ""
	opts.Logger = nil
	if result, err := VerifySnapshot(opts, blob, 1<<20); err != nil || result == nil || result.Manifest["name"] != "retained" {
		t.Fatalf("path-free signed input needs filesystem path: %v", err)
	}
}

func TestSnapshotBoundedInputs(t *testing.T) {
	opts, blob := snapshotFixture(t, `{"name":"bounded","version":"1.0.0"}`)
	exact := snapshotInflated(t, blob)
	if result, err := VerifySnapshot(opts, blob, exact); err != nil || result == nil || result.Verification == nil || result.Usage.InflatedBytes != exact {
		t.Fatalf("exact stream cap rejected: %v", err)
	}
	for _, cap := range []int64{0, -1, math.MaxInt64, exact - 1} {
		result, err := VerifySnapshot(opts, blob, cap)
		if !errors.Is(err, skillbundle.ErrInflatedLimit) || (result != nil && result.Verification != nil) {
			t.Fatalf("inflated boundary became verified success: cap=%d err=%v", cap, err)
		}
	}
	for name, manifest := range map[string]string{
		"null": "null", "array": "[]", "invalid": "{", "duplicate": `{"x":1,"x":2}`,
		"escaped-alias": `{"x":1,"\u0078":2}`, "nested-duplicate": `{"nested":{"x":1,"x":2}}`,
		"depth":                 `{"nested":` + strings.Repeat("[", 128) + `0` + strings.Repeat("]", 128) + `}`,
		"manifest-cap-plus-one": `{"padding":"` + strings.Repeat("x", (1<<20)-13) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			o, b := snapshotFixture(t, manifest)
			result, err := VerifySnapshot(o, b, 4<<20)
			if !errors.Is(err, ErrDigestMismatch) || (result != nil && result.Verification != nil) {
				t.Fatalf("invalid signed manifest accepted: %v", err)
			}
		})
	}
	// The nested-container boundary is a real accepted input, not a blanket
	// refusal of all arrays used to make the over-depth negative pass.
	nested := `{"nested":` + strings.Repeat("[", 127) + `0` + strings.Repeat("]", 127) + `}`
	nestedOpts, nestedBlob := snapshotFixture(t, nested)
	if result, err := VerifySnapshot(nestedOpts, nestedBlob, 1<<20); err != nil || result == nil || result.Verification == nil {
		t.Fatalf("valid depth edge rejected: %v", err)
	}
	missing, _ := manifestReaderArchive(t, []string{"SKILL.md"}, `{"name":"not-a-manifest"}`)
	if result, err := VerifySnapshot(snapshotSignedOpts(t, missing), missing, 1<<20); !errors.Is(err, ErrDigestMismatch) || (result != nil && result.Verification != nil) {
		t.Fatalf("missing manifest accepted: %v", err)
	}
	wrapped, _ := manifestReaderArchive(t, []string{"wrapper/bundle.json"}, `{"name":"wrapped"}`)
	if result, err := VerifySnapshot(snapshotSignedOpts(t, wrapped), wrapped, 1<<20); err != nil || result == nil || result.Manifest["name"] != "wrapped" {
		t.Fatalf("valid wrapped manifest rejected: %v", err)
	}
	// A valid object exactly at the manifest byte boundary must remain usable.
	prefix, suffix := `{"padding":"`, `"}`
	manifest := prefix + strings.Repeat("x", (1<<20)-len(prefix)-len(suffix)) + suffix
	o, b := snapshotFixture(t, manifest)
	if result, err := VerifySnapshot(o, b, 4<<20); err != nil || result == nil || result.Verification == nil {
		t.Fatalf("exact manifest limit rejected: %v", err)
	}
	repeated, _ := manifestReaderArchive(t, []string{"bundle.json", "bundle.json"}, `{"name":"duplicate"}`)
	if result, err := VerifySnapshot(snapshotSignedOpts(t, repeated), repeated, 1<<20); !errors.Is(err, ErrDigestMismatch) || (result != nil && result.Verification != nil) {
		t.Fatalf("multiple manifests accepted: %v", err)
	}
	for _, bad := range [][]byte{nil, []byte("signed but not a gzip archive")} {
		result, err := VerifySnapshot(snapshotSignedOpts(t, bad), bad, 1<<20)
		if !errors.Is(err, ErrDigestMismatch) || (result != nil && result.Verification != nil) {
			t.Fatalf("invalid archive accepted: %v", err)
		}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	opts.Ctx = canceled
	if result, err := VerifySnapshot(opts, blob, 1<<20); !errors.Is(err, context.Canceled) || (result != nil && result.Verification != nil) {
		t.Fatalf("canceled snapshot accepted: %v", err)
	}
	t.Run("late-cancellation-after-signed-scopes", func(t *testing.T) {
		lateOpts, lateBlob := snapshotFixture(t, `{"name":"late-cancel","data_dependencies":[{"id":"signed-scope"}]}`)
		lateCtx, lateCancel := context.WithCancel(context.Background())
		defer lateCancel()
		logger := &snapshotScopeCancelWriter{cancel: lateCancel}
		lateOpts.Ctx = lateCtx
		lateOpts.Logger = logger
		result, err := VerifySnapshot(lateOpts, lateBlob, 1<<20)
		if !logger.called || !errors.Is(err, context.Canceled) || (result != nil && result.Verification != nil) {
			t.Fatalf("late cancellation published verified success: reached=%v err=%v result=%+v", logger.called, err, result)
		}
	})
	// The raw cap must fail before copying/hashing or crypto traversal. The slice
	// has no secret data; only the size boundary matters.
	oversized := make([]byte, int(registry.MaxBlobSize)+1)
	if result, err := VerifySnapshot(VerifyOpts{}, oversized, 1<<20); !errors.Is(err, ErrDigestMismatch) || (result != nil && result.Verification != nil) {
		t.Fatalf("oversized raw snapshot accepted: %v", err)
	}
}

func TestSnapshotExistingVerifyParity(t *testing.T) {
	opts, blob := snapshotFixture(t, `{"name":"parity","version":"1.0.0","data_dependencies":[{"id":"same"}]}`)
	path := filepath.Join(t.TempDir(), "legacy.skb")
	if err := os.WriteFile(path, blob, 0600); err != nil {
		t.Fatal(err)
	}
	legacyOpts := opts
	legacyOpts.BundlePath = path
	legacy, err := Verify(legacyOpts)
	if err != nil {
		t.Fatal(err)
	}
	result, err := VerifySnapshot(opts, blob, 1<<20)
	if err != nil || result == nil || !reflect.DeepEqual(legacy, result.Verification) {
		t.Fatalf("legacy and snapshot chain/scope mismatch: %v", err)
	}
	// Existing path verifier keeps malformed-scope data advisory. The new strict
	// snapshot must reject rather than silently import that permissive behavior.
	bad, raw := snapshotFixture(t, `{`)
	path = filepath.Join(t.TempDir(), "advisory.skb")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	bad.BundlePath = path
	if _, err := Verify(bad); err != nil {
		t.Fatalf("legacy advisory contract unexpectedly changed: %v", err)
	}
	bad.BundlePath = ""
	if result, err := VerifySnapshot(bad, raw, 1<<20); !errors.Is(err, ErrDigestMismatch) || (result != nil && result.Verification != nil) {
		t.Fatalf("strict snapshot imported advisory fallback: %v", err)
	}
}
