package install

// Tests for the network-free verify helpers (SPEC-0247). The full
// VerifyInstalledOffline happy path needs a signed bundle (covered by the e2e
// once a real skill is installed); here we test the pieces that don't need
// signatures: the extracted-content binding (AC-1) and the stash round-trip.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// makeSkb writes a gzip+tar .skb of the given files and extracts the same files
// to target. Returns the .skb path.
func makeSkb(t *testing.T, target string, files map[string]string) string {
	t.Helper()
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
		// extract the identical content to disk
		p := filepath.Join(target, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	skb := filepath.Join(target, "bundle.skb")
	if err := os.WriteFile(skb, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return skb
}

func TestContentBinding_MatchingExtraction_OK(t *testing.T) {
	dir := t.TempDir()
	skb := makeSkb(t, dir, map[string]string{"SKILL.md": "# hello", "sub/x.txt": "data"})
	if err := verifyExtractedMatchesBlob(skb, dir); err != nil {
		t.Fatalf("matching extraction should pass, got %v", err)
	}
}

func TestContentBinding_EditedBody_ExitDigestMismatch(t *testing.T) {
	dir := t.TempDir()
	skb := makeSkb(t, dir, map[string]string{"SKILL.md": "# hello"})
	// Tamper the body Claude would actually load.
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# EVIL"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := verifyExtractedMatchesBlob(skb, dir)
	if !errors.Is(err, verify.ErrDigestMismatch) {
		t.Fatalf("edited body must map to ErrDigestMismatch (exit 10), got %v", err)
	}
	if verify.ExitCode(err) != verify.ExitDigestMismatch {
		t.Fatalf("exit code = %d, want %d", verify.ExitCode(err), verify.ExitDigestMismatch)
	}
}

func TestContentBinding_MissingFile_Mismatch(t *testing.T) {
	dir := t.TempDir()
	skb := makeSkb(t, dir, map[string]string{"SKILL.md": "# hello", "extra.txt": "x"})
	if err := os.Remove(filepath.Join(dir, "extra.txt")); err != nil {
		t.Fatal(err)
	}
	if err := verifyExtractedMatchesBlob(skb, dir); !errors.Is(err, verify.ErrDigestMismatch) {
		t.Fatalf("missing file must be ErrDigestMismatch, got %v", err)
	}
}

func TestContentBinding_ExtraFile_Mismatch(t *testing.T) {
	dir := t.TempDir()
	skb := makeSkb(t, dir, map[string]string{"SKILL.md": "# hello"})
	// Attacker drops a new file the bundle never had.
	if err := os.WriteFile(filepath.Join(dir, "evil.sh"), []byte("rm -rf"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyExtractedMatchesBlob(skb, dir); !errors.Is(err, verify.ErrDigestMismatch) {
		t.Fatalf("unexpected extra file must be ErrDigestMismatch, got %v", err)
	}
}

func TestContentBinding_IgnoresSkbAndStash(t *testing.T) {
	dir := t.TempDir()
	skb := makeSkb(t, dir, map[string]string{"SKILL.md": "# hello"})
	// The .skb and the offline stash live in the dir but are NOT bundle content.
	if err := os.WriteFile(filepath.Join(dir, offlineMetaFile), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyExtractedMatchesBlob(skb, dir); err != nil {
		t.Fatalf(".skb + stash must be ignored, got %v", err)
	}
}

func TestStashRoundTrip_AndNoMeta(t *testing.T) {
	target := t.TempDir()
	meta := &registry.BundleMeta{
		Signatures:        []registry.SignatureRow{{Role: "author", IdentityID: "id:alice@m3c", SignatureB64: "sig"}},
		CurrentGovernance: "green",
	}
	resolver := stubResolver{m: map[string]*registry.Identity{
		"id:alice@m3c": {ID: "id:alice@m3c", PubkeyB64: "pk", AuthSource: "manual"},
	}}
	if err := StashOfflineMeta(context.Background(), resolver, target, meta, nil); err != nil {
		t.Fatalf("stash: %v", err)
	}
	om, err := readOfflineMeta(target)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if om.BundleMeta.CurrentGovernance != "green" || om.Identities["id:alice@m3c"].PubkeyB64 != "pk" {
		t.Fatalf("round-trip lost data: %+v", om)
	}

	// No stash → ErrNoOfflineMeta.
	if _, err := readOfflineMeta(t.TempDir()); !errors.Is(err, ErrNoOfflineMeta) {
		t.Fatalf("missing stash must be ErrNoOfflineMeta, got %v", err)
	}
}

func TestStaticFetcher(t *testing.T) {
	f := staticIdentityFetcher{m: map[string]*registry.Identity{"id:x": {ID: "id:x", PubkeyB64: "p"}}}
	if got, err := f.GetIdentity(context.Background(), "id:x"); err != nil || got.PubkeyB64 != "p" {
		t.Fatalf("hit failed: %v %v", got, err)
	}
	if _, err := f.GetIdentity(context.Background(), "id:missing"); err == nil {
		t.Fatal("miss must error")
	}
}

// writeSidecar writes a .m3c-provenance.json into target with the given level.
func writeSidecar(t *testing.T, target, level string) {
	t.Helper()
	side := registry.ProvenanceSidecar{
		SchemaVersion:   registry.ProvenanceSchemaVersion,
		Skill:           filepath.Base(target),
		Version:         "1.0.0",
		BundleDigest:    "sha256:deadbeef",
		Registry:        "self",
		GovernanceLevel: level,
	}
	b, err := json.Marshal(side)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, registry.ProvenanceSidecarName), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSidecar_NoSidecar_ErrNoSidecar(t *testing.T) {
	home := t.TempDir()
	target := filepath.Join(home, ".claude", "skills", "foo")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	err := VerifyInstalledSidecar(Opts{Name: "foo", HomeDir: home, GovernanceMin: "green"})
	if !errors.Is(err, registry.ErrNoSidecar) {
		t.Fatalf("want ErrNoSidecar, got %v", err)
	}
}

func TestSidecar_GreenPasses_WithContentBinding(t *testing.T) {
	home := t.TempDir()
	target := filepath.Join(home, ".claude", "skills", "good")
	makeSkb(t, target, map[string]string{"SKILL.md": "# good"})
	writeSidecar(t, target, "green")
	if err := VerifyInstalledSidecar(Opts{Name: "good", HomeDir: home, GovernanceMin: "green"}); err != nil {
		t.Fatalf("green + matching content should pass, got %v", err)
	}
}

func TestSidecar_TamperedBody_DigestMismatch(t *testing.T) {
	home := t.TempDir()
	target := filepath.Join(home, ".claude", "skills", "good")
	makeSkb(t, target, map[string]string{"SKILL.md": "# good"})
	writeSidecar(t, target, "green")
	// Tamper the body Claude loads — must be caught via content-binding.
	if err := os.WriteFile(filepath.Join(target, "SKILL.md"), []byte("# EVIL"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := VerifyInstalledSidecar(Opts{Name: "good", HomeDir: home, GovernanceMin: "green"})
	if !errors.Is(err, verify.ErrDigestMismatch) {
		t.Fatalf("tampered body must be ErrDigestMismatch, got %v", err)
	}
}

func TestSidecar_GovernanceBelowFloor(t *testing.T) {
	home := t.TempDir()
	target := filepath.Join(home, ".claude", "skills", "yel")
	makeSkb(t, target, map[string]string{"SKILL.md": "# y"})
	writeSidecar(t, target, "yellow")
	err := VerifyInstalledSidecar(Opts{Name: "yel", HomeDir: home, GovernanceMin: "green"})
	if !errors.Is(err, verify.ErrGovernanceBelowMin) {
		t.Fatalf("yellow under green floor must be ErrGovernanceBelowMin, got %v", err)
	}
}

// SEC-M5: a sidecar skill with NO stashed .skb has a fully unverified body.
// Governance + fingerprint alone must NOT pass it — it FAILS CLOSED with
// ErrDigestMismatch (exit 10), and content-binding is never skipped.
func TestSidecar_NoSkb_FailsClosed(t *testing.T) {
	home := t.TempDir()
	target := filepath.Join(home, ".claude", "skills", "nobody")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	// Write the body Claude would load + a green sidecar, but NO .skb to bind to.
	if err := os.WriteFile(filepath.Join(target, "SKILL.md"), []byte("# anything"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeSidecar(t, target, "green") // green would otherwise satisfy the floor
	err := VerifyInstalledSidecar(Opts{Name: "nobody", HomeDir: home, GovernanceMin: "green"})
	if !errors.Is(err, verify.ErrDigestMismatch) {
		t.Fatalf("sidecar with no .skb must FAIL CLOSED with ErrDigestMismatch, got %v", err)
	}
	if verify.ExitCode(err) != verify.ExitDigestMismatch {
		t.Fatalf("exit code = %d, want %d", verify.ExitCode(err), verify.ExitDigestMismatch)
	}
}

// makeOversizedSkb writes a .skb whose single entry decompresses to far more
// than MaxExtractedBytes (a gzip bomb shape). The on-disk extraction is NOT
// written — content-binding should abort on the size cap before any compare.
func makeOversizedSkb(t *testing.T, target string, oversizeBytes int64) string {
	t.Helper()
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "BIG.bin", Mode: 0o644, Size: oversizeBytes, Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	// Highly compressible zero-fill so the .skb stays tiny while the entry is huge.
	if _, err := io.CopyN(tw, zeroReader{}, oversizeBytes); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	skb := filepath.Join(target, "bomb.skb")
	if err := os.WriteFile(skb, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return skb
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// SEC-M1/M6: a single entry larger than the 100 MiB ceiling must abort the
// content-binding walk with ErrDigestMismatch — the per-entry io.Copy is now
// capped via io.LimitReader against the running total, so the gzip bomb never
// gets fully buffered/hashed.
func TestContentBinding_OversizedEntry_Mismatch(t *testing.T) {
	dir := t.TempDir()
	skb := makeOversizedSkb(t, dir, MaxExtractedBytes+1)
	err := verifyExtractedMatchesBlob(skb, dir)
	if !errors.Is(err, verify.ErrDigestMismatch) {
		t.Fatalf("oversized entry must abort with ErrDigestMismatch, got %v", err)
	}
	if verify.ExitCode(err) != verify.ExitDigestMismatch {
		t.Fatalf("exit code = %d, want %d", verify.ExitCode(err), verify.ExitDigestMismatch)
	}
}

// writeSidecarFP writes a sidecar with an explicit trust_roots_fingerprint.
func writeSidecarFP(t *testing.T, target, level, fp string) {
	t.Helper()
	side := registry.ProvenanceSidecar{
		SchemaVersion: registry.ProvenanceSchemaVersion, Skill: filepath.Base(target),
		Version: "1.0.0", BundleDigest: "sha256:deadbeef", Registry: "self",
		GovernanceLevel: level, TrustRootsFingerprint: fp,
	}
	b, _ := json.Marshal(side)
	if err := os.WriteFile(filepath.Join(target, registry.ProvenanceSidecarName), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// writeSelfTrustRoots writes a valid SPEC-0225 trust-roots.yaml and returns its
// computed fingerprint.
func writeSelfTrustRoots(t *testing.T, path string) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	y := "registry: self\npubkey_b64: " + base64.StdEncoding.EncodeToString(pub) + "\n"
	if err := os.WriteFile(path, []byte(y), 0o644); err != nil {
		t.Fatal(err)
	}
	tr, err := registry.LoadSelfTrustRoots(path)
	if err != nil {
		t.Fatalf("load self trust-roots: %v", err)
	}
	return tr.Fingerprint
}

func TestSidecar_TrustRootFingerprint_Match(t *testing.T) {
	home := t.TempDir()
	target := filepath.Join(home, ".claude", "skills", "good")
	makeSkb(t, target, map[string]string{"SKILL.md": "# good"})
	trPath := filepath.Join(home, ".claude", "trust-roots.yaml")
	fp := writeSelfTrustRoots(t, trPath)
	writeSidecarFP(t, target, "green", fp)
	if err := VerifyInstalledSidecar(Opts{Name: "good", HomeDir: home, GovernanceMin: "green", SelfTrustRootsPath: trPath}); err != nil {
		t.Fatalf("matching trust-root fingerprint should pass, got %v", err)
	}
}

func TestSidecar_TrustRootFingerprint_Mismatch(t *testing.T) {
	home := t.TempDir()
	target := filepath.Join(home, ".claude", "skills", "good")
	makeSkb(t, target, map[string]string{"SKILL.md": "# good"})
	trPath := filepath.Join(home, ".claude", "trust-roots.yaml")
	_ = writeSelfTrustRoots(t, trPath)
	writeSidecarFP(t, target, "green", "sha256:bogus-fingerprint-from-a-different-root")
	err := VerifyInstalledSidecar(Opts{Name: "good", HomeDir: home, GovernanceMin: "green", SelfTrustRootsPath: trPath})
	if !errors.Is(err, verify.ErrRegistryNotTrusted) {
		t.Fatalf("fingerprint mismatch must be ErrRegistryNotTrusted (exit 12), got %v", err)
	}
}

type stubResolver struct{ m map[string]*registry.Identity }

func (s stubResolver) GetIdentity(_ context.Context, id string) (*registry.Identity, error) {
	if v, ok := s.m[id]; ok {
		return v, nil
	}
	return nil, errors.New("not found")
}
