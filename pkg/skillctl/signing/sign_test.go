package signing

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// makeFakeBundle writes a small gzipped tar to dir and returns its path.
// It deliberately does NOT depend on pkg/skillbundle (which isn't on
// this stream's base branch) — sign/verify-sig only care about file
// bytes' SHA-256, not the bundle's internal structure.
func makeFakeBundle(t *testing.T, dir, name string) string {
	t.Helper()

	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	tw := tar.NewWriter(gz)

	body := []byte("# tiny test skill\n")
	if err := tw.WriteHeader(&tar.Header{
		Name: "tiny/SKILL.md",
		Mode: 0o644,
		Size: int64(len(body)),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestComputeBundleDigest_MatchesStdlibSHA256(t *testing.T) {
	dir := t.TempDir()
	bundle := makeFakeBundle(t, dir, "tiny.skb")

	got, err := ComputeBundleDigest(bundle)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(raw)
	if got != want {
		t.Fatalf("ComputeBundleDigest = %x, want %x", got, want)
	}
}

func TestComputeBundleDigest_RefusesEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.skb")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ComputeBundleDigest(path); err == nil {
		t.Fatal("ComputeBundleDigest accepted empty bundle; want refusal")
	}
}

func TestSignBundle_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	bundle := makeFakeBundle(t, dir, "demo.skb")

	keyOut := filepath.Join(dir, "k")
	if err := Generate(keyOut); err != nil {
		t.Fatal(err)
	}

	sigPath, digestHex, err := SignBundle(bundle, keyOut+".priv", "id:test@m3c")
	if err != nil {
		t.Fatalf("SignBundle: %v", err)
	}

	// Path convention.
	wantPath := bundle + "." + digestHex + ".author.sig"
	if sigPath != wantPath {
		t.Errorf("sig path = %s, want %s", sigPath, wantPath)
	}
	// Hex digest is 64 lowercase chars.
	if len(digestHex) != 64 {
		t.Errorf("digest hex length = %d, want 64", len(digestHex))
	}
	if digestHex != strings.ToLower(digestHex) {
		t.Errorf("digest hex %q is not lowercase", digestHex)
	}
	if _, err := hex.DecodeString(digestHex); err != nil {
		t.Errorf("digest hex not parseable: %v", err)
	}

	// Signature file is exactly 64 bytes.
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 64 {
		t.Errorf("signature size = %d bytes, want exactly 64", len(sig))
	}

	// And it verifies under the matching pubkey.
	if err := VerifyDetached(bundle, keyOut+".pub"); err != nil {
		t.Fatalf("VerifyDetached on freshly signed bundle: %v", err)
	}
}

func TestSignBundle_RefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	bundle := makeFakeBundle(t, dir, "demo.skb")
	keyOut := filepath.Join(dir, "k")
	if err := Generate(keyOut); err != nil {
		t.Fatal(err)
	}

	if _, _, err := SignBundle(bundle, keyOut+".priv", ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := SignBundle(bundle, keyOut+".priv", ""); err == nil {
		t.Fatal("second SignBundle succeeded; want refusal-to-overwrite")
	}
}

func TestSignBundle_RequiresPaths(t *testing.T) {
	if _, _, err := SignBundle("", "/nope.priv", ""); err == nil {
		t.Fatal("missing bundle path accepted")
	}
	if _, _, err := SignBundle("/nope.skb", "", ""); err == nil {
		t.Fatal("missing key path accepted")
	}
}

func TestSignBundle_RejectsEmptyBundle(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "empty.skb")
	if err := os.WriteFile(bundle, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	keyOut := filepath.Join(dir, "k")
	if err := Generate(keyOut); err != nil {
		t.Fatal(err)
	}
	if _, _, err := SignBundle(bundle, keyOut+".priv", ""); err == nil {
		t.Fatal("SignBundle accepted empty bundle")
	}
}

func TestSignaturePath_StaysInBundleDir(t *testing.T) {
	got := SignaturePath("/some/dir/foo.skb", "abc123")
	want := filepath.Join("/some/dir", "foo.skb.abc123.author.sig")
	if got != want {
		t.Errorf("SignaturePath = %s, want %s", got, want)
	}
}

func TestSignBundle_DoesNotLeakKeyInError(t *testing.T) {
	// If the private key file is malformed we want the error to say
	// what's wrong — but it must NOT contain the (would-be) key bytes.
	dir := t.TempDir()
	bundle := makeFakeBundle(t, dir, "demo.skb")

	// A PEM block whose body decodes but isn't PKCS8.
	junkPriv := filepath.Join(dir, "junk.priv")
	body := "-----BEGIN PRIVATE KEY-----\nbm90IHJlYWxseSBhIGtleQ==\n-----END PRIVATE KEY-----\n"
	if err := os.WriteFile(junkPriv, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := SignBundle(bundle, junkPriv, "")
	if err == nil {
		t.Fatal("SignBundle accepted junk private key")
	}
	// The error should reference the file path (which is a label, not
	// a secret) but not the literal PEM body.
	if strings.Contains(err.Error(), "bm90IHJlYWxseSBhIGtleQ") {
		t.Errorf("error message contains key-file body: %v", err)
	}
}

// quick sanity that ErrSignatureInvalid wraps cleanly under fmt.Errorf %w.
func TestErrSignatureInvalid_WrapsCleanly(t *testing.T) {
	wrapped := fmt.Errorf("outer context: %w", ErrSignatureInvalid)
	if !errors.Is(wrapped, ErrSignatureInvalid) {
		t.Errorf("fmt.Errorf %%w should wrap ErrSignatureInvalid so errors.Is matches")
	}
}
