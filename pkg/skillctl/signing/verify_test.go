package signing

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyDetached_HappyPath(t *testing.T) {
	dir := t.TempDir()
	bundle := makeFakeBundle(t, dir, "demo.skb")
	keyOut := filepath.Join(dir, "k")
	if err := Generate(keyOut); err != nil {
		t.Fatal(err)
	}

	if _, _, err := SignBundle(bundle, keyOut+".priv", ""); err != nil {
		t.Fatal(err)
	}
	if err := VerifyDetached(bundle, keyOut+".pub"); err != nil {
		t.Fatalf("VerifyDetached: %v", err)
	}
}

func TestVerifyDetached_TamperedBundle(t *testing.T) {
	dir := t.TempDir()
	bundle := makeFakeBundle(t, dir, "demo.skb")
	keyOut := filepath.Join(dir, "k")
	if err := Generate(keyOut); err != nil {
		t.Fatal(err)
	}
	if _, _, err := SignBundle(bundle, keyOut+".priv", ""); err != nil {
		t.Fatal(err)
	}

	// Flip a single byte in the bundle. The digest changes, so the
	// signature lookup either misses or — if the attacker fabricates
	// a sig file at the new digest path — verifies as invalid.
	raw, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 5 {
		t.Fatal("test bundle too small to tamper meaningfully")
	}
	// Pick a byte well past the gzip header.
	raw[len(raw)/2] ^= 0xFF
	if err := os.WriteFile(bundle, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	err = VerifyDetached(bundle, keyOut+".pub")
	if err == nil {
		t.Fatal("VerifyDetached accepted tampered bundle; want non-nil error")
	}
}

func TestVerifyDetached_WrongPubkey(t *testing.T) {
	dir := t.TempDir()
	bundle := makeFakeBundle(t, dir, "demo.skb")

	keyA := filepath.Join(dir, "kA")
	keyB := filepath.Join(dir, "kB")
	if err := Generate(keyA); err != nil {
		t.Fatal(err)
	}
	if err := Generate(keyB); err != nil {
		t.Fatal(err)
	}

	// Sign with A, verify with B's public key.
	if _, _, err := SignBundle(bundle, keyA+".priv", ""); err != nil {
		t.Fatal(err)
	}
	err := VerifyDetached(bundle, keyB+".pub")
	if err == nil {
		t.Fatal("VerifyDetached accepted mismatched pubkey; want non-nil error")
	}
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("VerifyDetached error = %v; want wraps ErrSignatureInvalid", err)
	}
}

func TestVerifyDetached_MissingSigFile(t *testing.T) {
	dir := t.TempDir()
	bundle := makeFakeBundle(t, dir, "demo.skb")
	keyOut := filepath.Join(dir, "k")
	if err := Generate(keyOut); err != nil {
		t.Fatal(err)
	}
	// Don't sign — just try to verify.
	err := VerifyDetached(bundle, keyOut+".pub")
	if err == nil {
		t.Fatal("VerifyDetached accepted missing sig file")
	}
}

func TestVerifyDetached_MalformedSigLength(t *testing.T) {
	dir := t.TempDir()
	bundle := makeFakeBundle(t, dir, "demo.skb")
	keyOut := filepath.Join(dir, "k")
	if err := Generate(keyOut); err != nil {
		t.Fatal(err)
	}
	if _, _, err := SignBundle(bundle, keyOut+".priv", ""); err != nil {
		t.Fatal(err)
	}

	// Truncate the signature so it's the wrong length.
	digest, err := ComputeBundleDigest(bundle)
	if err != nil {
		t.Fatal(err)
	}
	hexDigest := hexLower(digest[:])
	sigPath := SignaturePath(bundle, hexDigest)
	if err := os.WriteFile(sigPath, []byte("short"), 0o644); err != nil {
		t.Fatal(err)
	}
	err = VerifyDetached(bundle, keyOut+".pub")
	if err == nil {
		t.Fatal("VerifyDetached accepted malformed sig length")
	}
	// Must NOT be ErrSignatureInvalid — that's reserved for crypto
	// failure, not structural failure. Tests downstream branch on this.
	if errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("malformed-sig-length error misclassified as ErrSignatureInvalid: %v", err)
	}
}

func TestVerifyDetached_RequiresPaths(t *testing.T) {
	if err := VerifyDetached("", "/nope.pub"); err == nil {
		t.Fatal("missing bundle path accepted")
	}
	if err := VerifyDetached("/nope.skb", ""); err == nil {
		t.Fatal("missing pubkey path accepted")
	}
}

// hexLower exists only because importing encoding/hex in a test file
// here would require the same import path — but we already use it
// transitively. This local helper keeps the test focused.
func hexLower(b []byte) string {
	const hexChars = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, x := range b {
		out[i*2] = hexChars[x>>4]
		out[i*2+1] = hexChars[x&0x0f]
	}
	return string(out)
}
