package seal

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// SPEC-0470 section 4.3: key_id convention.
func TestKeyIDConvention(t *testing.T) {
	s := seedSigner(t, seedTrusted)
	id := KeyIDFor(s.PublicKey())
	if !strings.HasPrefix(id, "ed25519:") || len(id) != len("ed25519:")+16 || !ValidKeyID(id) {
		t.Fatalf("key id %q", id)
	}
	if s.KeyID() != id {
		t.Fatalf("signer key id %q, want %q", s.KeyID(), id)
	}
	for _, bad := range []string{"", "ed25519:", "device:0123456789abcdef", "ed25519:0123456789ABCDEF", "ed25519:0123456789abcde", "ed25519:0123456789abcdef0", "key-01234567"} {
		if ValidKeyID(bad) {
			t.Fatalf("ValidKeyID(%q) = true", bad)
		}
	}
	if KeyIDFor(seedSigner(t, seedAttacker).PublicKey()) == id {
		t.Fatal("two keys share a key id")
	}
}

// SPEC-0470 section 4.5: FileSigner goes through signing.LoadPrivateKey and
// signs exactly like the seed signer of the same key.
func TestFileSigner(t *testing.T) {
	dir := t.TempDir()
	privPath, pubPath := writeKeyFiles(t, dir, "reviewer", seedTrusted)
	fs, err := NewFileSigner(privPath)
	if err != nil {
		t.Fatal(err)
	}
	ss := seedSigner(t, seedTrusted)
	if fs.KeyID() != ss.KeyID() || !bytes.Equal(fs.PublicKey(), ss.PublicKey()) {
		t.Fatal("file and seed signer of the same key differ")
	}
	msg := []byte("message")
	s1, err := fs.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	s2, _ := ss.Sign(msg)
	if !bytes.Equal(s1, s2) || !ed25519.Verify(fs.PublicKey(), msg, s1) {
		t.Fatal("signatures differ or do not verify")
	}
	pub := fs.PublicKey()
	pub[0] ^= 0xff
	if bytes.Equal(pub, fs.PublicKey()) {
		t.Fatal("PublicKey returned internal storage")
	}

	fs.Close()
	if _, err := fs.Sign(msg); !errors.Is(err, ErrSignerClosed) {
		t.Fatalf("Sign after Close: %v", err)
	}
	if fs.KeyID() == "" {
		t.Fatal("key id lost after Close")
	}

	if _, err := NewFileSigner(pubPath); err == nil {
		t.Fatal("a public key file was accepted as signing key")
	}
	if _, err := NewFileSigner(filepath.Join(dir, "missing.priv")); err == nil {
		t.Fatal("missing key file accepted")
	}
	junk := filepath.Join(dir, "junk.priv")
	if err := os.WriteFile(junk, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileSigner(junk); err == nil {
		t.Fatal("junk key file accepted")
	}

	// The 0600 convention of signing.LoadPrivateKey applies unchanged. On
	// Windows that function skips the POSIX mode check by design.
	loose := filepath.Join(dir, "loose.priv")
	b, _ := os.ReadFile(privPath)
	if err := os.WriteFile(loose, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = NewFileSigner(loose)
	if runtime.GOOS == "windows" {
		t.Logf("windows: POSIX mode check not applicable (signing.LoadPrivateKey), load err = %v", err)
	} else if err == nil || !strings.Contains(err.Error(), "insecure mode") {
		t.Fatalf("0644 key accepted: %v", err)
	}
}

func TestSeedSignerAndKeyPair(t *testing.T) {
	if _, err := NewSeedSigner(make([]byte, 31)); !errors.Is(err, ErrSignerInvalid) {
		t.Fatalf("short seed: %v", err)
	}
	s := seedSigner(t, seedTrusted)
	s.Close()
	if _, err := s.Sign([]byte("x")); !errors.Is(err, ErrSignerClosed) {
		t.Fatalf("Sign after Close: %v", err)
	}

	// A private key whose public half does not belong to its seed is refused.
	priv := ed25519.NewKeyFromSeed(seedTrusted)
	other := ed25519.NewKeyFromSeed(seedAttacker)
	mixed := append(append(ed25519.PrivateKey{}, priv[:32]...), other[32:]...)
	if _, err := newKeyPair(mixed); !errors.Is(err, ErrSignerInvalid) {
		t.Fatalf("inconsistent key halves: %v", err)
	}
	if _, err := newKeyPair(priv[:40]); !errors.Is(err, ErrSignerInvalid) {
		t.Fatalf("short key: %v", err)
	}
}
