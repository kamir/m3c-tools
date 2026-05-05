package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGenerate_HappyPath(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "key")

	if err := Generate(out); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Both files exist with expected modes.
	priv, err := os.Stat(out + ".priv")
	if err != nil {
		t.Fatalf("priv stat: %v", err)
	}
	if mode := priv.Mode().Perm(); mode != 0o600 {
		t.Errorf("priv mode = %#o, want 0600", mode)
	}

	pub, err := os.Stat(out + ".pub")
	if err != nil {
		t.Fatalf("pub stat: %v", err)
	}
	if mode := pub.Mode().Perm(); mode != 0o644 {
		t.Errorf("pub mode = %#o, want 0644", mode)
	}

	// Round-trip: load both, sign random data, verify with stdlib.
	loadedPriv, err := LoadPrivateKey(out + ".priv")
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	loadedPub, err := LoadPublicKey(out + ".pub")
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}

	msg := make([]byte, 32)
	if _, err := rand.Read(msg); err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(loadedPriv, msg)
	if !ed25519.Verify(loadedPub, msg, sig) {
		t.Fatal("ed25519.Verify failed on freshly generated keypair")
	}
}

func TestGenerate_RefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "key")

	if err := Generate(out); err != nil {
		t.Fatalf("first Generate: %v", err)
	}
	// Capture fingerprint of the existing private key to confirm it's
	// untouched after the second call.
	before, err := os.ReadFile(out + ".priv")
	if err != nil {
		t.Fatal(err)
	}
	if err := Generate(out); err == nil {
		t.Fatal("second Generate succeeded; expected refusal-to-overwrite error")
	}
	after, err := os.ReadFile(out + ".priv")
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("private key bytes changed after refused-overwrite Generate — keygen MUST never touch existing key files")
	}
}

func TestGenerate_RequiresOutPath(t *testing.T) {
	if err := Generate(""); err == nil {
		t.Fatal("Generate(\"\") succeeded; want usage error")
	}
}

func TestLoadPrivateKey_RejectsBroadMode(t *testing.T) {
	// chmod semantics differ on Windows; this test is only meaningful
	// on POSIX where mode bits actually constrain access.
	if runtime.GOOS == "windows" {
		t.Skip("private-key mode check is POSIX-only")
	}

	dir := t.TempDir()
	out := filepath.Join(dir, "key")
	if err := Generate(out); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := os.Chmod(out+".priv", 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadPrivateKey(out + ".priv")
	if err == nil {
		t.Fatal("LoadPrivateKey accepted 0644 mode; want rejection")
	}
}

func TestLoadPrivateKey_RejectsWrongPEMType(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fake.priv")
	// A PEM block with the wrong type. Bytes don't matter; the
	// validator should reject before parsing.
	body := "-----BEGIN RSA PRIVATE KEY-----\nABCD\n-----END RSA PRIVATE KEY-----\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateKey(path); err == nil {
		t.Fatal("LoadPrivateKey accepted wrong-typed PEM; want rejection")
	}
}

func TestLoadPrivateKey_RejectsExtraTrailingBlock(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "key")
	if err := Generate(out); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	good, err := os.ReadFile(out + ".priv")
	if err != nil {
		t.Fatal(err)
	}
	// Append a second, junk PEM block.
	tampered := append([]byte{}, good...)
	tampered = append(tampered, []byte("\n-----BEGIN PRIVATE KEY-----\nZZZZ\n-----END PRIVATE KEY-----\n")...)

	bad := filepath.Join(dir, "tampered.priv")
	if err := os.WriteFile(bad, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateKey(bad); err == nil {
		t.Fatal("LoadPrivateKey accepted file with extra trailing PEM block; want rejection")
	}
}

func TestLoadPublicKey_RejectsWrongPEMType(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fake.pub")
	body := "-----BEGIN CERTIFICATE-----\nABCD\n-----END CERTIFICATE-----\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPublicKey(path); err == nil {
		t.Fatal("LoadPublicKey accepted CERTIFICATE PEM; want rejection")
	}
}
