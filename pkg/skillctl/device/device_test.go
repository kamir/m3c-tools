package device

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestEnsureKey_LazyCreate(t *testing.T) {
	home := t.TempDir()
	// First call creates.
	k, err := EnsureKey(home)
	if err != nil {
		t.Fatalf("EnsureKey (create): %v", err)
	}
	if !strings.HasPrefix(k.KeyID(), "device:") {
		t.Errorf("KeyID %q lacks device: prefix", k.KeyID())
	}
	if !fileExists(privPath(home)) || !fileExists(pubPath(home)) {
		t.Fatalf("key files not written")
	}
	// Private key file must be 0600 (POSIX only — Windows synthesizes modes).
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(privPath(home))
		if perm := fi.Mode().Perm(); perm&0o077 != 0 {
			t.Errorf("priv key mode = %#o, want 0600", perm)
		}
	}
	// Second call is idempotent: same KeyID, no regeneration.
	k2, err := EnsureKey(home)
	if err != nil {
		t.Fatalf("EnsureKey (reload): %v", err)
	}
	if k.KeyID() != k2.KeyID() {
		t.Errorf("KeyID changed on reload: %q != %q", k.KeyID(), k2.KeyID())
	}
}

func TestEnsureKey_RefuseHalfKeypair(t *testing.T) {
	home := t.TempDir()
	if _, err := EnsureKey(home); err != nil {
		t.Fatalf("create: %v", err)
	}
	// Remove the .pub, leaving a half-keypair.
	if err := os.Remove(pubPath(home)); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureKey(home); err == nil {
		t.Fatalf("EnsureKey should refuse a half-keypair (only .priv present)")
	}
}

func TestLoad_AbsentIsError(t *testing.T) {
	home := t.TempDir()
	if _, err := Load(home); err == nil {
		t.Fatalf("Load on absent key should error")
	}
}

func TestSignVerify_RoundTrip(t *testing.T) {
	home := t.TempDir()
	k, err := EnsureKey(home)
	if err != nil {
		t.Fatalf("EnsureKey: %v", err)
	}
	msg := []byte("invocation_event_v1\nschema=x\n")
	sig := k.Sign(msg)
	if len(sig) != 64 {
		t.Fatalf("signature len = %d, want 64", len(sig))
	}
	if !k.Verify(msg, sig) {
		t.Errorf("Verify failed on freshly-signed message")
	}
	// Tampered message must not verify.
	if k.Verify([]byte("tampered"), sig) {
		t.Errorf("Verify accepted a tampered message")
	}
	// A second loaded handle (same key) verifies the same signature.
	k2, err := Load(home)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !k2.Verify(msg, sig) {
		t.Errorf("reloaded key did not verify a signature from the original handle")
	}
}

func TestKeyID_StableAcrossMachines_DependsOnPubKey(t *testing.T) {
	// Two distinct homes get distinct keys → distinct KeyIDs (no accidental
	// collision; the id is a function of the public key, not the path).
	a, err := EnsureKey(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b, err := EnsureKey(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if a.KeyID() == b.KeyID() {
		t.Errorf("two independently-generated keys share a KeyID: %q", a.KeyID())
	}
}

func TestLoad_DetectsTamperedPub(t *testing.T) {
	// Pair a real .priv with a foreign .pub → Load must refuse (key-confusion
	// guard), not return a confused handle.
	homeA := t.TempDir()
	homeB := t.TempDir()
	if _, err := EnsureKey(homeA); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureKey(homeB); err != nil {
		t.Fatal(err)
	}
	// Overwrite A's .pub with B's .pub.
	bPub, err := os.ReadFile(pubPath(homeB))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubPath(homeA), bPub, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(homeA); err == nil {
		t.Fatalf("Load accepted a mismatched .pub; want key-mismatch error")
	}
}

func TestPaths(t *testing.T) {
	home := "/tmp/h"
	if got, want := PrivPath(home), filepath.Join("/tmp/h", ".claude", "skillctl", "device-key.priv"); got != want {
		t.Errorf("PrivPath = %q, want %q", got, want)
	}
}
