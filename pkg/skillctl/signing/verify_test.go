package signing

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
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
	// signature lookup either misses or, if the attacker fabricates
	// a sig file at the new digest path, verifies as invalid.
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
	// Don't sign: just try to verify.
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
	// Must NOT be ErrSignatureInvalid. That's reserved for crypto
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
// here would require the same import path, but we already use it
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

// SPEC-0406 AC-08 for this surface: a refusal must name the condition that was
// violated, not its side effect.
//
// The detached signature is stored under a filename containing the digest it
// covers. Change a byte and the lookup misses, and the tool used to answer
// "signature file not found": true, useless, and it sends the reader after a
// missing file instead of a broken seal.
func TestTamperedBundleNamesTheCauseNotTheSideEffect(t *testing.T) {
	dir := t.TempDir()
	bundle := makeFakeBundle(t, dir, "b.skb")
	keyOut := filepath.Join(dir, "k")
	if err := Generate(keyOut); err != nil {
		t.Fatal(err)
	}
	if _, _, err := SignBundle(bundle, keyOut+".priv", ""); err != nil {
		t.Fatal(err)
	}

	// The digest the signature actually covers, captured before the tamper.
	digest, err := ComputeBundleDigest(bundle)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	signedHex := hex.EncodeToString(digest[:])

	// Anti-vacuity: if the clean bundle does not verify, everything below is
	// measuring a broken fixture rather than the property under test.
	if err := VerifyDetached(bundle, keyOut+".pub"); err != nil {
		t.Fatalf("the untampered bundle must verify first, or this test proves nothing: %v", err)
	}

	// The tamper. The signature stays where it is, under its old name: exactly
	// what a recipient sees when a signed file is altered in transit.
	if err := os.WriteFile(bundle, []byte("ALTERED, and not a valid archive"), 0o600); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	err = VerifyDetached(bundle, keyOut+".pub")
	if err == nil {
		t.Fatal("a tampered bundle verified")
	}
	if !errors.Is(err, ErrDigestChanged) {
		t.Errorf("the refusal does not carry ErrDigestChanged, so the CLI cannot map it to exit 10: %v", err)
	}
	// It still IS a signature failure; the specific cause simply wins.
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("the refusal dropped ErrSignatureInvalid: %v", err)
	}
	msg := err.Error()
	if strings.Contains(msg, "not found") {
		t.Errorf("the message still reports a missing file rather than altered bytes: %v", msg)
	}
	if !strings.Contains(msg, signedHex) {
		t.Errorf("the message does not name the digest the signature covers, so the reader cannot see the two differ: %v", msg)
	}
}

// The opposite case must stay distinguishable: a bundle nobody ever signed here
// is a forgotten packaging step, not a broken seal, and it calls for a different
// action (ask the sender for the signature).
func TestUnsignedBundleIsNotReportedAsTampering(t *testing.T) {
	dir := t.TempDir()
	bundle := makeFakeBundle(t, dir, "never-signed.skb")
	keyOut := filepath.Join(dir, "k")
	if err := Generate(keyOut); err != nil {
		t.Fatal(err)
	}

	err := VerifyDetached(bundle, keyOut+".pub")
	if err == nil {
		t.Fatal("an unsigned bundle verified")
	}
	if errors.Is(err, ErrDigestChanged) {
		t.Errorf("an unsigned bundle was reported as tampering: %v", err)
	}
	if !strings.Contains(err.Error(), "never to have been signed") {
		t.Errorf("the message does not say what is actually the case: %v", err)
	}
}

// The sibling scan reads filenames from a directory an attacker may influence in
// exactly the scenario it runs in. It must not put arbitrary text into an error
// message, so anything that is not a sha256 hex digest is ignored.
func TestSiblingScanIgnoresNonDigestFilenames(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "b.skb")
	if err := os.WriteFile(bundle, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	for _, name := range []string{
		"b.skb.not-a-digest.author.sig",
		"b.skb.deadbeef.author.sig", // hex, but too short
		"b.skb." + strings.Repeat("z", 64) + ".author.sig",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("junk"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if got := siblingSignatureDigests(bundle); len(got) != 0 {
		t.Errorf("non-digest filenames leaked into the scan result: %v", got)
	}
}
