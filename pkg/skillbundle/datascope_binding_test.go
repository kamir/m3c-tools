package skillbundle

// SPEC-0196 §12 Q1 / P2b — the load-bearing security proof: a data-scope bound
// into bundle.json at pack time is INSIDE the signed bytes (the author signs
// the SHA-256 of the whole .skb), so EDITING the scope after pack changes the
// digest and BREAKS author-signature verification.
//
// This is the property the challenge gate checks: a red-teamer cannot strip or
// edit the signed scope without invalidating the signature.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
)

// scopedManifest returns a manifest carrying one author-signed write-scope plus
// the consistent intent (destructive=true so the §3.3 cross-rules are satisfied
// — this test is about binding, not validation).
func scopedManifest() BundleManifest {
	m := fixtureManifest()
	m.AuthorGovernanceIntent = "yellow"
	m.Intent = &Intent{
		SideEffects: []string{"fs:write"},
		Destructive: true,
	}
	m.DataDependencies = []DataDependency{
		{
			ID:     "ds:fs/cwd",
			Kind:   "local_fs",
			Access: "write",
			Scope:  "<cwd>/decks/**",
			Reason: "write the scaffolded decks",
		},
	}
	return m
}

// signDigest signs the SHA-256 of a packed .skb exactly as SignBundle does
// (ed25519 over the raw 32-byte digest, SPEC-0188 §4.1).
func signDigest(t *testing.T, priv ed25519.PrivateKey, skbPath string) ([]byte, [32]byte) {
	t.Helper()
	raw, err := os.ReadFile(skbPath)
	if err != nil {
		t.Fatalf("read skb: %v", err)
	}
	d := sha256.Sum256(raw)
	return ed25519.Sign(priv, d[:]), d
}

// TestDataScopeIsInsideSignedBytes proves a packed scope is digest-covered and
// that tampering the scope after pack breaks signature verification.
func TestDataScopeIsInsideSignedBytes(t *testing.T) {
	src := writeFixtureSkill(t)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	// 1. Pack the bundle WITH the author-signed scope, then sign its digest.
	good := filepath.Join(t.TempDir(), "good.skb")
	if _, err := Pack(src, good, PackOptions{Manifest: scopedManifest(), BuiltAt: fixedTime, BuiltBy: "skillctl/test"}); err != nil {
		t.Fatalf("pack good: %v", err)
	}
	sig, goodDigest := signDigest(t, priv, good)

	// The author signature verifies against the bundle's true digest.
	if !ed25519.Verify(pub, goodDigest[:], sig) {
		t.Fatal("author signature must verify against the unmodified bundle")
	}

	// The scope is genuinely present in the signed bundle.json.
	bj := readTarFile(t, good, "bundle.json")
	if !containsBytes(bj, "<cwd>/decks/**") {
		t.Fatal("scope must be present in the signed bundle.json")
	}

	// 2. Re-pack the SAME skill but with the scope EDITED (the tamper). A
	// red-teamer who edits the declared scope must change the bytes that were
	// signed. Re-packing is the most faithful model of "edit bundle.json and
	// re-tar" — it produces the archive an attacker would have to substitute.
	tampered := scopedManifest()
	tampered.DataDependencies[0].Scope = "<cwd>/**" // widened from decks/** to everything
	bad := filepath.Join(t.TempDir(), "bad.skb")
	if _, err := Pack(src, bad, PackOptions{Manifest: tampered, BuiltAt: fixedTime, BuiltBy: "skillctl/test"}); err != nil {
		t.Fatalf("pack tampered: %v", err)
	}
	_, badDigest := signDigest(t, priv, bad)

	// 3. The digest MUST differ — proof the scope is inside the signed bytes.
	if goodDigest == badDigest {
		t.Fatal("editing the scope did not change the digest — scope is NOT digest-covered")
	}

	// 4. The ORIGINAL author signature MUST NOT verify against the tampered
	// digest — the tamper is detected.
	if ed25519.Verify(pub, badDigest[:], sig) {
		t.Fatal("author signature verified against a TAMPERED scope — binding is broken")
	}
}

// TestStrippingScopeBreaksSignature proves removing the scope entirely (the
// "strip" attack) also changes the digest and breaks the signature.
func TestStrippingScopeBreaksSignature(t *testing.T) {
	src := writeFixtureSkill(t)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	good := filepath.Join(t.TempDir(), "good.skb")
	if _, err := Pack(src, good, PackOptions{Manifest: scopedManifest(), BuiltAt: fixedTime, BuiltBy: "skillctl/test"}); err != nil {
		t.Fatalf("pack good: %v", err)
	}
	sig, goodDigest := signDigest(t, priv, good)

	// Strip: re-pack with no data_dependencies and no intent.
	stripped := scopedManifest()
	stripped.DataDependencies = nil
	stripped.Intent = nil
	bad := filepath.Join(t.TempDir(), "stripped.skb")
	if _, err := Pack(src, bad, PackOptions{Manifest: stripped, BuiltAt: fixedTime, BuiltBy: "skillctl/test"}); err != nil {
		t.Fatalf("pack stripped: %v", err)
	}
	_, badDigest := signDigest(t, priv, bad)

	if goodDigest == badDigest {
		t.Fatal("stripping the scope did not change the digest — scope is NOT digest-covered")
	}
	if ed25519.Verify(pub, badDigest[:], sig) {
		t.Fatal("author signature verified against a STRIPPED scope — binding is broken")
	}
}

func containsBytes(haystack []byte, needle string) bool {
	n := []byte(needle)
	for i := 0; i+len(n) <= len(haystack); i++ {
		if string(haystack[i:i+len(n)]) == needle {
			return true
		}
	}
	return false
}
