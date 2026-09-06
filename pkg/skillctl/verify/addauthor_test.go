package verify

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writePub writes an ed25519 public key in the PEM SPKI form `skillctl keygen`
// produces, and returns its path plus the fingerprint an operator would read
// aloud on a call.
func writePub(t *testing.T, dir, name string) (path, fingerprint string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path = filepath.Join(dir, name+".pub")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	sum := sha256.Sum256(pub)
	return path, "sha256:" + hex.EncodeToString(sum[:])
}

func rootWithRegistry(t *testing.T, dir, url string) *TrustRoots {
	t.Helper()
	tr := &TrustRoots{Path: filepath.Join(dir, "roots.yaml")}
	regPath, _ := writePub(t, dir, "registry")
	if err := tr.AddRegistry(url, regPath, "reg-1"); err != nil {
		t.Fatalf("AddRegistry: %v", err)
	}
	return tr
}

// THE test of this feature. A key that arrives with the artifact proves nothing,
// because it came down the same untrusted channel. The fingerprint is what makes
// SPEC-0406 AC-02 a fact instead of a claim, so a wrong one must be refused
// rather than reported, and there is no trust-on-first-use to fall back to.
func TestAddAuthorRefusesAKeyThatDoesNotMatchTheConfirmedFingerprint(t *testing.T) {
	dir := t.TempDir()
	const url = "https://eric.example/api/skills"
	tr := rootWithRegistry(t, dir, url)

	// The operator confirmed ONE key on the phone; a DIFFERENT key arrives.
	_, confirmed := writePub(t, dir, "the-one-we-agreed")
	arrived, _ := writePub(t, dir, "the-one-that-came")

	err := tr.AddAuthor(url, "id:eric@kup", arrived, confirmed)
	if err == nil {
		t.Fatal("a key that does not match the confirmed fingerprint was pinned")
	}
	// The message has to show BOTH values: the operator's next move is to compare
	// them, and a refusal that hides one of them cannot be acted on.
	msg := err.Error()
	for _, want := range []string{"confirmed:", "this key:", "second channel"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not help the operator act: missing %q in %v", want, msg)
		}
	}
	if len(tr.Roots[0].Authors) != 0 {
		t.Error("a refused pin was written anyway")
	}
}

// No fingerprint at all is the same refusal, not a lenient path. If this ever
// becomes optional, trust-on-first-use is back and the whole Phase 0 is theatre.
func TestAddAuthorRequiresAFingerprint(t *testing.T) {
	dir := t.TempDir()
	const url = "https://eric.example/api/skills"
	tr := rootWithRegistry(t, dir, url)
	pub, _ := writePub(t, dir, "eric")

	if err := tr.AddAuthor(url, "id:eric@kup", pub, ""); err == nil {
		t.Fatal("an author was pinned with no fingerprint at all")
	} else if !strings.Contains(err.Error(), "SECOND channel") {
		t.Errorf("the refusal does not say why a fingerprint is required: %v", err)
	}
}

// The happy path, and the two side effects that matter: the key lands in
// authors:, and the root flips to pinned. A root that carries a pinned author
// key and still fetches identities from a registry would answer the author
// question two ways.
func TestAddAuthorPinsAndSwitchesTheRootToPinned(t *testing.T) {
	dir := t.TempDir()
	const url = "https://eric.example/api/skills"
	tr := rootWithRegistry(t, dir, url)
	if got := tr.Roots[0].IdentityKeysAuthorized; got != "from-registry" {
		t.Fatalf("precondition: a fresh registry root should be %q, got %q", "from-registry", got)
	}

	pub, fp := writePub(t, dir, "eric")
	if err := tr.AddAuthor(url, "id:eric@kup", pub, fp); err != nil {
		t.Fatalf("AddAuthor: %v", err)
	}
	if n := len(tr.Roots[0].Authors); n != 1 {
		t.Fatalf("authors = %d, want 1", n)
	}
	if got := tr.Roots[0].Authors[0].ID; got != "id:eric@kup" {
		t.Errorf("identity = %q", got)
	}
	if got := tr.Roots[0].IdentityKeysAuthorized; got != "pinned" {
		t.Errorf("identity_keys_authorized = %q, want pinned: the offline paths need it", got)
	}
	// The pin must survive a save/load round trip, or the second machine reads
	// something different from what the first one wrote.
	if err := tr.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}
	back, err := Load(tr.Path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(back.Roots) != 1 || len(back.Roots[0].Authors) != 1 || back.Roots[0].Authors[0].ID != "id:eric@kup" {
		t.Fatalf("the pin did not survive the round trip: %+v", back.Roots)
	}
}

// A second, different key under the SAME identity is either a rotation or a
// substitution. Both are decisions; silently appending would make the second one
// invisible, and the verifier would then accept either key.
func TestAddAuthorRefusesASecondKeyForOneIdentity(t *testing.T) {
	dir := t.TempDir()
	const url = "https://eric.example/api/skills"
	tr := rootWithRegistry(t, dir, url)

	first, fp1 := writePub(t, dir, "eric-1")
	if err := tr.AddAuthor(url, "id:eric@kup", first, fp1); err != nil {
		t.Fatalf("first pin: %v", err)
	}
	second, fp2 := writePub(t, dir, "eric-2")
	err := tr.AddAuthor(url, "id:eric@kup", second, fp2)
	if err == nil {
		t.Fatal("a second key for one identity was accepted silently")
	}
	if !strings.Contains(err.Error(), "DIFFERENT key") {
		t.Errorf("the refusal does not name what happened: %v", err)
	}
	if n := len(tr.Roots[0].Authors); n != 1 {
		t.Errorf("authors = %d after a refused second pin, want 1", n)
	}
}

// An author key alone cannot create a root, because the chain also checks the
// registry signature. The refusal has to name the fix, not the invariant: this
// is the AC-08 lesson from verify-sig, applied before it could bite.
func TestAddAuthorOnAnUnknownRegistryNamesTheFix(t *testing.T) {
	dir := t.TempDir()
	tr := &TrustRoots{Path: filepath.Join(dir, "roots.yaml")}
	pub, fp := writePub(t, dir, "eric")

	err := tr.AddAuthor("https://nobody.example/api/skills", "id:eric@kup", pub, fp)
	if err == nil {
		t.Fatal("an author key alone created a trust root")
	}
	if !strings.Contains(err.Error(), "skillctl trust add --registry") {
		t.Errorf("the refusal does not tell the operator what to run: %v", err)
	}
}
