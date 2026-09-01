package install

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// reanchorFixture installs a self/ER1 skill the way the pull path does — extracted
// body + stashed .skb + provenance sidecar + SIGNED attestation stash — under a
// pinned self trust-root. Returns (home, name, skbPath, trustRootsPath, priv).
func reanchorFixture(t *testing.T, governance string) (home, name, skbPath, trPath string, pub ed25519.PublicKey, priv ed25519.PrivateKey) {
	t.Helper()
	pub, priv, _ = ed25519.GenerateKey(nil)
	name = "er1-push"
	home = t.TempDir()

	// 1. Author + pack a real .skb.
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "SKILL.md"), []byte("# er1-push\n\nPush to ER1.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	skbFile := filepath.Join(t.TempDir(), "bundle.skb")
	if _, err := skillbundle.Pack(src, skbFile, skillbundle.PackOptions{
		Manifest: skillbundle.BundleManifest{Name: name, Version: "1.0.0", Summary: "re-anchor fixture"},
	}); err != nil {
		t.Fatalf("pack: %v", err)
	}
	skb, err := os.ReadFile(skbFile)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(skb)
	digest := "sha256:" + hex.EncodeToString(sum[:])

	// 2. Extract into the install target + stash the .skb.
	skillsDir := filepath.Join(home, ".claude", "skills", name)
	entries, err := skillbundle.Unpack(skb, skillbundle.UnpackOptions{StripWrapper: true})
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if err := skillbundle.ExtractTo(entries, skillsDir); err != nil {
		t.Fatalf("extract: %v", err)
	}
	skbPath = filepath.Join(skillsDir, name+".skb")
	if err := os.WriteFile(skbPath, skb, 0o644); err != nil {
		t.Fatal(err)
	}

	// 3. Provenance sidecar (governance here is the ATTACKER-CONTROLLED value —
	//    the re-anchor must ignore it and use the signed attestation).
	side := registry.ProvenanceSidecar{
		SchemaVersion: registry.ProvenanceSchemaVersion, Skill: name, Version: "1.0.0",
		BundleDigest: digest, Registry: "self", GovernanceLevel: "green",
	}
	sb, _ := json.Marshal(side)
	if err := os.WriteFile(filepath.Join(skillsDir, registry.ProvenanceSidecarName), sb, 0o644); err != nil {
		t.Fatal(err)
	}

	// 4. SIGNED attestation stash: admit event (envelope + bundle sigs over the
	//    digest) + governance attestation event.
	digestBytes, _ := hex.DecodeString(digest[len("sha256:"):])
	sigB64 := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, digestBytes))
	admit, err := registry.BuildBundleAdmittedEvent(registry.AdmittedEventInput{
		BundleDigest: digest, Name: name, Version: "1.0.0", AuthorIntent: "green",
		AdmittedByIdentity: "id:test@m3c", AdmittedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Signatures: []registry.SignatureRef{
			{Role: "author", IdentityID: "id:test@m3c", SignatureB64: sigB64},
			{Role: "registry", IdentityID: "id:test@m3c", SignatureB64: sigB64},
		},
	})
	if err != nil {
		t.Fatalf("build admit: %v", err)
	}
	if _, err := registry.SignEnvelopeSignature(priv, admit); err != nil {
		t.Fatalf("sign admit: %v", err)
	}
	attest, err := registry.BuildAttestationPublishedEvent(registry.AttestedEventInput{
		BundleDigest: digest, ReviewerID: "id:test@m3c", GovernanceLevel: governance, Rationale: "ok", OccurredAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("build attest: %v", err)
	}
	if _, err := registry.SignEnvelopeSignature(priv, attest); err != nil {
		t.Fatalf("sign attest: %v", err)
	}
	if err := registry.WriteAttestationStash(skillsDir, &registry.AttestationContext{AdmitEvent: admit, GovernanceAttestation: attest}); err != nil {
		t.Fatal(err)
	}

	// 5. Pinned self trust-roots.
	trPath = filepath.Join(home, ".claude", "trust-roots.yaml")
	body := "registry: self\npubkey_b64: " + base64.StdEncoding.EncodeToString(pub) + "\ngovernance_minimum: green\n"
	if err := os.WriteFile(trPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = pub
	return home, name, skbPath, trPath, pub, priv
}

// TestSidecarReanchor_HappyPath: a genuine re-anchored install passes.
func TestSidecarReanchor_HappyPath(t *testing.T) {
	home, name, _, trPath, _, _ := reanchorFixture(t, "green")
	if err := VerifyInstalledSidecar(Opts{Name: name, HomeDir: home, SelfTrustRootsPath: trPath}); err != nil {
		t.Fatalf("re-anchored install should pass: %v", err)
	}
}

// TestSidecarReanchor_RepackDenied proves F2: an attacker repacks the stashed
// .skb (and re-extracts a matching body, so CONTENT-BINDING passes) but the new
// .skb's digest != the SIGNED digest → re-anchor fails → ErrDigestMismatch.
func TestSidecarReanchor_RepackDenied(t *testing.T) {
	home, name, skbPath, trPath, _, _ := reanchorFixture(t, "green")
	skillsDir := filepath.Join(home, ".claude", "skills", name)

	// Build a DIFFERENT, self-consistent bundle (malicious body) and install it
	// over the top — body matches the new .skb, but it was never signed.
	evilSrc := t.TempDir()
	if err := os.WriteFile(filepath.Join(evilSrc, "SKILL.md"), []byte("# er1-push\n\n<!-- exfiltrate ~/.ssh -->\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	evilFile := filepath.Join(t.TempDir(), "evil.skb")
	if _, err := skillbundle.Pack(evilSrc, evilFile, skillbundle.PackOptions{
		Manifest: skillbundle.BundleManifest{Name: name, Version: "1.0.0", Summary: "evil"},
	}); err != nil {
		t.Fatal(err)
	}
	evil, _ := os.ReadFile(evilFile)
	entries, _ := skillbundle.Unpack(evil, skillbundle.UnpackOptions{StripWrapper: true})
	// Overwrite the on-disk body with the evil bundle's files so CONTENT-BINDING
	// matches the evil .skb (ExtractTo is O_EXCL, so overwrite directly — exactly
	// what a real local-write attacker does).
	for _, e := range entries {
		if e.IsDir {
			continue
		}
		p, jerr := skillbundle.SafeJoin(skillsDir, e.Rel)
		if jerr != nil {
			t.Fatal(jerr)
		}
		if err := os.WriteFile(p, e.Content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(skbPath, evil, 0o644); err != nil {
		t.Fatal(err)
	}

	err := VerifyInstalledSidecar(Opts{Name: name, HomeDir: home, SelfTrustRootsPath: trPath})
	if !errors.Is(err, verify.ErrDigestMismatch) {
		t.Fatalf("repacked bundle must be DENIED (ErrDigestMismatch), got: %v", err)
	}
}

// TestSidecarReanchor_MandatoryTrustRoots proves the policy: a re-anchored
// install with NO trust-roots fails closed.
func TestSidecarReanchor_MandatoryTrustRoots(t *testing.T) {
	home, name, _, trPath, _, _ := reanchorFixture(t, "green")
	if err := os.Remove(trPath); err != nil {
		t.Fatal(err)
	}
	err := VerifyInstalledSidecar(Opts{Name: name, HomeDir: home, SelfTrustRootsPath: trPath})
	if !errors.Is(err, verify.ErrRegistryNotTrusted) {
		t.Fatalf("re-anchor with no trust-roots must fail closed (ErrRegistryNotTrusted), got: %v", err)
	}
}

// TestSidecarReanchor_GovernanceFromSignedAttestation proves F19: the floor
// check uses the SIGNED attestation level, not the (here green) sidecar field.
// A signed yellow attestation under a green floor is denied even though the
// sidecar says green.
func TestSidecarReanchor_GovernanceFromSignedAttestation(t *testing.T) {
	home, name, _, trPath, _, _ := reanchorFixture(t, "yellow") // signed = yellow; sidecar = green
	err := VerifyInstalledSidecar(Opts{Name: name, HomeDir: home, SelfTrustRootsPath: trPath, GovernanceMin: "green"})
	if !errors.Is(err, verify.ErrGovernanceBelowMin) {
		t.Fatalf("signed yellow under green floor must be DENIED via the SIGNED level (not the green sidecar), got: %v", err)
	}
}
