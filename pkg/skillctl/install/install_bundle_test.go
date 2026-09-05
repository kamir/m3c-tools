package install

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// pinnedRoot builds the offline trust root InstallBundle requires: the author
// key is pinned locally, so nothing about the decision needs a network call.
func pinnedRoot(t *testing.T, fx *bundleFixture) *verify.TrustRoot {
	t.Helper()
	return &verify.TrustRoot{
		RegistryURL:            "local://acceptance",
		IdentityKeysAuthorized: "pinned",
		GovernanceMinimum:      "green",
		RegistryKeys: []verify.RegistryKey{{
			ID:        "reg-key-1",
			Pubkey:    []byte(fx.regPub),
			PubkeyB64: base64.StdEncoding.EncodeToString(fx.regPub),
			Issued:    "2026-05-05",
		}},
		Authors: []verify.AuthorKey{{
			ID:        "id:author@m3c",
			Pubkey:    []byte(fx.authorPub),
			PubkeyB64: base64.StdEncoding.EncodeToString(fx.authorPub),
		}},
	}
}

// sidecarMeta is the BundleMeta that travels alongside the .skb. `name` is the
// field an attacker would edit, which is the whole point of the relabel test.
func sidecarMeta(t *testing.T, fx *bundleFixture, name string) *registry.BundleMeta {
	t.Helper()
	authorSig := ed25519.Sign(fx.authorPriv, fx.digestRaw[:])
	regSig := ed25519.Sign(fx.regPriv, fx.digestRaw[:])
	raw := map[string]any{
		"bundle": map[string]any{
			"bundle_digest": fx.digestStr,
			"name":          name,
			"version":       "1.0.0",
			"status":        "admitted",
		},
		"signatures": []map[string]any{
			{"role": "author", "identity_id": "id:author@m3c", "signature_b64": base64.StdEncoding.EncodeToString(authorSig), "status": "active"},
			{"role": "registry", "identity_id": "id:registry@aims-core", "signature_b64": base64.StdEncoding.EncodeToString(regSig), "status": "active"},
		},
		"manifest":           map[string]any{"author_governance_intent": "green", "depends_on": []any{}},
		"current_governance": "green",
		"attestations": []map[string]any{
			{"level": "green", "reviewer_id": "id:reviewer@m3c", "attested_at": "2026-05-05T20:00:00Z"},
		},
	}
	b, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal meta: %v", err)
	}
	var meta registry.BundleMeta
	if err := json.Unmarshal(b, &meta); err != nil {
		t.Fatalf("unmarshal meta: %v", err)
	}
	return &meta
}

func writeBundle(t *testing.T, fx *bundleFixture) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "delivered.skb")
	if err := os.WriteFile(p, fx.blob, 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	return p
}

// The happy path: a signed .skb that arrived over an untrusted transport is
// verified against pinned roots and installed, with no network at all.
func TestInstallBundle_HappyPath(t *testing.T) {
	fx := mkBundleFixture(t)
	home := t.TempDir()

	res, err := InstallBundle(BundleOpts{
		BundlePath: writeBundle(t, fx),
		Meta:       sidecarMeta(t, fx, "fetch-contract"),
		TrustRoot:  pinnedRoot(t, fx),
		HomeDir:    home,
	})
	if err != nil {
		t.Fatalf("InstallBundle: %v", err)
	}
	if got := filepath.Base(res.InstalledPath); got != "fetch-contract" {
		t.Errorf("installed as %q, want %q", got, "fetch-contract")
	}
	if _, err := os.Stat(res.InstalledPath); err != nil {
		t.Errorf("nothing at the install path: %v", err)
	}
}

// THE security test of this feature.
//
// The author signature covers the digest and nothing else, so the sidecar's
// `name` is not signature-covered. An attacker who forwards a GENUINELY signed
// .skb can edit the sidecar to name a different, already-installed skill. Every
// signature still verifies. If the install directory were taken from the
// sidecar, the victim's other skill would be silently overwritten by content
// that was never meant for that name.
//
// The install directory must therefore come from the bundle.json INSIDE the
// digest-verified archive, and this test is what holds that line.
func TestInstallBundle_RelabelledSidecarCannotRedirectTheInstall(t *testing.T) {
	fx := mkBundleFixture(t)
	home := t.TempDir()

	// A legitimate, unrelated skill the victim already has installed.
	victim := filepath.Join(home, installRoot, "kup-deploy-stage")
	if err := os.MkdirAll(victim, 0o755); err != nil {
		t.Fatalf("seed victim skill: %v", err)
	}
	canary := filepath.Join(victim, "SKILL.md")
	if err := os.WriteFile(canary, []byte("the operator's real deploy skill"), 0o600); err != nil {
		t.Fatalf("seed canary: %v", err)
	}

	// The attacker forwards the genuinely signed bundle, relabelled.
	res, err := InstallBundle(BundleOpts{
		BundlePath: writeBundle(t, fx),
		Meta:       sidecarMeta(t, fx, "kup-deploy-stage"),
		TrustRoot:  pinnedRoot(t, fx),
		HomeDir:    home,
	})
	if err != nil {
		t.Fatalf("the install should still succeed under its OWN signed name: %v", err)
	}

	// It must land under the signed name, not the relabelled one.
	if got := filepath.Base(res.InstalledPath); got != "fetch-contract" {
		t.Errorf("a relabelled sidecar steered the install to %q", got)
	}

	// And the victim's skill must be untouched, byte for byte.
	got, err := os.ReadFile(canary) // #nosec G304 -- the test's own temp dir.
	if err != nil {
		t.Fatalf("the victim skill disappeared: %v", err)
	}
	if string(got) != "the operator's real deploy skill" {
		t.Errorf("a relabelled sidecar overwrote an unrelated installed skill; canary now reads %q", got)
	}
}

// An explicit --name is a statement of intent. When it disagrees with the signed
// name, the operator believes they are installing something else, and that
// disagreement must stop the install rather than be quietly resolved either way.
func TestInstallBundle_NameMismatchIsRefused(t *testing.T) {
	fx := mkBundleFixture(t)
	_, err := InstallBundle(BundleOpts{
		BundlePath: writeBundle(t, fx),
		Meta:       sidecarMeta(t, fx, "fetch-contract"),
		TrustRoot:  pinnedRoot(t, fx),
		HomeDir:    t.TempDir(),
		Name:       "something-else",
	})
	if err == nil {
		t.Fatal("a --name disagreeing with the signed bundle name was accepted")
	}
	if !errors.Is(err, verify.ErrDigestMismatch) {
		t.Errorf("the refusal does not carry a typed sentinel, so the exit code would be generic: %v", err)
	}
	if !strings.Contains(err.Error(), "signed bundle name") {
		t.Errorf("the message does not name the cause: %v", err)
	}
}

// A tampered artifact must be refused with the digest sentinel, so the CLI maps
// it to the SAME numbered exit code the registry path produces. An operator
// comparing two machines has to read the same number for the same cause.
func TestInstallBundle_TamperedBundleIsRefusedAndWritesNothing(t *testing.T) {
	fx := mkBundleFixture(t)
	home := t.TempDir()
	path := writeBundle(t, fx)

	// Flip one byte AFTER signing: the classic SPEC-0406 Phase 5 move.
	blob, err := os.ReadFile(path) // #nosec G304 -- the test's own temp dir.
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	blob[len(blob)/2] ^= 0xFF
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err = InstallBundle(BundleOpts{
		BundlePath: path,
		Meta:       sidecarMeta(t, fx, "fetch-contract"),
		TrustRoot:  pinnedRoot(t, fx),
		HomeDir:    home,
	})
	if err == nil {
		t.Fatal("a tampered bundle was installed")
	}
	if !errors.Is(err, verify.ErrDigestMismatch) {
		t.Errorf("want ErrDigestMismatch so the exit code is 10, got %v", err)
	}
	if verify.ExitCode(err) != verify.ExitDigestMismatch {
		t.Errorf("exit code = %d, want %d", verify.ExitCode(err), verify.ExitDigestMismatch)
	}
	// INV-6 in miniature: a refusal writes nothing into the install root.
	if entries, err := os.ReadDir(filepath.Join(home, installRoot)); err == nil && len(entries) > 0 {
		t.Errorf("a refused install still wrote %d entries into the install root", len(entries))
	}
}

// A root that expects to fetch identities cannot be used offline. InstallBundle
// requires a pinned root; the CLI reports this in actionable terms, and the
// library must not quietly proceed with an unverifiable author key.
func TestInstallBundle_RequiresPinnedAuthorKey(t *testing.T) {
	fx := mkBundleFixture(t)
	root := pinnedRoot(t, fx)
	root.IdentityKeysAuthorized = "from-registry"
	root.Authors = nil

	_, err := InstallBundle(BundleOpts{
		BundlePath: writeBundle(t, fx),
		Meta:       sidecarMeta(t, fx, "fetch-contract"),
		TrustRoot:  root,
		HomeDir:    t.TempDir(),
	})
	if err == nil {
		t.Fatal("an unpinned author key was accepted on the offline path")
	}
}
