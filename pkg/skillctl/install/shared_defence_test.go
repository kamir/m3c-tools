package install

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// This file exists because of a comment.
//
// finishInstall carries the claim that both install paths share one write
// sequence, "so a defence added to one is a defence in both". That sentence was
// true when it was written and nothing enforced it. A comment is never checked
// against a run: someone can add a third install path, or inline the sequence,
// and the sentence still reads like a guarantee.
//
// A peer session hit exactly this failure mode on the same day, in a comment
// that asserted the reach of a waiver next to the rule it justified. The reach
// was wrong and no test could have said so. This is the countermeasure for our
// version of it, and it is behavioural rather than structural on purpose: it
// does not check that the paths CALL a shared function, it checks that they
// REFUSE the same artifact. A refactor that keeps the guarantee is free to move
// the code; one that loses it fails here.
//
// CHECKSUMS validation is the defence under test because it is the one an
// independent reviewer flagged as missing on a neighbouring path (BUG-0217): a
// good proxy for "would a third path quietly skip a check".

// bundleWithBadChecksums builds a .skb whose CHECKSUMS file claims a digest the
// packed file does not have. The archive is otherwise well formed, and its own
// bundle digest is honest, so every earlier gate passes and only step 8 can
// refuse it. That isolation is what makes the test about the shared sequence
// rather than about the chain in general.
func bundleWithBadChecksums(t *testing.T, name string) []byte {
	t.Helper()
	files := map[string]string{
		"bundle.json": `{"schema":"m3c-skill-bundle/v1","name":"` + name + `","version":"1.0.0"}` + "\n",
		"SKILL.md":    "# " + name + "\n\nreal content\n",
		// A digest of something else entirely. Two spaces, sha256sum convention.
		"CHECKSUMS": strings.Repeat("00", sha256.Size) + "  SKILL.md\n",
	}
	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	tw := tar.NewWriter(gw)
	root := name + "-1.0.0"
	if err := tw.WriteHeader(&tar.Header{Name: root + "/", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
		t.Fatalf("tar dir: %v", err)
	}
	for p, c := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: root + "/" + p, Mode: 0o644, Size: int64(len(c)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatalf("tar header %s: %v", p, err)
		}
		if _, err := tw.Write([]byte(c)); err != nil {
			t.Fatalf("tar write %s: %v", p, err)
		}
	}
	_ = tw.Close()
	_ = gw.Close()
	return gz.Bytes()
}

// TestBothInstallPathsRefuseTheSameBadChecksums is the test the comment needed.
//
// One artifact, two entry points, one expected verdict. If a later change gives
// the registry path a check the bundle path lacks (or the reverse), exactly one
// half of this fails, and the failure names which path lost the defence.
func TestBothInstallPathsRefuseTheSameBadChecksums(t *testing.T) {
	const name = "fetch-contract"

	// One set of keys and one blob, used by both halves: the artifact must be
	// literally the same thing, or the test compares two experiments.
	authorPub, authorPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("author key: %v", err)
	}
	regPub, regPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("registry key: %v", err)
	}
	blob := bundleWithBadChecksums(t, name)
	sum := sha256.Sum256(blob)
	digest := "sha256:" + hex.EncodeToString(sum[:])

	metaRaw := map[string]any{
		"bundle": map[string]any{
			"bundle_digest": digest, "name": name, "version": "1.0.0", "status": "admitted",
		},
		"signatures": []map[string]any{
			{"role": "author", "identity_id": "id:author@m3c",
				"signature_b64": base64.StdEncoding.EncodeToString(ed25519.Sign(authorPriv, sum[:])), "status": "active"},
			{"role": "registry", "identity_id": "id:registry@m3c",
				"signature_b64": base64.StdEncoding.EncodeToString(ed25519.Sign(regPriv, sum[:])), "status": "active"},
		},
		"manifest":           map[string]any{"author_governance_intent": "green", "depends_on": []any{}},
		"current_governance": "green",
		"attestations": []map[string]any{
			{"level": "green", "reviewer_id": "id:reviewer@m3c", "attested_at": "2026-09-06T00:00:00Z"},
		},
	}
	meta := decodeMeta(t, metaRaw)

	root := &verify.TrustRoot{
		RegistryURL:            "https://shared.example/api/skills",
		IdentityKeysAuthorized: "pinned",
		GovernanceMinimum:      "green",
		RegistryKeys: []verify.RegistryKey{{
			ID: "reg-1", Pubkey: []byte(regPub),
			PubkeyB64: base64.StdEncoding.EncodeToString(regPub), Issued: "2026-09-06",
		}},
		Authors: []verify.AuthorKey{{
			ID: "id:author@m3c", Pubkey: []byte(authorPub),
			PubkeyB64: base64.StdEncoding.EncodeToString(authorPub),
		}},
	}

	// --- path 1: the local .skb (SPEC-0406 D2) ---
	dir := t.TempDir()
	skb := filepath.Join(dir, name+"@1.0.0.skb")
	if err := os.WriteFile(skb, blob, 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	home1 := t.TempDir()
	_, bundleErr := InstallBundle(BundleOpts{
		BundlePath: skb, Meta: meta, TrustRoot: root, HomeDir: home1,
	})

	// --- path 2: the shared sequence, reached directly ---
	//
	// The registry path is exercised through finishInstall rather than through a
	// stub server, because what is under test is the WRITE SEQUENCE both paths
	// share, not the fetching that only one of them does. A stub would add a
	// second variable and weaken the comparison.
	home2 := t.TempDir()
	staging, err := makeStagingDir(home2, name, digest)
	if err != nil {
		t.Fatalf("staging: %v", err)
	}
	blobPath := filepath.Join(staging, name+".skb")
	if err := os.WriteFile(blobPath, blob, 0o600); err != nil {
		t.Fatalf("stage: %v", err)
	}
	_, seqErr := finishInstall(finishOpts{
		blob: blob, blobPath: blobPath, stagingDir: staging, homeDir: home2,
		name: name, digest: digest, meta: meta, verRes: &verify.VerifyResult{Digest: digest},
	})

	// --- the comparison ---
	if bundleErr == nil {
		t.Error("install --bundle accepted a bundle whose CHECKSUMS do not match its content")
	}
	if seqErr == nil {
		t.Error("the shared write sequence accepted a bundle whose CHECKSUMS do not match its content")
	}
	if (bundleErr == nil) != (seqErr == nil) {
		t.Fatalf("THE TWO PATHS DISAGREE: bundle=%v, shared sequence=%v\n"+
			"finishInstall's comment claims a defence added to one is a defence in both. "+
			"That is now false.", bundleErr, seqErr)
	}
	// Same cause, not merely the same outcome: a path that refuses for an
	// unrelated reason would still pass a bare "both failed" check.
	for label, e := range map[string]error{"install --bundle": bundleErr, "shared sequence": seqErr} {
		if !errors.Is(e, verify.ErrDigestMismatch) {
			t.Errorf("%s refused for the wrong reason: want ErrDigestMismatch, got %v", label, e)
		}
	}

	// And neither path may leave the skill installed after refusing.
	for label, h := range map[string]string{"install --bundle": home1, "shared sequence": home2} {
		if _, err := os.Stat(filepath.Join(h, installRoot, name)); err == nil {
			t.Errorf("%s refused and installed the skill anyway", label)
		}
	}
}

// decodeMeta round-trips a raw map through the wire type, so the test feeds the
// verifier exactly what a sidecar file would.
func decodeMeta(t *testing.T, raw map[string]any) *registry.BundleMeta {
	t.Helper()
	b, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal meta: %v", err)
	}
	var m registry.BundleMeta
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal meta: %v", err)
	}
	return &m
}
