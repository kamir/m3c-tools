package main

// Cross-version wire-format compatibility (AUDIT-0001 finding N.4).
//
// TestGitWireFormatFrozen (pkg/skillctl/backend/git/format_test.go) creates the
// registry with the build under test and reads it back with that same build. It
// pins self-consistency, not compatibility: any change that moves the writer and
// the reader together stays green there. COMPATIBILITY.md promises something
// stronger, that a reader accepts bundles produced by the current and the
// previous MINOR of its line, and nothing checked that mechanically.
//
// This file closes the gap with a COMMITTED BYTE FIXTURE: a complete local://
// registry built by an OLDER released skillctl, read by the build under test.
// The bytes cannot follow a refactor, so a break shows up as a red test instead
// of as a support ticket from a machine we do not control.
//
// # Fixture provenance
//
//	file      testdata/wireformat/skillctl-v0.4.0-registry.bundle, 3249 bytes
//	producer  tag skillctl/v0.4.0, commit f43eb49, committed 2026-09-03
//	content   wire-freeze-canary@1.0.0: a signed .skb of 777 bytes, its signed
//	          BundleAdmittedEvent and its signed AttestationPublishedEvent
//	key       a throwaway ed25519 keypair made for the fixture; only the public
//	          half is recorded here, the private half was never committed
//
// The fixture is a git bundle, not a bare repo: one small binary file rather
// than a repository nested inside this repository, and local://<file.bundle> is
// the supported read-only snapshot form (SPEC-0359 D1, backend/git/local.go).
//
// # Regenerating the fixture
//
// Do this only when the freeze is DELIBERATELY moved, and say so in the commit
// message. A red test is otherwise a real compatibility break, so fix the code,
// do not refresh the fixture.
//
//	OLD=skillctl/v0.4.0                      # the release the fixture comes from
//	W=$(mktemp -d); B=$(mktemp -d)
//	git worktree add --detach "$W" "$OLD"
//	(cd "$W" && go build -o "$B/skillctl" ./cmd/skillctl)
//	mkdir -p "$B/skill"
//	printf -- '---\nname: wire-freeze-canary\nversion: 1.0.0\ndescription: Fixture skill for the cross-version wire-format compatibility test.\n---\n' > "$B/skill/SKILL.md"
//	"$B/skillctl" keygen --out "$B/k"
//	"$B/skillctl" pack --skill "$B/skill" -o "$B/c.skb" --name wire-freeze-canary \
//	   --version 1.0.0 --summary "cross-version wire-format fixture"
//	"$B/skillctl" sign --key "$B/k.priv" "$B/c.skb"   # flags first: v0.4.0 stops at the positional
//	"$B/skillctl" registry init --registry "local://$B/registry.git"
//	"$B/skillctl" publish wire-freeze-canary --registry "local://$B/registry.git" \
//	   --bundle "$B/c.skb" --version 1.0.0 --key "$B/k.priv" --identity id:fixture@m3c \
//	   --yes --no-checkpoint                          # note the digest it prints
//	"$B/skillctl" publish --attest wire-freeze-canary --registry "local://$B/registry.git" \
//	   --version 1.0.0 --digest <that digest> --level green --rationale "fixture attestation" \
//	   --key "$B/k.priv" --identity id:fixture@m3c --yes --no-checkpoint
//	"$B/skillctl" registry export --registry "local://$B/registry.git" \
//	   --out cmd/skillctl/testdata/wireformat/skillctl-<OLD>-registry.bundle
//	git worktree remove "$W" --force
//
// Then refresh the pins below from that run: fixtureBundleDigest is the digest
// publish printed, fixtureManifestDigest is bundle_digest from pack, and the key
// pins are the base64 of the raw 32 key bytes inside "$B/k.pub" plus its sha256,
// which the admitted event records verbatim as pubkey_fingerprint.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
	_ "github.com/kamir/m3c-tools/pkg/skillctl/backend/git" // registers the local:// scheme
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

// The pins: what the older release actually wrote. None of these may be
// recomputed from the fixture at test time, because a value read back out of the
// bytes under test follows a drift instead of catching it.
const (
	fixtureRegistryBundle = "testdata/wireformat/skillctl-v0.4.0-registry.bundle"
	fixtureProducer       = "skillctl/v0.4.0"
	fixtureSkillName      = "wire-freeze-canary"
	fixtureSkillVersion   = "1.0.0"

	// fixtureBundleDigest is sha256 over the .skb bytes: the bundle identity the
	// admitted event is signed over.
	fixtureBundleDigest = "sha256:816f4fe8f780acb547c99fe77739116179ed6dde8fa932d3f39f2ffda8aa1fe2"
	// fixtureManifestDigest is bundle_digest inside bundle.json: the canonical
	// archive hash pack computed. It is a different number by construction.
	fixtureManifestDigest = "sha256:35296619be88012b1e532f3b9d310aa58307d31e77f0dddd9b5bd0ef259eab8e"
	fixtureSkbBytes       = 777

	fixturePubKeyB64   = "FjGBf5D9iEzFu27s1jJ0RihVPI7UfTqNGHMPVElQ8hQ="
	fixtureFingerprint = "sha256:e903ba4d7b0315a951cd7a7cff990094f123e31ddf866061da21489878855fbd"
)

// fixtureSpec copies the committed bundle into a temp dir and returns its
// local:// spec. The copy is not cosmetic: the backend clones from this path, and
// a test must never be able to touch the frozen bytes in testdata/.
func fixtureSpec(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile(fixtureRegistryBundle)
	if err != nil {
		t.Fatalf("read fixture %s: %v", fixtureRegistryBundle, err)
	}
	dst := filepath.Join(t.TempDir(), "registry.bundle")
	if err := os.WriteFile(dst, src, 0o644); err != nil {
		t.Fatalf("copy fixture: %v", err)
	}
	return "local://" + dst
}

// fixturePeer pins a key against the fixture registry, which is how a real
// consumer anchors a peer (SPEC-0359 D2). AsTrustRoots refuses a fingerprint that
// does not match the key, so a wrong pin cannot silently pass.
func fixturePeer(t *testing.T, spec, pubB64, fingerprint string) *registry.SelfTrustRoots {
	t.Helper()
	p := registry.Peer{
		Name:              "wire-freeze-fixture",
		Locator:           spec,
		PubKeyB64:         pubB64,
		Fingerprint:       fingerprint,
		GovernanceMinimum: "green",
	}
	tr, err := p.AsTrustRoots()
	if err != nil {
		t.Fatalf("pin fixture key: %v", err)
	}
	return tr
}

// hermeticHome points every per-user trust path (bundle cache, install-token key,
// trust roots, peers file) at a temp dir. An ambient registry masking a trust
// decision is exactly how H-F1 slipped past two adversarial reviews.
func hermeticHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("M3C_SKILL_CACHE_DIR", filepath.Join(home, "cache", "m3c", "skill-bundles"))
	return home
}

// describeSkips renders the gauntlet's rejections readably. Without it a break
// reports a slice of pointers, and the one thing the reader needs, WHICH gate
// refused the old bytes and why, is the thing that is missing.
func describeSkips(skips []*registry.PullSkip) string {
	if len(skips) == 0 {
		return "  (none: the fixture events were not found at all)"
	}
	var b strings.Builder
	for _, s := range skips {
		fmt.Fprintf(&b, "  %s@%s %s: gate=%v detail=%s\n", s.Name, s.Version, s.Digest, s.Gate, s.Detail)
	}
	return b.String()
}

// TestWireFormatOlderReleaseStillReadable is the N-1 read guarantee from
// COMPATIBILITY.md, made mechanical. It runs the full SPEC-0188 section 7
// gauntlet of the CURRENT build against bytes an OLDER build wrote, then
// installs from them offline.
//
// What breaks it: a renamed path in the registry layout, a renamed or dropped
// field in the SPEC-0190 admitted or attestation event, a change to the envelope
// signature canonicalization, a change to the digest derivation, a change to the
// .skb archive layout, its manifest schema or its CHECKSUMS format. Each of those
// is a wire-format break and each is invisible to a writer-plus-reader test on
// one build.
func TestWireFormatOlderReleaseStillReadable(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	hermeticHome(t)
	ctx := context.Background()

	spec := fixtureSpec(t)
	be, err := artifact.Open(spec, artifact.OpenOptions{})
	if err != nil {
		t.Fatalf("open the %s fixture registry: %v", fixtureProducer, err)
	}
	defer be.Close()

	// Gate 1 to gate 5 against the pinned key. Passing gate 4 proves the OLD
	// attestation event was found, parsed and signature-verified too: the floor is
	// never satisfied by the admit event's author_intent.
	res, err := registry.PullBundlesFromBackend(ctx, be, fixturePeer(t, spec, fixturePubKeyB64, fixtureFingerprint), registry.PullOpts{})
	if err != nil {
		t.Fatalf("verifying pull over the %s fixture: %v", fixtureProducer, err)
	}
	if len(res.Staged) != 1 {
		t.Fatalf("the %s fixture must stage exactly 1 bundle; staged=%d warnings=%v; rejections:\n%s",
			fixtureProducer, len(res.Staged), res.Warnings, describeSkips(res.Skipped))
	}
	sb := res.Staged[0]
	if sb.Name != fixtureSkillName || sb.Version != fixtureSkillVersion || sb.Digest != fixtureBundleDigest {
		t.Errorf("staged identity drifted: got %s@%s %s, want %s@%s %s",
			sb.Name, sb.Version, sb.Digest, fixtureSkillName, fixtureSkillVersion, fixtureBundleDigest)
	}
	if sb.Governance != "green" {
		t.Errorf("attested governance level = %q, want green (the old attestation event no longer reads)", sb.Governance)
	}

	t.Run("wrong pinned key stages nothing", func(t *testing.T) {
		// The negative control. Without it a permissive reader would look exactly
		// like a compatible one: every assertion above would pass while the pull
		// verified nothing. A freshly generated key is correctly pinned (its own
		// fingerprint), so AsTrustRoots is satisfied and only the signature check
		// can reject the bundle.
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(pub)
		impostor := registry.Peer{
			Name:              "impostor",
			Locator:           spec,
			PubKeyB64:         base64.StdEncoding.EncodeToString(pub),
			Fingerprint:       "sha256:" + hex.EncodeToString(sum[:]),
			GovernanceMinimum: "green",
		}
		roots, err := impostor.AsTrustRoots()
		if err != nil {
			t.Fatalf("pin the control key: %v", err)
		}
		out, err := registry.PullBundlesFromBackend(ctx, be, roots, registry.PullOpts{})
		if err != nil {
			t.Fatalf("a pull with the wrong key must reject, not error: %v", err)
		}
		if len(out.Staged) != 0 {
			t.Fatalf("a wrong pinned key staged %d bundle(s): the pull is not verifying anything", len(out.Staged))
		}
	})

	t.Run("skb bytes are the frozen bytes", func(t *testing.T) {
		skb, err := os.ReadFile(sb.StagedSkbPath)
		if err != nil {
			t.Fatalf("read staged .skb: %v", err)
		}
		if len(skb) != fixtureSkbBytes {
			t.Errorf("staged .skb is %d bytes, want the frozen %d", len(skb), fixtureSkbBytes)
		}
		sum := sha256.Sum256(skb)
		if got := "sha256:" + hex.EncodeToString(sum[:]); got != fixtureBundleDigest {
			t.Errorf("staged .skb hashes to %s, want %s", got, fixtureBundleDigest)
		}
	})

	t.Run("skb manifest is still parseable", func(t *testing.T) {
		// The .skb archive is the load-bearing compatibility surface named in
		// COMPATIBILITY.md. Reading it here is what turns "schema is the gate
		// point" from a claim into a check.
		skb, err := os.ReadFile(sb.StagedSkbPath)
		if err != nil {
			t.Fatalf("read staged .skb: %v", err)
		}
		entries, err := skillbundle.Unpack(skb, skillbundle.UnpackOptions{})
		if err != nil {
			t.Fatalf("the current unpacker cannot read a %s .skb: %v", fixtureProducer, err)
		}
		var manifest, skillmd, checksums bool
		var m skillbundle.BundleManifest
		for _, e := range entries {
			switch e.Rel {
			case "bundle.json":
				manifest = true
				if err := json.Unmarshal(e.Content, &m); err != nil {
					t.Fatalf("bundle.json from %s no longer unmarshals: %v", fixtureProducer, err)
				}
			case "SKILL.md":
				skillmd = true
			case "CHECKSUMS":
				checksums = true
			}
		}
		if !manifest || !skillmd || !checksums {
			t.Fatalf("frozen archive members missing: bundle.json=%v SKILL.md=%v CHECKSUMS=%v", manifest, skillmd, checksums)
		}
		if m.Schema != skillbundle.Schema {
			t.Errorf("fixture schema %q is no longer the current %q: a schema bump needs a MAJOR release and a reader that still accepts v1",
				m.Schema, skillbundle.Schema)
		}
		if m.Name != fixtureSkillName || m.Version != fixtureSkillVersion || m.BundleDigest != fixtureManifestDigest {
			t.Errorf("manifest drifted: got %s@%s %s, want %s@%s %s",
				m.Name, m.Version, m.BundleDigest, fixtureSkillName, fixtureSkillVersion, fixtureManifestDigest)
		}
	})

	t.Run("installs offline from the old fixture", func(t *testing.T) {
		// The end of the chain, and the only step that proves the CHECKSUMS format
		// still reads: installOne runs skillbundle.ValidateChecksums over the
		// extracted tree before anything is written into place.
		skillsDir := filepath.Join(t.TempDir(), "skills")
		results, err := registry.ConfirmInstall([]*registry.StagedBundle{sb}, "", registry.InstallOpts{
			StagedSkbPath:         sb.StagedSkbPath,
			Bundle:                sb,
			SkillsDir:             skillsDir,
			TrustRootsFingerprint: fixtureFingerprint,
			RegistrySpec:          spec,
		})
		if err != nil {
			t.Fatalf("install a %s bundle with the current build: %v", fixtureProducer, err)
		}
		if len(results) != 1 || !results[0].CreatedFresh {
			t.Fatalf("install result = %+v, want one freshly created skill", results)
		}
		if _, err := os.Stat(filepath.Join(skillsDir, fixtureSkillName, "SKILL.md")); err != nil {
			t.Errorf("installed skill has no SKILL.md: %v", err)
		}
		sidecar := filepath.Join(skillsDir, fixtureSkillName, registry.ProvenanceSidecarName)
		raw, err := os.ReadFile(sidecar)
		if err != nil {
			t.Fatalf("read provenance sidecar: %v", err)
		}
		var side registry.ProvenanceSidecar
		if err := json.Unmarshal(raw, &side); err != nil {
			t.Fatalf("provenance sidecar not valid JSON: %v", err)
		}
		if side.BundleDigest != fixtureBundleDigest {
			t.Errorf("sidecar bundle_digest = %q, want %q", side.BundleDigest, fixtureBundleDigest)
		}
	})
}
