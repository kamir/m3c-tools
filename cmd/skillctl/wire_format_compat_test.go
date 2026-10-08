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
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

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
// TestWireFormatOlderReleaseReachesTheDigestGate replaces what this file used
// to assert, and the replacement is the point rather than a concession.
//
// Until v0.6.x the test required the v0.4.0 fixture to STAGE, which pinned the
// COMPATIBILITY.md promise that a reader accepts bundles from the current and
// the previous MINOR. ADR-0047 ends that promise for bundles: the digest now
// covers the canonical tar, every pre-v0.7.0 digest is a hash over gzip output,
// and no reader can recompute it. The owner decided that on 2026-10-08, with no
// migration path, because only v1.0.x goes to customers.
//
// What a frozen byte fixture can still prove is therefore narrower, and it is
// worth keeping: the OLD CARRIER still parses. Reaching the digest gate at all
// means the registry store opened, the admit event was found, its envelope was
// read and its declared digest extracted. A break anywhere in that chain shows
// up here as a different gate or an error, not as a staged bundle.
//
// It also pins the REFUSAL ITSELF: an old bundle must be refused by name, not
// with a bare digest mismatch that reads like tampering.
func TestWireFormatOlderReleaseReachesTheDigestGate(t *testing.T) {
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

	res, err := registry.PullBundlesFromBackend(ctx, be, fixturePeer(t, spec, fixturePubKeyB64, fixtureFingerprint), registry.PullOpts{})
	if err != nil {
		t.Fatalf("verifying pull over the %s fixture: %v", fixtureProducer, err)
	}
	if len(res.Staged) != 0 {
		t.Fatalf("a pre-ADR-0047 bundle staged; its digest cannot be recomputed by this build: %+v", res.Staged)
	}
	if len(res.Skipped) != 1 {
		t.Fatalf("the %s fixture must be refused exactly once; skipped=%d:\n%s",
			fixtureProducer, len(res.Skipped), describeSkips(res.Skipped))
	}
	skip := res.Skipped[0]
	if !errors.Is(skip.Gate, registry.ErrGateDigest) {
		t.Errorf("refused at %v, want the digest gate: reaching a LATER gate would mean the digest was recomputed, an EARLIER one that the old carrier no longer parses", skip.Gate)
	}
	if skip.Name != fixtureSkillName || skip.Version != fixtureSkillVersion {
		t.Errorf("refused identity = %s@%s, want %s@%s: the old event still has to parse",
			skip.Name, skip.Version, fixtureSkillName, fixtureSkillVersion)
	}
	if skip.Digest != fixtureBundleDigest {
		t.Errorf("the declared digest read back as %s, want the frozen %s", skip.Digest, fixtureBundleDigest)
	}
	// The sentence a human gets. Without this the refusal is indistinguishable
	// from a tampered download, which is the confusion COMPATIBILITY.md names as
	// the reason for a schema marker in the first place.
	if !strings.Contains(skip.Detail, "retired schema") || !strings.Contains(skip.Detail, "re-packed") {
		t.Errorf("the refusal does not say WHY in words a reader can act on: %q", skip.Detail)
	}
}
