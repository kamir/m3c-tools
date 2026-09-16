package registry

// Re-gate R1/RG-1 (PR #319): the backend carrier built StagedBundle without
// Kind. The installOne tag-vs-manifest guard skips itself on an empty Kind and
// PlanInstall then targets skills/, while the write would route to agents/ by
// the manifest: the plan a human approves would not name the write. Since the
// fix, PullBundlesFromBackend reads the manifest out of the digest-verified
// bytes (fail-closed) and stamps StagedBundle.Kind from it.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillbundle"
	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
)

// fakeEventBackend is the minimal Backend+GovernanceLog the backend gauntlet
// touches: Events, Fetch, Describe. The rest is never called by
// PullBundlesFromBackend and fails loudly if that ever changes.
type fakeEventBackend struct {
	events []artifact.EventRecord
	blobs  map[string][]byte // digest → skb bytes
}

func (f *fakeEventBackend) Describe() artifact.Descriptor { return artifact.Descriptor{Scheme: "fake"} }
func (f *fakeEventBackend) Publish(context.Context, artifact.PublishRequest) (*artifact.PublishResult, error) {
	return nil, errors.New("fake: Publish unused")
}
func (f *fakeEventBackend) List(context.Context, artifact.ListFilter, artifact.Page) (*artifact.Listing, error) {
	return nil, errors.New("fake: List unused")
}
func (f *fakeEventBackend) Resolve(context.Context, artifact.RefQuery) (*artifact.ArtifactRef, error) {
	return nil, errors.New("fake: Resolve unused")
}
func (f *fakeEventBackend) Fetch(_ context.Context, ref artifact.ArtifactRef) ([]byte, error) {
	b, ok := f.blobs[ref.Digest]
	if !ok {
		return nil, fmt.Errorf("fake: no blob for %s", ref.Digest)
	}
	return b, nil
}
func (f *fakeEventBackend) Close() error { return nil }
func (f *fakeEventBackend) Events(context.Context, artifact.ListFilter, artifact.Page) (*artifact.EventPage, error) {
	return &artifact.EventPage{Events: f.events}, nil
}

// seedSignedBundle admits + attests skb into the fake backend, signed by priv.
func seedSignedBundle(t *testing.T, f *fakeEventBackend, priv ed25519.PrivateKey, name, ver string, skb []byte) string {
	t.Helper()
	d := sha256.Sum256(skb)
	digest := "sha256:" + hex.EncodeToString(d[:])
	sigB64 := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, d[:]))
	fp := selfFingerprint(priv.Public().(ed25519.PublicKey))

	admit, err := BuildBundleAdmittedEvent(AdmittedEventInput{
		BundleDigest: digest, Name: name, Version: ver, AuthorIntent: "green",
		AdmittedByIdentity: "id:test@m3c", AdmittedAt: testTime(),
		Signatures: []SignatureRef{
			{Role: "author", IdentityID: "id:test@m3c", SignatureB64: sigB64, PubKeyFingerprint: fp},
			{Role: "registry", IdentityID: "id:test@m3c", SignatureB64: sigB64, PubKeyFingerprint: fp},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignEnvelopeSignature(priv, admit); err != nil {
		t.Fatal(err)
	}
	attest, err := BuildAttestationPublishedEvent(AttestedEventInput{
		BundleDigest: digest, ReviewerID: "id:test@m3c", GovernanceLevel: "green", OccurredAt: testTime(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignEnvelopeSignature(priv, attest); err != nil {
		t.Fatal(err)
	}
	f.events = append(f.events,
		artifact.EventRecord{Kind: artifact.KindAdmit, Digest: digest, Envelope: admit},
		artifact.EventRecord{Kind: artifact.KindAttest, Digest: digest, Envelope: attest},
	)
	if f.blobs == nil {
		f.blobs = map[string][]byte{}
	}
	f.blobs[digest] = skb
	return digest
}

// TestBackendPullStampsKindFromManifest: an agent .skb pulled over the backend
// carrier stages with Kind agent, and the G-23 plan names agents/<name>.md.
// Counter-probe: a skill bundle through the same path plans skills/<name>.
func TestBackendPullStampsKindFromManifest(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	tr, err := LoadSelfTrustRoots(writeTrustRoots(t, pub))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("M3C_SKILL_CACHE_DIR", t.TempDir())

	f := &fakeEventBackend{}
	agentSkb := makeAgentSkb(t, "plan-agent", nil, skillbundle.SchemaAgent, skillbundle.KindAgent)
	seedSignedBundle(t, f, priv, "plan-agent", "1.0.0", agentSkb)

	res, err := PullBundlesFromBackend(context.Background(), f, tr, PullOpts{})
	if err != nil {
		t.Fatalf("PullBundlesFromBackend: %v", err)
	}
	if len(res.Staged) != 1 || len(res.Skipped) != 0 {
		t.Fatalf("staged=%+v skipped=%+v, want 1/0", res.Staged, res.Skipped)
	}
	if res.Staged[0].Kind != skillbundle.KindAgent {
		t.Fatalf("staged kind = %q, want %q", res.Staged[0].Kind, skillbundle.KindAgent)
	}

	skillsDir := filepath.Join(t.TempDir(), ".claude", "skills")
	plan, err := PlanInstall(res.Staged, skillsDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Creates) != 1 {
		t.Fatalf("plan creates = %+v", plan.Creates)
	}
	wantTarget := filepath.Join(agentsDirFor(skillsDir), "plan-agent.md")
	if plan.Creates[0].SkillPath != wantTarget {
		t.Fatalf("plan targets %q, want %q (agents/, not skills/)", plan.Creates[0].SkillPath, wantTarget)
	}

	// Counter-probe: a skill bundle plans into skills/<name>.
	f2 := &fakeEventBackend{}
	skillSkb := makeAgentSkb(t, "plain-skill", map[string]string{"SKILL.md": "# s\n"}, skillbundle.Schema, "")
	seedSignedBundle(t, f2, priv, "plain-skill", "1.0.0", skillSkb)
	res2, err := PullBundlesFromBackend(context.Background(), f2, tr, PullOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.Staged) != 1 {
		t.Fatalf("skill counter-probe: staged=%+v skipped=%+v", res2.Staged, res2.Skipped)
	}
	plan2, err := PlanInstall(res2.Staged, skillsDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan2.Creates) != 1 || plan2.Creates[0].SkillPath != filepath.Join(skillsDir, "plain-skill") {
		t.Fatalf("skill plan = %+v, want target %q", plan2.Creates, filepath.Join(skillsDir, "plain-skill"))
	}
}

// TestBackendPullRefusesManifestlessBundle: bytes that pass digest and
// signature gates but carry no readable manifest are refused, because without
// the manifest the kind is unknown and the plan could not name the target.
func TestBackendPullRefusesManifestlessBundle(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	tr, err := LoadSelfTrustRoots(writeTrustRoots(t, pub))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("M3C_SKILL_CACHE_DIR", t.TempDir())

	f := &fakeEventBackend{}
	seedSignedBundle(t, f, priv, "raw-bytes", "1.0.0", []byte("NOT-A-BUNDLE"))

	res, err := PullBundlesFromBackend(context.Background(), f, tr, PullOpts{})
	if err != nil {
		t.Fatalf("PullBundlesFromBackend: %v", err)
	}
	if len(res.Staged) != 0 {
		t.Fatalf("a manifest-less bundle staged: %+v", res.Staged)
	}
	if len(res.Skipped) != 1 || !errors.Is(res.Skipped[0].Gate, ErrBundleManifest) {
		t.Fatalf("expected ErrBundleManifest, got skipped=%+v", res.Skipped)
	}
	if !strings.Contains(res.Skipped[0].Gate.Error(), "kind unknown") {
		t.Errorf("refusal %q does not say why the kind matters", res.Skipped[0].Gate.Error())
	}
}
