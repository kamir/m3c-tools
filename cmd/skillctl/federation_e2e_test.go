package main

// SPEC-0359 §8 — offline federation end-to-end. Two local:// registries prove the
// whole D1→D5 chain compose without any network: node A publishes + attests a
// signed skill; node B PINS A as a peer and its verifying pull succeeds against
// A's key but FAILS against a wrong key (D2); A revokes; a re-pull is denied at
// gate-5 and `revoke feed --gossip` propagates the revoke into B's durable set
// (D5(b)). Uses only exported APIs + the real git backend via local://.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
	backendgit "github.com/kamir/m3c-tools/pkg/skillctl/backend/git"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

func fpOf(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return "sha256:" + hex.EncodeToString(h[:])
}

// publishSignedSkill admits + attests a gauntlet-passing bundle into `be`, signed
// by priv (playing author+registry+reviewer for the test). Returns the digest.
func publishSignedSkill(t *testing.T, be artifact.Backend, priv ed25519.PrivateKey, name, ver, body string) string {
	t.Helper()
	ctx := context.Background()
	skb := []byte(body)
	db := sha256.Sum256(skb)
	digest := "sha256:" + hex.EncodeToString(db[:])
	sigB64 := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, db[:])) // over the digest bytes → gate-3
	fp := fpOf(priv.Public().(ed25519.PublicKey))
	meta := artifact.ArtifactMeta{Name: name, Version: ver, Digest: digest}

	admit, err := registry.BuildBundleAdmittedEvent(registry.AdmittedEventInput{
		BundleDigest: digest, Name: name, Version: ver, AuthorIntent: "green",
		AdmittedByIdentity: "id:a@org", AdmittedAt: time.Now().UTC(),
		Signatures: []registry.SignatureRef{
			{Role: "author", IdentityID: "id:a@org", SignatureB64: sigB64, PubKeyFingerprint: fp},
			{Role: "registry", IdentityID: "id:a@org", SignatureB64: sigB64, PubKeyFingerprint: fp},
		},
	})
	if err != nil {
		t.Fatalf("build admit: %v", err)
	}
	if _, err := registry.SignEnvelopeSignature(priv, admit); err != nil {
		t.Fatal(err)
	}
	if _, err := be.Publish(ctx, artifact.PublishRequest{Kind: artifact.KindAdmit, Event: admit, Meta: meta, Blob: skb}); err != nil {
		t.Fatalf("publish admit: %v", err)
	}

	attest, err := registry.BuildAttestationPublishedEvent(registry.AttestedEventInput{
		BundleDigest: digest, ReviewerID: "id:a@org", GovernanceLevel: "green", OccurredAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.SignEnvelopeSignature(priv, attest); err != nil {
		t.Fatal(err)
	}
	if _, err := be.Publish(ctx, artifact.PublishRequest{Kind: artifact.KindAttest, Event: attest, Meta: meta}); err != nil {
		t.Fatalf("publish attest: %v", err)
	}
	return digest
}

func TestFederationEndToEnd(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	ctx := context.Background()

	// Node A's registry key + a local:// registry.
	pubA, privA, _ := ed25519.GenerateKey(rand.Reader)
	specA := "local://" + filepath.Join(t.TempDir(), "regA.git")
	if _, err := backendgit.InitLocalRegistry(specA); err != nil {
		t.Fatalf("init regA: %v", err)
	}
	beA, err := artifact.Open(specA, artifact.OpenOptions{})
	if err != nil {
		t.Fatalf("open regA: %v", err)
	}
	defer beA.Close()

	digest := publishSignedSkill(t, beA, privA, "fedskill", "1.0.0", "SKB:fedskill body")

	// D2: node B pins A as a peer → verifying pull succeeds against A's key.
	peerA := registry.Peer{Name: "A", Locator: specA, PubKeyB64: base64.StdEncoding.EncodeToString(pubA), Fingerprint: fpOf(pubA), GovernanceMinimum: "green"}
	trA, err := peerA.AsTrustRoots()
	if err != nil {
		t.Fatalf("peer A AsTrustRoots: %v", err)
	}
	res, err := registry.PullBundlesFromBackend(ctx, beA, trA, registry.PullOpts{})
	if err != nil {
		t.Fatalf("pull from A: %v", err)
	}
	if len(res.Staged) != 1 || res.Staged[0].Digest != digest {
		t.Fatalf("verifying pull should stage fedskill: staged=%d skipped=%d", len(res.Staged), len(res.Skipped))
	}

	// D2 negative: a WRONG pinned key must verify NOTHING (pinning is load-bearing).
	pubX, _, _ := ed25519.GenerateKey(rand.Reader)
	peerX := registry.Peer{Name: "X", Locator: specA, PubKeyB64: base64.StdEncoding.EncodeToString(pubX), Fingerprint: fpOf(pubX), GovernanceMinimum: "green"}
	trX, _ := peerX.AsTrustRoots()
	resX, err := registry.PullBundlesFromBackend(ctx, beA, trX, registry.PullOpts{})
	if err != nil {
		t.Fatalf("pull with wrong key: %v", err)
	}
	if len(resX.Staged) != 0 {
		t.Errorf("a wrong pinned key must stage nothing, staged %d", len(resX.Staged))
	}

	// A revokes fedskill (signed).
	rev, err := registry.BuildBundleRevokedEvent(registry.RevokedEventInput{BundleDigest: digest, RevokedBy: "id:a@org", OccurredAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.SignEnvelopeSignature(privA, rev); err != nil {
		t.Fatal(err)
	}
	if _, err := beA.Publish(ctx, artifact.PublishRequest{Kind: artifact.KindRevoke, Event: rev, Meta: artifact.ArtifactMeta{Name: "fedskill", Version: "1.0.0", Digest: digest}}); err != nil {
		t.Fatalf("publish revoke: %v", err)
	}

	// Gate-5: a re-pull is now DENIED (revoked) — the git registry's revoke is honored.
	res2, err := registry.PullBundlesFromBackend(ctx, beA, trA, registry.PullOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.Staged) != 0 {
		t.Errorf("a revoked bundle must not stage; staged %d", len(res2.Staged))
	}
	revokedSkip := false
	for _, s := range res2.Skipped {
		if s.Digest == digest && errors.Is(s.Gate, registry.ErrGateRevoked) {
			revokedSkip = true
		}
	}
	if !revokedSkip {
		t.Errorf("expected the digest skipped at gate-5 (revoked); skips=%+v", res2.Skipped)
	}

	// D5(b): B gossips A's revoke (A marked --contributes-revokes) → digest unioned
	// into the durable grow-only set.
	peers := &registry.Peers{Peers: []registry.Peer{{
		Name: "A", Locator: specA, PubKeyB64: base64.StdEncoding.EncodeToString(pubA),
		Fingerprint: fpOf(pubA), GovernanceMinimum: "green", ContributesRevokes: true,
	}}}
	union, reports := gossipRevokedDigests(peers)
	if _, ok := union[digest]; !ok {
		t.Fatalf("gossip did not union A's signed revoke: union=%v reports=%+v", union, reports)
	}
	home := t.TempDir()
	if _, err := mergeGossipedRevoked(home, union, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, ok := loadGossipedRevoked(home)[digest]; !ok {
		t.Error("gossiped revoke not persisted to the durable set")
	}

	// A NON-contributor peer's revokes must stay advisory (not unioned).
	advisory := &registry.Peers{Peers: []registry.Peer{{
		Name: "A", Locator: specA, PubKeyB64: base64.StdEncoding.EncodeToString(pubA),
		Fingerprint: fpOf(pubA), GovernanceMinimum: "green", // ContributesRevokes: false
	}}}
	if u, _ := gossipRevokedDigests(advisory); len(u) != 0 {
		t.Errorf("a non-contributor peer's revokes must not be unioned; got %d", len(u))
	}
}
