package registry

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"
)

// signedRevokeHead builds + signs a revocation HEAD committing to `digests` with
// `emergency` as the inline burn list, so a test can serve it via the
// pullRevocationHeadFetch seam.
func signedRevokeHead(t *testing.T, priv ed25519.PrivateKey, digests, emergency []string) map[string]any {
	t.Helper()
	head, err := BuildRevocationHead(RevocationHeadInput{
		Epoch:     1,
		IssuedAt:  testTime(),
		Digests:   digests,
		Emergency: emergency,
	})
	if err != nil {
		t.Fatalf("BuildRevocationHead: %v", err)
	}
	if _, err := SignEnvelopeSignature(priv, head); err != nil {
		t.Fatalf("sign head: %v", err)
	}
	return head
}

// TestPullBundles_RevokeAbsentFromDiscovery_ButOnSignedHead_RejectsAtGate5 is the
// FR-0090 IS-RS-01 bite. A signed revoke for digest X is ABSENT from tag discovery
// (a hostile/compromised tenant stripped/aged/flooded it out of the searchByTags
// window) so it never enters the accumulator — acc.IsRevoked(X) is false. But X is
// named on the SIGNED revocation HEAD (emergency burn list + committed
// revoked_set_root). PullBundles must STILL refuse X at Gate 5.
//
// Pre-fix (no HEAD consultation) PullBundles built Gate 5 only from discovery, so
// X — cleanly admitted + attested — STAGED. Post-fix the verified HEAD both names
// X on the emergency list AND fails the set-root binding (discovered revoked set
// is empty, HEAD commits to {X}), so the pull fails closed.
func TestPullBundles_RevokeAbsentFromDiscovery_ButOnSignedHead_RejectsAtGate5(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	f := newPullFake(t)

	// X is admitted + attested (clears gates 1-4). NO revoke item is published, so
	// tag discovery finds no revoke for X — modelling the omission attack.
	admit, digest := mintAdmitItem(t, priv, "victim", "1.0.0", "PRETEND-SKB")
	attest := mintAttestItem(t, priv, "victim", "1.0.0", digest, "green", "ok")
	f.addItem(admit)
	f.addItem(attest)

	trPath := writeTrustRoots(t, pub)
	tr, err := LoadSelfTrustRoots(trPath)
	if err != nil {
		t.Fatalf("trust-roots: %v", err)
	}
	t.Setenv("M3C_SKILL_CACHE_DIR", t.TempDir())

	// Serve a SIGNED HEAD that names X (absent from discovery) via the fetch seam.
	head := signedRevokeHead(t, priv, []string{digest}, []string{digest})
	orig := pullRevocationHeadFetch
	pullRevocationHeadFetch = func(_, _ string, _ time.Duration) (map[string]any, error) {
		return head, nil
	}
	t.Cleanup(func() { pullRevocationHeadFetch = orig })

	res, err := PullBundles(f.cfg(), "skills", tr, PullOpts{
		RevocationHeadURL: "https://registry.example/api/skills",
	})
	if err != nil {
		t.Fatalf("PullBundles: %v", err)
	}
	if len(res.Staged) != 0 {
		t.Fatalf("a digest named on the signed revoke HEAD but absent from discovery must NOT stage; staged=%+v", res.Staged)
	}
	if len(res.Skipped) != 1 || !errors.Is(res.Skipped[0].Gate, ErrGateRevoked) {
		t.Fatalf("expected ErrGateRevoked (HEAD caught the omitted revoke), got skipped=%+v", res.Skipped)
	}
	if !strings.Contains(res.Skipped[0].Detail, "IS-RS-01") {
		t.Errorf("skip detail should attribute IS-RS-01, got %q", res.Skipped[0].Detail)
	}
}

// signedRevokeHeadEpoch is signedRevokeHead with an explicit epoch, for the
// replay/rollback bite (a validly-signed but OLD head).
func signedRevokeHeadEpoch(t *testing.T, priv ed25519.PrivateKey, epoch int, digests, emergency []string) map[string]any {
	t.Helper()
	head, err := BuildRevocationHead(RevocationHeadInput{
		Epoch:     epoch,
		IssuedAt:  testTime(),
		Digests:   digests,
		Emergency: emergency,
	})
	if err != nil {
		t.Fatalf("BuildRevocationHead: %v", err)
	}
	if _, err := SignEnvelopeSignature(priv, head); err != nil {
		t.Fatalf("sign head: %v", err)
	}
	return head
}

// TestPullBundles_ReplayedStaleHead_RejectedByEpochFloor is the challenge-gate bite
// for the IS-RS-01 replay gap. A hostile tenant strips X's revoke from discovery AND
// serves a genuinely-signed OLD head (epoch 0, from before X was revoked, empty
// revoked set) instead of the current one. A signature-only check accepted it — its
// stale empty root matched the truncated (empty) discovery, so X staged. With the
// epoch floor (the client already accepted epoch 5), the replayed epoch-0 head is a
// rollback → the pull fails closed and X is refused.
func TestPullBundles_ReplayedStaleHead_RejectedByEpochFloor(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	f := newPullFake(t)

	admit, digest := mintAdmitItem(t, priv, "victim", "1.0.0", "PRETEND-SKB")
	attest := mintAttestItem(t, priv, "victim", "1.0.0", digest, "green", "ok")
	f.addItem(admit)
	f.addItem(attest)
	_ = digest

	trPath := writeTrustRoots(t, pub)
	tr, err := LoadSelfTrustRoots(trPath)
	if err != nil {
		t.Fatalf("trust-roots: %v", err)
	}
	t.Setenv("M3C_SKILL_CACHE_DIR", t.TempDir())

	// The attacker replays a validly-signed GENESIS head (epoch 0, empty set) that
	// predates X's revoke — it does NOT name X.
	stale := signedRevokeHeadEpoch(t, priv, 0, nil, nil)
	orig := pullRevocationHeadFetch
	pullRevocationHeadFetch = func(_, _ string, _ time.Duration) (map[string]any, error) {
		return stale, nil
	}
	t.Cleanup(func() { pullRevocationHeadFetch = orig })

	res, err := PullBundles(f.cfg(), "skills", tr, PullOpts{
		RevocationHeadURL:        "https://registry.example/api/skills",
		RevocationHeadFloorEpoch: 5, // client already accepted a newer head
	})
	if err != nil {
		t.Fatalf("PullBundles: %v", err)
	}
	if len(res.Staged) != 0 {
		t.Fatalf("a replayed stale (rolled-back) HEAD must not let an omitted revoke stage; staged=%+v", res.Staged)
	}
	if len(res.Skipped) != 1 || !errors.Is(res.Skipped[0].Gate, ErrGateRevoked) {
		t.Fatalf("expected ErrGateRevoked from the epoch-rollback fail-closed, got skipped=%+v", res.Skipped)
	}
	low := strings.ToLower(res.Skipped[0].Detail)
	if !strings.Contains(low, "rolled back") && !strings.Contains(low, "rollback") {
		t.Errorf("skip detail should attribute the rollback, got %q", res.Skipped[0].Detail)
	}
}

// TestPullBundles_NoHeadConfigured_StillStages is the never-regress control: with
// no HEAD URL configured and a small (uncapped) discovery page, PullBundles behaves
// exactly as before — a clean, attested, non-revoked bundle STAGES. This proves the
// IS-RS-01 gate is inert on the default self-ER1 host that pins no revoke HEAD.
func TestPullBundles_NoHeadConfigured_StillStages(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	f := newPullFake(t)
	admit, digest := mintAdmitItem(t, priv, "ok-skill", "1.0.0", "SKB")
	f.addItem(admit)
	f.addItem(mintAttestItem(t, priv, "ok-skill", "1.0.0", digest, "green", "ok"))

	trPath := writeTrustRoots(t, pub)
	tr, _ := LoadSelfTrustRoots(trPath)
	t.Setenv("M3C_SKILL_CACHE_DIR", t.TempDir())

	res, err := PullBundles(f.cfg(), "skills", tr, PullOpts{}) // no RevocationHeadURL
	if err != nil {
		t.Fatalf("PullBundles: %v", err)
	}
	if len(res.Staged) != 1 || len(res.Skipped) != 0 {
		t.Fatalf("clean bundle must stage with no HEAD configured; staged=%+v skipped=%+v", res.Staged, res.Skipped)
	}
}

// TestPullBundles_RequireHeadUnreachable_FailsClosed proves the IS-T5-mirroring
// freshness policy: when the HEAD is REQUIRED (managed enterprise root) but the
// fetch fails, the pull fails closed for every candidate rather than trust a
// discovery-only revoked set.
func TestPullBundles_RequireHeadUnreachable_FailsClosed(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	f := newPullFake(t)
	admit, digest := mintAdmitItem(t, priv, "svc", "1.0.0", "SKB")
	f.addItem(admit)
	f.addItem(mintAttestItem(t, priv, "svc", "1.0.0", digest, "green", "ok"))

	trPath := writeTrustRoots(t, pub)
	tr, _ := LoadSelfTrustRoots(trPath)
	t.Setenv("M3C_SKILL_CACHE_DIR", t.TempDir())

	orig := pullRevocationHeadFetch
	pullRevocationHeadFetch = func(_, _ string, _ time.Duration) (map[string]any, error) {
		return nil, errors.New("registry unreachable")
	}
	t.Cleanup(func() { pullRevocationHeadFetch = orig })

	res, err := PullBundles(f.cfg(), "skills", tr, PullOpts{
		RevocationHeadURL:     "https://registry.example/api/skills",
		RequireRevocationHead: true,
	})
	if err != nil {
		t.Fatalf("PullBundles: %v", err)
	}
	if len(res.Staged) != 0 {
		t.Fatalf("a REQUIRED-but-unreachable HEAD must fail the pull closed; staged=%+v", res.Staged)
	}
	if len(res.Skipped) != 1 || !errors.Is(res.Skipped[0].Gate, ErrGateRevoked) {
		t.Fatalf("expected ErrGateRevoked (fail-closed), got skipped=%+v", res.Skipped)
	}
}
