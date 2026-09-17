package registry

// Challenge-gate F1 (PR #319): the publisher stamps EVERY event of a bundle,
// attest and revoke included, onto the shelf of its kind (SPEC-0432 E-6). The
// pull gauntlet's governance/revoke sweep (loadAttestAccumulator) must
// therefore cover BOTH shelves, exactly like loadAttestRevoke. Against the
// pre-fix code (one shelf, "skill-registry:self" only) direction (a) fails at
// Gate 4 (an agent's attestation is invisible, agents are never pullable
// through the honest flow) and direction (b) stages a REVOKED bundle (the
// revoke lives on the agent shelf, Gate 5 is blind).
//
// Each test carries its own counter-probe (claims rule 4): the same machinery
// on the skill shelf must show the OPPOSITE verdict, proving the assertion
// would detect the failure it claims to detect.

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
)

// onAgentShelf moves a minted registry item onto the agent shelf and stamps
// the kind tag, the way er1_publish's tagPrefixCommon does for Kind "agent".
func onAgentShelf(item map[string]any) map[string]any {
	tags, _ := item["tags"].(string)
	tags = strings.ReplaceAll(tags, SkillShelfTag, AgentShelfTag)
	item["tags"] = tags + "," + KindTagPrefix + "agent"
	return item
}

// Direction (a): an agent admitted, and attested green, entirely on the agent
// shelf passes Gate 4. Counter-probe: the same admit WITHOUT any attestation
// is rejected at Gate 4, so the acceptance above is a real verdict, not a
// gate that stopped judging.
func TestPullBundles_AgentShelfAttestation_SeenByGate4(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	f := newPullFake(t)
	admit, digest := mintAdmitItem(t, priv, "release-agent", "1.0.0", "AGENT-SKB-BYTES")
	attest := mintAttestItem(t, priv, "release-agent", "1.0.0", digest, "green", "ok")
	f.addItem(onAgentShelf(admit))
	f.addItem(onAgentShelf(attest))

	trPath := writeTrustRoots(t, pub)
	tr, err := LoadSelfTrustRoots(trPath)
	if err != nil {
		t.Fatalf("trust-roots: %v", err)
	}
	t.Setenv("M3C_SKILL_CACHE_DIR", t.TempDir())

	res, err := PullBundles(f.cfg(), "skills", tr, PullOpts{})
	if err != nil {
		t.Fatalf("PullBundles: %v", err)
	}
	if len(res.Staged) != 1 || len(res.Skipped) != 0 {
		t.Fatalf("an agent attested on its own shelf must stage: staged=%+v skipped=%+v",
			res.Staged, res.Skipped)
	}
	if res.Staged[0].Kind != "agent" {
		t.Errorf("staged kind = %q, want agent", res.Staged[0].Kind)
	}

	// Counter-probe: same shelf, no attestation anywhere. Gate 4 must reject.
	f2 := newPullFake(t)
	admit2, _ := mintAdmitItem(t, priv, "bare-agent", "1.0.0", "AGENT-SKB-2")
	f2.addItem(onAgentShelf(admit2))
	res2, err := PullBundles(f2.cfg(), "skills", tr, PullOpts{})
	if err != nil {
		t.Fatalf("PullBundles (counter-probe): %v", err)
	}
	if len(res2.Skipped) != 1 || !errors.Is(res2.Skipped[0].Gate, ErrGateGovernance) {
		t.Fatalf("counter-probe: expected ErrGateGovernance for the unattested agent, got staged=%+v skipped=%+v",
			res2.Staged, res2.Skipped)
	}
}

// Direction (b): the attestation sits (without --kind) on the skill shelf, the
// revoke sits regelkonform on the AGENT shelf. Gate 5 must still see it and
// refuse. Counter-probe: without that agent-shelf revoke the very same items
// stage, so the rejection is attributable to the revoke alone.
func TestPullBundles_AgentShelfRevoke_BlocksAtGate5(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	f := newPullFake(t)
	admit, digest := mintAdmitItem(t, priv, "mixed-shelves", "1.0.0", "MIXED-SKB")
	attest := mintAttestItem(t, priv, "mixed-shelves", "1.0.0", digest, "green", "ok")
	revoke := mintRevokeItem(t, priv, "mixed-shelves", "1.0.0", digest, "key-compromise")
	f.addItem(admit)
	f.addItem(attest)
	f.addItem(onAgentShelf(revoke))

	trPath := writeTrustRoots(t, pub)
	tr, err := LoadSelfTrustRoots(trPath)
	if err != nil {
		t.Fatalf("trust-roots: %v", err)
	}
	t.Setenv("M3C_SKILL_CACHE_DIR", t.TempDir())

	res, err := PullBundles(f.cfg(), "skills", tr, PullOpts{})
	if err != nil {
		t.Fatalf("PullBundles: %v", err)
	}
	if len(res.Staged) != 0 {
		t.Fatalf("a bundle whose revoke lives on the agent shelf must NOT stage: staged=%+v", res.Staged)
	}
	if len(res.Skipped) != 1 || !errors.Is(res.Skipped[0].Gate, ErrGateRevoked) {
		t.Fatalf("expected ErrGateRevoked from the agent-shelf revoke, got skipped=%+v", res.Skipped)
	}

	// Counter-probe: identical setup minus the revoke stages cleanly.
	f2 := newPullFake(t)
	admit2, digest2 := mintAdmitItem(t, priv, "mixed-shelves", "2.0.0", "MIXED-SKB-2")
	f2.addItem(admit2)
	f2.addItem(mintAttestItem(t, priv, "mixed-shelves", "2.0.0", digest2, "green", "ok"))
	res2, err := PullBundles(f2.cfg(), "skills", tr, PullOpts{})
	if err != nil {
		t.Fatalf("PullBundles (counter-probe): %v", err)
	}
	if len(res2.Staged) != 1 || len(res2.Skipped) != 0 {
		t.Fatalf("counter-probe: without the revoke the bundle must stage: staged=%+v skipped=%+v",
			res2.Staged, res2.Skipped)
	}
}
