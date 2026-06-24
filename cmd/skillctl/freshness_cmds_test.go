package main

// SPEC-0279 P4 — CLI-level integration tests for the freshness contract on the
// `agentid verify` consumer. They drive the real runner with on-disk ed25519
// keys + a pinned trust-roots file carrying a freshness policy, and assert the
// canonical exit codes (22 stale fail-closed, 17 emergency deny, 12 forged
// checkpoint/emergency). These are the consumer-side AC2/AC3 + the adversarial
// red-team cases (replay-stale, forge/rollback checkpoint, evade emergency,
// downgrade high→low).

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/signing"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// freshFixture extends agentFixture with a freshness policy (max_staleness) and a
// chosen grant-intent risk. It writes its own trust-roots so the freshness fields
// are present.
type freshFixture struct {
	agentFixture
	regPriv ed25519.PrivateKey
}

// buildFreshFixture builds an agentFixture-like scenario with a freshness policy.
// maxStaleness is the trust-root max_staleness ("24h"); failPolicy the low-risk
// disposition ("closed"/"open"); intents the grant intents (drives risk).
func buildFreshFixture(t *testing.T, maxStaleness, failPolicy string) freshFixture {
	t.Helper()
	dir := t.TempDir()

	ownerPub, ownerPriv, _ := ed25519.GenerateKey(rand.Reader)
	regPub, regPriv, _ := ed25519.GenerateKey(rand.Reader)

	ownerKeyPath := filepath.Join(dir, "owner.priv")
	regKeyPath := filepath.Join(dir, "reg.priv")
	writePrivKeyPEM(t, ownerKeyPath, ownerPriv)
	writePrivKeyPEM(t, regKeyPath, regPriv)

	ownerID := "id:kamir@m3c"
	regURL := "https://reg.example/api/skills"

	trPath := filepath.Join(dir, "trust-roots.yaml")
	var b strings.Builder
	b.WriteString("trust_roots:\n")
	b.WriteString("  - registry_url: " + regURL + "\n")
	b.WriteString("    registry_keys:\n")
	b.WriteString("      - id: reg-1\n")
	b.WriteString("        pubkey: " + rawPubB64(regPub) + "\n")
	b.WriteString("    identity_keys_authorized: pinned\n")
	b.WriteString("    governance_minimum: green\n")
	if maxStaleness != "" {
		b.WriteString("    max_staleness: " + maxStaleness + "\n")
	}
	if failPolicy != "" {
		b.WriteString("    fail_policy: " + failPolicy + "\n")
	}
	b.WriteString("    authors:\n")
	b.WriteString("      - id: " + ownerID + "\n")
	b.WriteString("        pubkey: " + rawPubB64(ownerPub) + "\n")
	if err := os.WriteFile(trPath, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write trust-roots: %v", err)
	}

	f := freshFixture{
		agentFixture: agentFixture{
			dir: dir, trPath: trPath, ownerKeyPath: ownerKeyPath, regKeyPath: regKeyPath,
			ownerID: ownerID, regURL: regURL,
		},
		regPriv: regPriv,
	}
	return f
}

// issueGrant issues an AgentID with the given intents (drives the freshness risk
// classification) and a far-future expiry.
func (f freshFixture) issueGrant(t *testing.T, agentID, out, intents string) {
	t.Helper()
	args := []string{
		"--owner", f.ownerID, "--owner-key", f.ownerKeyPath,
		"--agent-id", agentID,
		"--skills", "do-thing@>=1.0.0",
		"--intents", intents,
		"--trust-root", f.regURL,
		"--expires", "2099-12-31T00:00:00Z",
		"--out", filepath.Join(f.dir, out),
	}
	var so, se bytes.Buffer
	if code := runAgentIDIssue(args, &so, &se); code != exitOK {
		t.Fatalf("issue %s: exit %d, stderr=%s", agentID, code, se.String())
	}
}

// writeAgentRevList writes a signed agent-revocation list (empty revoked set is
// fine — we only care about its issued_at/epoch for freshness) at the given age.
func (f freshFixture) writeAgentRevList(t *testing.T, name string, epoch int, issuedAt string, agents ...string) string {
	t.Helper()
	list, err := verify.NewSignedAgentRevocationList(f.regURL, issuedAt, epoch, agents, f.regPriv)
	if err != nil {
		t.Fatalf("sign agent-rev list: %v", err)
	}
	p := filepath.Join(f.dir, name)
	writeJSON(t, p, list)
	return p
}

func (f freshFixture) writeCheckpoint(t *testing.T, name string, epoch int, issuedAt string, priv ed25519.PrivateKey) string {
	t.Helper()
	cp, err := verify.NewSignedFreshnessCheckpoint(f.regURL, epoch, issuedAt, priv)
	if err != nil {
		t.Fatalf("sign checkpoint: %v", err)
	}
	p := filepath.Join(f.dir, name)
	writeJSON(t, p, cp)
	return p
}

func (f freshFixture) writeEmergency(t *testing.T, name string, epoch int, issuedAt string, priv ed25519.PrivateKey, tokens ...string) string {
	t.Helper()
	em, err := verify.NewSignedEmergencyDenyList(f.regURL, issuedAt, epoch, tokens, priv)
	if err != nil {
		t.Fatalf("sign emergency: %v", err)
	}
	p := filepath.Join(f.dir, name)
	writeJSON(t, p, em)
	return p
}

func (f freshFixture) verifyFresh(t *testing.T, bundle string, extra ...string) (int, string, string) {
	t.Helper()
	args := append([]string{"--bundle", filepath.Join(f.dir, bundle), "--trust-roots", f.trPath, "--offline"}, extra...)
	var so, se bytes.Buffer
	code := runAgentIDVerify(args, &so, &se)
	return code, so.String(), se.String()
}

// staleISO returns an RFC3339 timestamp `age` in the past from now.
func staleISO(age time.Duration) string {
	return signing.FormatAttestationTimestamp(time.Now().Add(-age))
}

// --- AC2 (consumer): stale high-risk fails closed; stale low-risk follows policy ---

// Adversarial: replay a stale list past max_staleness for a HIGH-risk action →
// exit 22 (fail-closed), even though the mandate itself verifies.
func TestCLI_StaleHighRiskFailsClosed(t *testing.T) {
	f := buildFreshFixture(t, "24h", "open") // fail_policy=open should NOT save high-risk
	f.issueGrant(t, "agent:writer", "writer.json", "network:write,fs:write")
	list := f.writeAgentRevList(t, "revs.json", 1, staleISO(48*time.Hour)) // 48h old > 24h
	code, _, se := f.verifyFresh(t, "writer.json", "--revocations", list)
	if code != verify.ExitRevocationStale {
		t.Fatalf("stale high-risk must exit %d, got %d (stderr=%s)", verify.ExitRevocationStale, code, se)
	}
}

// Stale low-risk + fail_policy=closed → exit 22; + fail_policy=open → exit 0.
func TestCLI_StaleLowRiskFollowsFailPolicy(t *testing.T) {
	// closed branch
	fc := buildFreshFixture(t, "24h", "closed")
	fc.issueGrant(t, "agent:reader", "reader.json", "network:read,fs:read")
	listC := fc.writeAgentRevList(t, "revs.json", 1, staleISO(48*time.Hour))
	if code, _, se := fc.verifyFresh(t, "reader.json", "--revocations", listC); code != verify.ExitRevocationStale {
		t.Fatalf("stale low-risk + closed must exit %d, got %d (stderr=%s)", verify.ExitRevocationStale, code, se)
	}

	// open branch
	fo := buildFreshFixture(t, "24h", "open")
	fo.issueGrant(t, "agent:reader", "reader.json", "network:read,fs:read")
	listO := fo.writeAgentRevList(t, "revs.json", 1, staleISO(48*time.Hour))
	if code, _, se := fo.verifyFresh(t, "reader.json", "--revocations", listO); code != exitOK {
		t.Fatalf("stale low-risk + open must exit 0, got %d (stderr=%s)", code, se)
	}
}

// A fresh snapshot allows even a high-risk action.
func TestCLI_FreshSnapshotAllows(t *testing.T) {
	f := buildFreshFixture(t, "24h", "closed")
	f.issueGrant(t, "agent:writer", "writer.json", "network:write")
	list := f.writeAgentRevList(t, "revs.json", 1, staleISO(1*time.Hour)) // 1h old < 24h
	if code, _, se := f.verifyFresh(t, "writer.json", "--revocations", list); code != exitOK {
		t.Fatalf("fresh snapshot must exit 0, got %d (stderr=%s)", code, se)
	}
}

// --- R4 (consumer): checkpoint resets the clock; forged/rollback refused ---

// A valid fresh checkpoint at epoch ≥ synced resets the clock → a stale list
// passes for a high-risk action.
func TestCLI_CheckpointResetsStaleness(t *testing.T) {
	f := buildFreshFixture(t, "24h", "closed")
	f.issueGrant(t, "agent:writer", "writer.json", "network:write")
	list := f.writeAgentRevList(t, "revs.json", 2, staleISO(48*time.Hour)) // stale on its own
	// Fresh checkpoint, same epoch, 1h old → resets clock.
	cp := f.writeCheckpoint(t, "cp.json", 2, staleISO(1*time.Hour), f.regPriv)
	code, so, se := f.verifyFresh(t, "writer.json", "--revocations", list, "--checkpoint", cp)
	if code != exitOK {
		t.Fatalf("fresh checkpoint must reset clock → exit 0, got %d (stderr=%s)", code, se)
	}
	if !strings.Contains(so, "checkpoint=reset-clock") {
		t.Errorf("output should report checkpoint reset; got: %s", so)
	}
}

// Adversarial: forge a checkpoint with an unpinned key → refused (exit 12),
// fail-closed (cannot reset the clock).
func TestCLI_ForgedCheckpointRefused(t *testing.T) {
	f := buildFreshFixture(t, "24h", "closed")
	f.issueGrant(t, "agent:writer", "writer.json", "network:write")
	list := f.writeAgentRevList(t, "revs.json", 2, staleISO(48*time.Hour))
	_, forged, _ := ed25519.GenerateKey(rand.Reader)
	cp := f.writeCheckpoint(t, "cp.json", 2, staleISO(1*time.Hour), forged) // forged signer
	if code, _, se := f.verifyFresh(t, "writer.json", "--revocations", list, "--checkpoint", cp); code != verify.ExitRegistryNotTrusted {
		t.Fatalf("forged checkpoint must exit %d, got %d (stderr=%s)", verify.ExitRegistryNotTrusted, code, se)
	}
}

// Adversarial: a rollback checkpoint (epoch below the pinned floor) cannot reset
// the clock. We pin min_revocation_epoch via a high-epoch list and a low-epoch
// checkpoint — the checkpoint epoch < the list epoch is silently ignored (cannot
// advance), so the stale list still fails closed.
func TestCLI_RollbackCheckpointCannotReset(t *testing.T) {
	f := buildFreshFixture(t, "24h", "closed")
	f.issueGrant(t, "agent:writer", "writer.json", "network:write")
	list := f.writeAgentRevList(t, "revs.json", 5, staleISO(48*time.Hour))     // synced epoch 5
	cp := f.writeCheckpoint(t, "cp.json", 3, staleISO(1*time.Hour), f.regPriv) // epoch 3 < 5
	// epoch-3 checkpoint vouches for an OLDER set → does not advance → list stays stale.
	if code, _, se := f.verifyFresh(t, "writer.json", "--revocations", list, "--checkpoint", cp); code != verify.ExitRevocationStale {
		t.Fatalf("rollback checkpoint must NOT reset clock; want exit %d, got %d (stderr=%s)", verify.ExitRevocationStale, code, se)
	}
}

// --- R5 (consumer): emergency deny short-circuits even fresh + low-risk ---

// AC3: an emergency deny-list entry denies BEFORE the cadence — fresh snapshot,
// low-risk, fail_policy=open (which would otherwise ALLOW).
func TestCLI_EmergencyDeniesFreshLowRisk(t *testing.T) {
	f := buildFreshFixture(t, "24h", "open")
	f.issueGrant(t, "agent:burned", "burned.json", "network:read")        // low-risk
	list := f.writeAgentRevList(t, "revs.json", 1, staleISO(1*time.Hour)) // FRESH
	em := f.writeEmergency(t, "em.json", 1, staleISO(30*time.Minute), f.regPriv, "agent:burned")
	code, _, se := f.verifyFresh(t, "burned.json", "--revocations", list, "--emergency", em)
	if code != exitBundleRevoked {
		t.Fatalf("emergency must deny fresh+low-risk with exit %d, got %d (stderr=%s)", exitBundleRevoked, code, se)
	}
}

// Adversarial: evade the emergency deny-list by forging it with an unpinned key →
// refused (exit 12), never silently ignored.
func TestCLI_ForgedEmergencyRefused(t *testing.T) {
	f := buildFreshFixture(t, "", "")
	f.issueGrant(t, "agent:x", "x.json", "network:read")
	_, forged, _ := ed25519.GenerateKey(rand.Reader)
	em := f.writeEmergency(t, "em.json", 1, staleISO(10*time.Minute), forged, "agent:x")
	if code, _, se := f.verifyFresh(t, "x.json", "--emergency", em); code != verify.ExitRegistryNotTrusted {
		t.Fatalf("forged emergency must exit %d, got %d (stderr=%s)", verify.ExitRegistryNotTrusted, code, se)
	}
}

// An emergency list that does NOT name the agent allows it (no false-deny).
func TestCLI_EmergencyDoesNotFalseDeny(t *testing.T) {
	f := buildFreshFixture(t, "", "")
	f.issueGrant(t, "agent:innocent", "innocent.json", "network:read")
	em := f.writeEmergency(t, "em.json", 1, staleISO(10*time.Minute), f.regPriv, "agent:someoneelse")
	if code, _, se := f.verifyFresh(t, "innocent.json", "--emergency", em); code != exitOK {
		t.Fatalf("emergency naming another agent must not deny; want 0, got %d (stderr=%s)", code, se)
	}
}
