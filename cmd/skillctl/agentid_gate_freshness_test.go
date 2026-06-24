package main

// SPEC-0279 P4 — runtime-gate freshness tests (the SPEC-0247 PreToolUse path).
//
// These drive the REAL gate (runVerifyHook → authorizeAgentForSkill →
// verifyActiveAgentID) with a configured AgentID mandate and the gate's
// conventional offline freshness files (~/.claude/skillctl/{emergency-deny,
// agent-revocations,freshness-checkpoint}.json). They prove:
//   - an emergency deny-list entry denies BEFORE the cadence (AC3, gate);
//   - a stale agent-revocation snapshot fails the gate closed for a high-risk
//     grant (AC2, gate);
//   - a fresh checkpoint resets the clock at the gate.

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/agentid"
	"github.com/kamir/m3c-tools/pkg/skillctl/signing"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// regKeyForGate loads the gate fixture's registry private key (PEM) so we can
// sign the emergency / checkpoint files with the SAME key the gate trust-roots
// pin. We reuse signing.LoadPrivateKey for parity with production.
func regKeyForGate(t *testing.T, e gateEnv) ed25519.PrivateKey {
	t.Helper()
	priv, err := signing.LoadPrivateKey(e.f.regKeyPath)
	if err != nil {
		t.Fatalf("load reg key: %v", err)
	}
	return priv
}

// setGateMaxStaleness rewrites the gate's default trust-roots to add a freshness
// policy (max_staleness + fail_policy). Must be called AFTER setupGate (which
// wrote the policy-free file) and BEFORE the hook fires.
func setGateMaxStaleness(t *testing.T, e gateEnv, maxStaleness, failPolicy string) {
	t.Helper()
	defaultTR := filepath.Join(e.home, ".claude", "skill-trust-roots.yaml")
	data, err := os.ReadFile(defaultTR)
	if err != nil {
		t.Fatal(err)
	}
	out := strings.Replace(string(data),
		"    governance_minimum: green\n",
		"    governance_minimum: green\n    max_staleness: "+maxStaleness+"\n    fail_policy: "+failPolicy+"\n",
		1)
	if err := os.WriteFile(defaultTR, []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeGateEmergency writes a signed emergency deny-list to the gate's path.
func writeGateEmergency(t *testing.T, e gateEnv, priv ed25519.PrivateKey, tokens ...string) {
	t.Helper()
	em, err := verify.NewSignedEmergencyDenyList(e.f.regURL, staleISO(10*time.Minute), 1, tokens, priv)
	if err != nil {
		t.Fatal(err)
	}
	p := emergencyDenyPath(e.home)
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	writeJSON(t, p, em)
}

// writeGateRevList writes a signed agent-revocation list to the gate's path with
// a chosen age (for the freshness check). The agent need not be revoked.
func writeGateRevList(t *testing.T, e gateEnv, priv ed25519.PrivateKey, epoch int, issuedAt string, agents ...string) {
	t.Helper()
	list, err := verify.NewSignedAgentRevocationList(e.f.regURL, issuedAt, epoch, agents, priv)
	if err != nil {
		t.Fatal(err)
	}
	p := agentRevocationsPath(e.home)
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	writeJSON(t, p, list)
}

func writeGateCheckpoint(t *testing.T, e gateEnv, priv ed25519.PrivateKey, epoch int, issuedAt string) {
	t.Helper()
	cp, err := verify.NewSignedFreshnessCheckpoint(e.f.regURL, epoch, issuedAt, priv)
	if err != nil {
		t.Fatal(err)
	}
	p := freshnessCheckpointPath(e.home)
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	writeJSON(t, p, cp)
}

// installHighRiskMandate installs a mandate whose grant intent is high-risk
// (network:write) so the freshness contract treats it as high-risk.
func (e gateEnv) installHighRiskMandate(t *testing.T, agentID, grantSkills string) {
	t.Helper()
	out := filepath.Join(e.home, ".claude", "skillctl", "agentid.json")
	_ = os.MkdirAll(filepath.Dir(out), 0o755)
	args := []string{
		"--owner", e.f.ownerID, "--owner-key", e.f.ownerKeyPath,
		"--agent-id", agentID, "--skills", grantSkills,
		"--intents", "network:write,fs:write",
		"--trust-root", e.f.regURL,
		"--expires", "2099-12-31T00:00:00Z", "--out", out,
	}
	var so, se strings.Builder
	if code := runAgentIDIssue(args, &so, &se); code != exitOK {
		t.Fatalf("install high-risk mandate: exit %d %s", code, se.String())
	}
}

// SPEC-0279 P4 (review finding #2): an empty-intents AgentID mandate is
// fail-safe HIGH-risk, matching bundleActionRisk's empty-scopes case. An empty
// grant cannot be PROVEN read-only, so grantActionRisk must NOT downgrade it to
// LOW (which would let it ride the low-risk fail-open path past max_staleness).
func TestGate_EmptyGrantIsHighRisk(t *testing.T) {
	if got := grantActionRisk(agentid.Grant{}); got != verify.RiskHigh {
		t.Fatalf("empty grant: grantActionRisk = %q, want %q (fail-safe HIGH)", got, verify.RiskHigh)
	}
	// A read-only grant is still LOW (the allowlist recognises the read intents).
	if got := grantActionRisk(agentid.Grant{Intents: []string{"network:read", "fs:read"}}); got != verify.RiskLow {
		t.Fatalf("read-only grant: grantActionRisk = %q, want %q", got, verify.RiskLow)
	}
	// A write/egress grant is HIGH.
	if got := grantActionRisk(agentid.Grant{Intents: []string{"network:write"}}); got != verify.RiskHigh {
		t.Fatalf("write grant: grantActionRisk = %q, want %q", got, verify.RiskHigh)
	}
	// An unknown/mis-typed intent token is HIGH (cannot downgrade by obfuscation).
	if got := grantActionRisk(agentid.Grant{Intents: []string{"weird:capability"}}); got != verify.RiskHigh {
		t.Fatalf("unknown-intent grant: grantActionRisk = %q, want %q (fail-safe HIGH)", got, verify.RiskHigh)
	}
}

// AC3 (gate): an emergency deny-list entry denies BEFORE the cadence — even with
// no revocation snapshot at all.
func TestGate_EmergencyDeniesAgent(t *testing.T) {
	e := setupGate(t, "summarize", false)
	e.installMandate(t, "agent:burned", "summarize", false)
	// Pre-emergency: allowed.
	if code, out, _ := feed(t, hookEventFor("summarize")); code != exitOK {
		t.Fatalf("pre-emergency should allow, got %d out=%q", code, out)
	}
	writeGateEmergency(t, e, regKeyForGate(t, e), "agent:burned")
	code, out, _ := feed(t, hookEventFor("summarize"))
	assertDeny(t, code, out, "not authorized")
	if !strings.Contains(out, "agent_emergency_denied") {
		t.Fatalf("expected agent_emergency_denied reason, got %q", out)
	}
}

// AC2 (gate): a stale agent-revocation snapshot fails the gate closed for a
// HIGH-risk grant.
func TestGate_StaleHighRiskFailsClosed(t *testing.T) {
	e := setupGate(t, "summarize", false)
	e.installHighRiskMandate(t, "agent:writer", "summarize")
	setGateMaxStaleness(t, e, "24h", "open") // even fail_policy=open
	writeGateRevList(t, e, regKeyForGate(t, e), 1, staleISO(48*time.Hour))
	code, out, _ := feed(t, hookEventFor("summarize"))
	assertDeny(t, code, out, "not authorized")
	if !strings.Contains(out, "agent_revocation_stale") {
		t.Fatalf("expected agent_revocation_stale reason, got %q", out)
	}
}

// A fresh snapshot allows the high-risk grant at the gate.
func TestGate_FreshHighRiskAllowed(t *testing.T) {
	e := setupGate(t, "summarize", false)
	e.installHighRiskMandate(t, "agent:writer", "summarize")
	setGateMaxStaleness(t, e, "24h", "closed")
	writeGateRevList(t, e, regKeyForGate(t, e), 1, staleISO(1*time.Hour)) // fresh
	code, out, _ := feed(t, hookEventFor("summarize"))
	assertAllow(t, code, out)
}

// A fresh checkpoint resets the clock at the gate → a stale list passes.
func TestGate_CheckpointResetsAtGate(t *testing.T) {
	e := setupGate(t, "summarize", false)
	e.installHighRiskMandate(t, "agent:writer", "summarize")
	setGateMaxStaleness(t, e, "24h", "closed")
	priv := regKeyForGate(t, e)
	writeGateRevList(t, e, priv, 2, staleISO(48*time.Hour)) // stale
	writeGateCheckpoint(t, e, priv, 2, staleISO(1*time.Hour))
	code, out, _ := feed(t, hookEventFor("summarize"))
	assertAllow(t, code, out)
}

// Adversarial: a forged emergency deny-list at the gate path is fail-closed.
//
// SPEC-0279 P4 (review finding #1): the forged file is now caught by the
// UNCONDITIONAL runtime emergency check (verify_hook_cmds.go), which runs FIRST —
// before the mandate path — so the gate refuses rather than ignore an
// operator-placed list it cannot verify, EVEN with a mandate present. The deny
// announces the emergency channel and fail-closes.
func TestGate_ForgedEmergencyFailsClosed(t *testing.T) {
	e := setupGate(t, "summarize", false)
	e.installMandate(t, "agent:x", "summarize", false)
	_, forged, _ := ed25519.GenerateKey(rand.Reader)
	writeGateEmergency(t, e, forged, "agent:someoneelse") // forged signer; doesn't even name x
	code, out, _ := feed(t, hookEventFor("summarize"))
	assertDeny(t, code, out, "emergency deny-list")
	// The fail-closed reason is announced.
	if !strings.Contains(out, "fail-closed") {
		t.Fatalf("forged emergency must fail closed; got %q", out)
	}
}
