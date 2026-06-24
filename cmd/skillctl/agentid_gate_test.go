package main

// SPEC-0277 P1 — runtime authorization tests for the SPEC-0247 gate.
//
// AC-P1: an agent invoking a skill OUTSIDE its grant is denied; a REVOKED agent
// is denied OFFLINE; an in-grant verified skill still runs; the approver floor
// refuses an owner-only AgentID when set. These drive the REAL gate (runVerifyHook)
// with a configured AgentID mandate + real pinned keys, stubbing only the
// skill-chain seam (verifyManagedFn) so the agent layer is what we are testing.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/agentid"
)

// gateEnv wires a temp $HOME with: a managed skill (chain stubbed to pass),
// pinned trust-roots, and the configured agentid.json mandate. It reuses the
// agentFixture key/trust-roots builders from agentid_cmds_test.go.
type gateEnv struct {
	home string
	f    agentFixture
}

// setupGate creates a managed skill, points the gate's trust-roots resolver at a
// pinned root, and (optionally) requires the approver floor. The skill chain seam
// is stubbed to ALLOW, so any deny that follows is purely the AgentID layer.
func setupGate(t *testing.T, skillName string, requireApprover bool) gateEnv {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // Windows: os.UserHomeDir() reads %USERPROFILE%, not $HOME.

	// The gate resolves trust-roots via loadRootsFn → loadAndPickRoot → the
	// default ~/.claude/skill-trust-roots.yaml under $HOME. Build the fixture
	// THEN copy its trust-roots to that default location so the real resolver
	// finds it (the gate doesn't take a --trust-roots flag).
	f := buildAgentFixture(t, requireApprover)
	defaultTR := filepath.Join(home, ".claude", "skill-trust-roots.yaml")
	if err := os.MkdirAll(filepath.Dir(defaultTR), 0o755); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(f.trPath)
	if err := os.WriteFile(defaultTR, data, 0o600); err != nil {
		t.Fatal(err)
	}

	// Managed skill with a stashed .skb so isManagedSkill returns true.
	skillDir := filepath.Join(home, ".claude", "skills", skillName)
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillDir, skillName+".skb"), []byte("fake"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Skill chain passes (we are testing the AGENT layer, not the chain).
	origOn := verifyManagedFn
	verifyManagedFn = func(string, gatePolicy) (int, string) { return exitOK, "" }
	origOff := verifyManagedOfflineFn
	verifyManagedOfflineFn = func(string, gatePolicy, string) (int, string, bool) { return exitOK, "", true }
	t.Cleanup(func() { verifyManagedFn = origOn; verifyManagedOfflineFn = origOff })

	return gateEnv{home: home, f: f}
}

// installMandate writes the active agentid.json (the opt-in switch). grantSkills
// is the CSV skill grant; withApprover co-signs with the approver key.
func (e gateEnv) installMandate(t *testing.T, agentID, grantSkills string, withApprover bool) {
	t.Helper()
	out := filepath.Join(e.home, ".claude", "skillctl", "agentid.json")
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		t.Fatal(err)
	}
	args := []string{
		"--owner", e.f.ownerID, "--owner-key", e.f.ownerKeyPath,
		"--agent-id", agentID,
		"--skills", grantSkills,
		"--intents", "network:read",
		"--trust-root", e.f.regURL,
		"--expires", "2099-12-31T00:00:00Z",
		"--out", out,
	}
	if withApprover {
		args = append(args, "--approver", e.f.approverID, "--approver-key", e.f.approverKey)
	}
	var so, se strings.Builder
	if code := runAgentIDIssue(args, &so, &se); code != exitOK {
		t.Fatalf("install mandate: exit %d %s", code, se.String())
	}
}

// revokeAgent writes a signed agent-revocation list to the gate's offline path.
func (e gateEnv) revokeAgent(t *testing.T, agentID string) {
	t.Helper()
	out := filepath.Join(e.home, ".claude", "skillctl", "agent-revocations.json")
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		t.Fatal(err)
	}
	var so, se strings.Builder
	code := runAgentIDRevoke([]string{
		agentID, "--reason", "vulnerability",
		"--registry", e.f.regURL, "--key", e.f.regKeyPath, "--out", out,
	}, &so, &se)
	if code != exitOK {
		t.Fatalf("revoke: exit %d %s", code, se.String())
	}
}

func hookEventFor(skill string) string {
	ev := map[string]any{
		"hook_event_name": "PreToolUse",
		"tool_name":       "Skill",
		"session_id":      "sess-1",
		"tool_input":      map[string]any{"skill": skill},
	}
	b, _ := json.Marshal(ev)
	return string(b)
}

// AC-P1: in-grant verified skill still runs.
func TestGate_InGrantSkillAllowed(t *testing.T) {
	e := setupGate(t, "summarize", false)
	e.installMandate(t, "agent:a1", "summarize,fetch-contract", false)
	code, out, _ := feed(t, hookEventFor("summarize"))
	assertAllow(t, code, out)
}

// AC-P1: a skill OUTSIDE the grant is denied — even though the skill chain passes.
func TestGate_OutOfGrantSkillDenied(t *testing.T) {
	e := setupGate(t, "danger", false)
	e.installMandate(t, "agent:a2", "summarize", false) // danger NOT granted
	code, out, _ := feed(t, hookEventFor("danger"))
	assertDeny(t, code, out, "not authorized")
	if !strings.Contains(out, "skill_not_in_grant") {
		t.Fatalf("expected skill_not_in_grant reason, got %q", out)
	}
}

// AC-P1: a REVOKED agent is denied OFFLINE (the local signed list, no network).
func TestGate_RevokedAgentDeniedOffline(t *testing.T) {
	e := setupGate(t, "summarize", false)
	e.installMandate(t, "agent:doomed", "summarize", false)
	// Pre-revocation: allowed.
	if code, out, _ := feed(t, hookEventFor("summarize")); code != exitOK {
		t.Fatalf("pre-revocation should allow, got exit %d out=%q", code, out)
	}
	// Revoke offline.
	e.revokeAgent(t, "agent:doomed")
	code, out, _ := feed(t, hookEventFor("summarize"))
	assertDeny(t, code, out, "not authorized")
	if !strings.Contains(out, "agent_revoked") {
		t.Fatalf("expected agent_revoked reason, got %q", out)
	}
}

// AC-P1: the approver floor refuses an owner-only AgentID when set.
func TestGate_ApproverFloorRefusesOwnerOnly(t *testing.T) {
	e := setupGate(t, "summarize", true) // require_agent_approver: true
	e.installMandate(t, "agent:solo", "summarize", false /* no approver */)
	code, out, _ := feed(t, hookEventFor("summarize"))
	assertDeny(t, code, out, "not authorized")
	if !strings.Contains(out, "agent_approver_floor") {
		t.Fatalf("expected agent_approver_floor reason, got %q", out)
	}
}

// The approver floor with an owner+approver mandate ALLOWS.
func TestGate_ApproverFloorMetAllowed(t *testing.T) {
	e := setupGate(t, "summarize", true)
	e.installMandate(t, "agent:two", "summarize", true /* with approver */)
	code, out, _ := feed(t, hookEventFor("summarize"))
	assertAllow(t, code, out)
}

// No mandate configured → the gate behaves exactly as pre-SPEC-0277 (opt-in).
func TestGate_NoMandateUnchanged(t *testing.T) {
	_ = setupGate(t, "summarize", false) // sets $HOME + managed skill; no mandate installed
	code, out, _ := feed(t, hookEventFor("summarize"))
	assertAllow(t, code, out)
}

// The always-on signed invocation event carries the agent identity for an
// in-grant ALLOW (emission is always-on when a mandate is configured).
func TestGate_InvocationEventCarriesAgentIdentity(t *testing.T) {
	e := setupGate(t, "summarize", false)
	e.installMandate(t, "agent:stamped", "summarize", false)
	if code, out, _ := feed(t, hookEventFor("summarize")); code != exitOK {
		t.Fatalf("expected allow, got %d out=%q", code, out)
	}
	tv := readAndVerifyTrail(e.home)
	if tv.Total == 0 {
		t.Fatal("no invocation event written")
	}
	// Read the raw trail and confirm agent_identity is populated + the record
	// still verifies (a VALUE change, not a format break).
	data, err := os.ReadFile(invocationTrailPath(e.home))
	if err != nil {
		t.Fatalf("read trail: %v", err)
	}
	if !strings.Contains(string(data), `"agent_identity":"agent:stamped"`) {
		t.Fatalf("agent_identity not stamped onto the signed event:\n%s", data)
	}
	if !strings.Contains(string(data), `"owner_identity":"id:kamir@m3c"`) {
		t.Fatalf("owner_identity not stamped onto the signed event:\n%s", data)
	}
	if tv.Verified == 0 {
		t.Fatal("the agent-stamped invocation event must still verify (value change, not format break)")
	}
}

// Direct unit on the authorization predicate via a forged mandate: an unsigned /
// owner-not-pinned mandate file is fail-closed (the gate denies any skill).
func TestGate_ForgedMandateFailsClosed(t *testing.T) {
	e := setupGate(t, "summarize", false)
	// Write a mandate signed by a throwaway key (owner id pinned, key is NOT).
	_, rogue, _ := ed25519.GenerateKey(rand.Reader)
	p := agentid.Payload{
		ID: "agent:forged", Owner: e.f.ownerID,
		CreatedAt: "2026-01-01T00:00:00Z", NotAfter: "2099-12-31T00:00:00Z",
		TrustRoot: e.f.regURL,
		Grant:     agentid.Grant{Skills: []string{"summarize"}, Intents: []string{"network:read"}},
	}
	sig, _ := agentid.Sign(p, agentid.RoleOwner, p.Owner, rogue)
	doc := agentid.AgentID{Payload: p, Signatures: []agentid.Signature{sig}}
	out := filepath.Join(e.home, ".claude", "skillctl", "agentid.json")
	_ = os.MkdirAll(filepath.Dir(out), 0o755)
	b, _ := json.MarshalIndent(doc, "", "  ")
	_ = os.WriteFile(out, b, 0o644)

	code, outStr, _ := feed(t, hookEventFor("summarize"))
	assertDeny(t, code, outStr, "not authorized")
	if !strings.Contains(outStr, "agent_owner_sig_invalid") {
		t.Fatalf("expected agent_owner_sig_invalid, got %q", outStr)
	}
}
