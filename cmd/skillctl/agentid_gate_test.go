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

	// Default scope-resolution seam: model an installed skill whose digest-verified
	// manifest declares NO extra capabilities (the common allow case), so the
	// agent-layer tests (grant / revoke / approver-floor) exercise the mandate layer
	// without depending on real .skb + provenance-file mechanics. Scope-specific
	// tests override this seam with a concrete requirement set; tests that exercise
	// the REAL resolver restore skillRequirementsFn = resolveInstalledSkillRequirements.
	origReq := skillRequirementsFn
	skillRequirementsFn = func(string, string) (agentid.SkillRequirements, bool) {
		return agentid.SkillRequirements{}, true
	}
	t.Cleanup(func() { skillRequirementsFn = origReq })

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

// installMandateWithSpendCap writes an active mandate granting `grantSkills` with
// intents network:read AND a hard spend ceiling (--limit spend_eur_max=<cap>).
func (e gateEnv) installMandateWithSpendCap(t *testing.T, agentID, grantSkills, cap string) {
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
		"--limit", "spend_eur_max=" + cap,
		"--trust-root", e.f.regURL,
		"--expires", "2099-12-31T00:00:00Z",
		"--out", out,
	}
	var so, se strings.Builder
	if code := runAgentIDIssue(args, &so, &se); code != exitOK {
		t.Fatalf("install mandate: exit %d %s", code, se.String())
	}
}

// installMandateSkillsOnly writes a NON-restricting mandate: a skill grant with NO
// intents / data-scopes / limits, so grantIsRestricting is false (name-only floor).
func (e gateEnv) installMandateSkillsOnly(t *testing.T, agentID, grantSkills string) {
	t.Helper()
	out := filepath.Join(e.home, ".claude", "skillctl", "agentid.json")
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		t.Fatal(err)
	}
	args := []string{
		"--owner", e.f.ownerID, "--owner-key", e.f.ownerKeyPath,
		"--agent-id", agentID, "--skills", grantSkills,
		"--trust-root", e.f.regURL, "--expires", "2099-12-31T00:00:00Z", "--out", out,
	}
	var so, se strings.Builder
	if code := runAgentIDIssue(args, &so, &se); code != exitOK {
		t.Fatalf("install mandate: exit %d %s", code, se.String())
	}
}

// writeSidecarAndDeleteSkb records a bundle digest in the skill's provenance sidecar
// (so installedSkillDigest returns non-empty — the gate KNOWS a bundle exists) and
// removes every stashed .skb (so the signed manifest is unreadable), modelling a
// same-uid actor stripping scope enforcement down to name-only.
func writeSidecarAndDeleteSkb(t *testing.T, home, skill string) {
	t.Helper()
	skillDir := filepath.Join(home, ".claude", "skills", skill)
	side := `{"schema_version":"1","skill":"` + skill + `","version":"1.0.0","bundle_digest":"sha256:` + strings.Repeat("a", 64) + `"}`
	if err := os.WriteFile(filepath.Join(skillDir, ".m3c-provenance.json"), []byte(side), 0o644); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(skillDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, en := range entries {
		if strings.HasSuffix(en.Name(), ".skb") {
			if err := os.Remove(filepath.Join(skillDir, en.Name())); err != nil {
				t.Fatal(err)
			}
		}
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

// AC IS-T6: with the ROOT-OWNED require-mandate floor engaged, a MISSING
// agentid.json is a hard DENY (agent_mandate_required), NOT the silent opt-out.
// Against the pre-IS-T6 code (no mandate → Configured=false → allow) this bites:
// the identical setup previously allowed the skill (see TestGate_NoMandateUnchanged).
func TestGate_RequireMandateFloor_MissingMandateDenied(t *testing.T) {
	_ = setupGate(t, "summarize", false) // managed skill + trust-roots, but NO mandate installed
	orig := gateRequireAgentMandate
	gateRequireAgentMandate = func() bool { return true }
	t.Cleanup(func() { gateRequireAgentMandate = orig })

	code, out, _ := feed(t, hookEventFor("summarize"))
	assertDeny(t, code, out, "not authorized")
	if !strings.Contains(out, "agent_mandate_required") {
		t.Fatalf("expected agent_mandate_required reason, got %q", out)
	}
}

// Control for IS-T6: with the floor OFF, a missing mandate stays the opt-out
// default (allow) — the floor is the ONLY thing that turns absence into a deny.
func TestGate_RequireMandateFloor_OffKeepsOptOut(t *testing.T) {
	_ = setupGate(t, "summarize", false)
	orig := gateRequireAgentMandate
	gateRequireAgentMandate = func() bool { return false }
	t.Cleanup(func() { gateRequireAgentMandate = orig })

	code, out, _ := feed(t, hookEventFor("summarize"))
	assertAllow(t, code, out)
}

// AC IS-T7: the gate enforces the SIGNED manifest SCOPE, not just the skill NAME. A
// skill NAMED in the grant but whose digest-verified manifest declares fs:write —
// an intent the network:read-only grant lacks — is DENIED. Against the pre-IS-T7
// code (which called AuthorizeSkill(skill, nil): no intents/scopes/limits) this
// bites — the identical in-grant skill was allowed on name membership alone. Drives
// the REAL gate; only the manifest-resolution seam is injected (so the test needn't
// mint a real .skb), which is exactly the value the old code discarded.
func TestGate_ManifestIntentExceedsGrantDenied(t *testing.T) {
	e := setupGate(t, "pdf", false)
	e.installMandate(t, "agent:scoped", "pdf", false) // grants pdf + intents network:read
	orig := skillRequirementsFn
	skillRequirementsFn = func(home, skill string) (agentid.SkillRequirements, bool) {
		return agentid.SkillRequirements{Intents: []string{"fs:write"}}, true
	}
	t.Cleanup(func() { skillRequirementsFn = orig })

	code, out, _ := feed(t, hookEventFor("pdf"))
	assertDeny(t, code, out, "not authorized")
	if !strings.Contains(out, "intent_not_in_grant") {
		t.Fatalf("expected intent_not_in_grant, got %q", out)
	}
}

// AC IS-T7 (limits): a manifest declaring a spend over the mandate's spend_eur_max
// cap of 0 is DENIED at the gate (limit_exceeded). Bites the pre-IS-T7 code that
// enforced no limits at all.
func TestGate_ManifestSpendOverCapDenied(t *testing.T) {
	e := setupGate(t, "pdf", false)
	e.installMandateWithSpendCap(t, "agent:spender", "pdf", "0")
	orig := skillRequirementsFn
	skillRequirementsFn = func(home, skill string) (agentid.SkillRequirements, bool) {
		return agentid.SkillRequirements{Limits: map[string]string{"spend_eur_max": "5"}}, true
	}
	t.Cleanup(func() { skillRequirementsFn = orig })

	code, out, _ := feed(t, hookEventFor("pdf"))
	assertDeny(t, code, out, "not authorized")
	if !strings.Contains(out, "limit_exceeded") {
		t.Fatalf("expected limit_exceeded, got %q", out)
	}
}

// AC IS-T7 (in-scope still allowed): a manifest fully within the grant (a
// network:read intent, spend 0 within cap 0) still runs — enforcement denies only
// what EXCEEDS the grant.
func TestGate_ManifestWithinGrantAllowed(t *testing.T) {
	e := setupGate(t, "pdf", false)
	e.installMandateWithSpendCap(t, "agent:ok", "pdf", "0")
	orig := skillRequirementsFn
	skillRequirementsFn = func(home, skill string) (agentid.SkillRequirements, bool) {
		return agentid.SkillRequirements{
			Intents: []string{"network:read"},
			Limits:  map[string]string{"spend_eur_max": "0"},
		}, true
	}
	t.Cleanup(func() { skillRequirementsFn = orig })

	code, out, _ := feed(t, hookEventFor("pdf"))
	assertAllow(t, code, out)
}

// Challenge-gate HIGH (IS-T7): requirementsFromManifest must read the SIGNED
// `intent` block, not just data_dependencies — else a skill declaring egress /
// subprocess / destructive / arbitrary side-effects with read-shaped data deps
// passes a grant that never granted those capabilities. Bites the pre-fix code that
// projected ONLY data_dependencies (req.Intents would have been just {er1:read} and
// the grant would have ALLOWED it).
func TestRequirementsFromManifest_IncludesSignedIntentBlock(t *testing.T) {
	m := map[string]any{
		"data_dependencies": []any{
			map[string]any{"id": "ds:x", "kind": "er1_collection", "access": "read"},
		},
		"intent": map[string]any{
			"network":      true,
			"subprocess":   []any{"curl"},
			"destructive":  true,
			"side_effects": []any{"fs:write", "llm:call"},
		},
	}
	req := requirementsFromManifest(m)
	got := map[string]bool{}
	for _, i := range req.Intents {
		got[i] = true
	}
	for _, want := range []string{"er1:read", "network:write", "subprocess:exec", "destructive", "fs:write", "llm:call"} {
		if !got[want] {
			t.Errorf("required intents %v missing %q (the signed intent block must be read, not just data_dependencies)", req.Intents, want)
		}
	}
	// The exact bite: a grant allowing only er1:read must DENY this skill.
	g := agentid.Grant{Skills: []string{"pdf"}, Intents: []string{"er1:read"}}
	if r, ok := g.AuthorizeSkillScoped("pdf", req); ok || r != "intent_not_in_grant" {
		t.Fatalf("a skill declaring network/subprocess/destructive/fs:write must be denied under an er1:read-only grant, got reason=%q ok=%v", r, ok)
	}
}

// An http_endpoint write/egress dependency is the network:write capability (not
// network:read) — so a network:read-only grant denies an egress skill.
func TestIntentForKindAccess_HttpEgressIsNetworkWrite(t *testing.T) {
	for _, acc := range []string{"write", "transform", "egress"} {
		if got := intentForKindAccess("http_endpoint", acc); got != "network:write" {
			t.Errorf("http_endpoint %q → %q, want network:write", acc, got)
		}
	}
	for _, acc := range []string{"read", "passthrough", ""} {
		if got := intentForKindAccess("http_endpoint", acc); got != "network:read" {
			t.Errorf("http_endpoint %q → %q, want network:read", acc, got)
		}
	}
}

// Challenge-gate MEDIUM (IS-T7): a same-uid actor deleting the stashed .skb must NOT
// downgrade a RESTRICTING mandate to name-only. When a digest IS on record but the
// signed manifest is unreadable, the gate fails CLOSED. Uses the REAL resolver (no
// seam override). Bites the pre-fix code that returned an empty requirement set
// (name-only) → the in-grant skill was ALLOWED.
func TestGate_SkbDeletedWithDigestOnRecord_FailsClosed(t *testing.T) {
	e := setupGate(t, "pdf", false)
	skillRequirementsFn = resolveInstalledSkillRequirements // exercise the REAL resolver
	e.installMandate(t, "agent:x", "pdf", false)            // RESTRICTING: grants pdf + intents network:read
	writeSidecarAndDeleteSkb(t, e.home, "pdf")

	code, out, _ := feed(t, hookEventFor("pdf"))
	assertDeny(t, code, out, "not authorized")
	if !strings.Contains(out, "skill_requirements_unresolved") {
		t.Fatalf("expected skill_requirements_unresolved, got %q", out)
	}
}

// stripAllProvenance removes EVERY provenance basis for a skill — the stashed
// *.skb, the .m3c-provenance.json sidecar, and the .skillctl-offline.json stash —
// leaving only a SKILL.md. This is the state a same-uid actor reaches by deleting
// all provenance to reclassify an in-grant skill as UNMANAGED (isManagedSkill →
// false), which the pre-IS-RS-02 gate then routed through unmanaged=allow.
func stripAllProvenance(t *testing.T, home, skill string) {
	t.Helper()
	dir := filepath.Join(home, ".claude", "skills", skill)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, en := range entries {
		n := en.Name()
		if strings.HasSuffix(n, ".skb") || n == ".m3c-provenance.json" || n == ".skillctl-offline.json" {
			if err := os.Remove(filepath.Join(dir, n)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: "+skill+"\n---\nbody\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// FR-0090 IS-RS-02 bite: deleting ALL provenance (.skb + sidecar + offline stash)
// while keeping SKILL.md reclassifies an in-grant skill as UNMANAGED, so the pre-fix
// gate took the unmanaged=allow branch and SKIPPED the IS-T7 mandate scope check —
// letting a same-uid actor escape a restricting mandate. Under a RESTRICTING mandate
// that NAMES the skill, the fully-stripped unmanaged skill must now be DENIED.
// Pre-fix: allowed.
func TestGate_FullyStrippedUnmanaged_RestrictingMandate_Denied(t *testing.T) {
	e := setupGate(t, "pdf", false)                         // fixture writes pdf.skb (managed)
	skillRequirementsFn = resolveInstalledSkillRequirements // exercise the REAL resolver
	e.installMandate(t, "agent:s", "pdf", false)            // RESTRICTING: grants pdf + intents network:read
	stripAllProvenance(t, e.home, "pdf")                    // now UNMANAGED (no .skb, no sidecar, no offline stash)

	// Precondition: the skill really is unmanaged now (else the test would exercise
	// the managed path and prove nothing about the unmanaged=allow bypass).
	if managed, _ := isManagedSkill("pdf"); managed {
		t.Fatal("precondition: pdf must be UNMANAGED after stripping all provenance")
	}

	code, out, _ := feed(t, hookEventFor("pdf"))
	assertDeny(t, code, out, "not skillctl-managed")
	if !strings.Contains(out, "IS-RS-02") {
		t.Fatalf("expected the IS-RS-02 unmanaged-under-restricting-mandate deny, got %q", out)
	}
}

// Never-brick control for IS-RS-02: a fully-stripped UNMANAGED skill under a
// NON-restricting (name-only) mandate that names it must STILL run — a name-only
// mandate owes no scope check, so the unmanaged=allow path is correct.
func TestGate_FullyStrippedUnmanaged_NonRestrictingMandate_Allows(t *testing.T) {
	e := setupGate(t, "pdf", false)
	skillRequirementsFn = resolveInstalledSkillRequirements
	e.installMandateSkillsOnly(t, "agent:t", "pdf") // NON-restricting
	stripAllProvenance(t, e.home, "pdf")

	if managed, _ := isManagedSkill("pdf"); managed {
		t.Fatal("precondition: pdf must be UNMANAGED after stripping all provenance")
	}
	code, out, _ := feed(t, hookEventFor("pdf"))
	assertAllow(t, code, out)
}

// Never-brick control for IS-RS-02: a fully-stripped UNMANAGED skill NOT named in a
// restricting grant must NOT be denied by the new rung — it falls through to the
// normal unmanaged policy path (default allow). (A different skill IS granted, so
// the mandate is configured + restricting but does not name `other`.)
func TestGate_FullyStrippedUnmanaged_NotInGrant_UnmanagedPolicyPath(t *testing.T) {
	e := setupGate(t, "other", false)
	skillRequirementsFn = resolveInstalledSkillRequirements
	e.installMandate(t, "agent:u", "pdf", false) // RESTRICTING, but grants pdf — NOT `other`
	stripAllProvenance(t, e.home, "other")

	_, out, _ := feed(t, hookEventFor("other"))
	// `other` is not in grant → the mandate denies it via allow() with the normal
	// skill_not_in_grant reason, NOT the new unmanaged_under_restricting_mandate rung.
	if strings.Contains(out, "unmanaged_under_restricting_mandate") {
		t.Fatalf("a not-in-grant skill must not hit the IS-RS-02 rung; got %q", out)
	}
}

// Never-brick control for the MEDIUM fix: a NON-restricting grant (skills only) keeps
// the name-only fallback even when the .skb is gone — a bundle-less-but-named skill
// under a name-only mandate must still run.
func TestGate_SkbDeleted_NonRestrictingGrantStillAllows(t *testing.T) {
	e := setupGate(t, "pdf", false)
	skillRequirementsFn = resolveInstalledSkillRequirements // exercise the REAL resolver
	e.installMandateSkillsOnly(t, "agent:y", "pdf")         // NON-restricting
	writeSidecarAndDeleteSkb(t, e.home, "pdf")

	code, out, _ := feed(t, hookEventFor("pdf"))
	assertAllow(t, code, out)
}

// Re-gate root-cause bite (was STILL-ENABLED): installedSkillDigest must resolve
// the digest from the `.skillctl-offline.json` stash that the PRIMARY `skillctl
// install` path writes — not only the `.m3c-provenance.json` sidecar that only the
// `pull` path writes. Pre-fix it read only the sidecar and returned "" here, so
// IS-T7 resolved no scope and silently degraded EVERY install-path skill to
// name-only enforcement, with no tampering at all.
func TestInstalledSkillDigest_FallsBackToOfflineMeta(t *testing.T) {
	home := t.TempDir()
	skill := "pdf"
	dir := filepath.Join(home, ".claude", "skills", skill)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	dg := "sha256:" + strings.Repeat("b", 64)
	// The `skillctl install` layout: an offline stash carrying the bundle digest,
	// and NO provenance sidecar.
	om := `{"bundle_meta":{"bundle":{"bundle_digest":"` + dg + `"}},"stashed_at":"2026-01-01T00:00:00Z"}`
	if err := os.WriteFile(filepath.Join(dir, ".skillctl-offline.json"), []byte(om), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := installedSkillDigest(home, skill); got != dg {
		t.Fatalf("installedSkillDigest must fall back to the offline-meta digest on the install path; got %q want %q (pre-fix it read only .m3c-provenance.json → \"\")", got, dg)
	}
}

// Re-gate core bite (was STILL-ENABLED, 2(b)): a MANAGED skill (a stashed .skb) for
// which NO digest resolves from ANY basis — no sidecar, no offline stash, the exact
// state after a same-uid strip of every provenance file (and the pre-fix
// install-path default) — must FAIL CLOSED under a restricting grant, not degrade to
// name-only. Uses the REAL resolver. Pre-fix returned (empty, TRUE) → the in-grant
// skill was ALLOWED with its scope unenforced.
func TestGate_ManagedSkbNoDigestBasis_FailsClosed(t *testing.T) {
	e := setupGate(t, "pdf", false)                         // fixture writes pdf.skb, NO sidecar, NO offline-meta
	skillRequirementsFn = resolveInstalledSkillRequirements // exercise the REAL resolver
	e.installMandate(t, "agent:z", "pdf", false)            // RESTRICTING: grants pdf + intents network:read

	code, out, _ := feed(t, hookEventFor("pdf"))
	assertDeny(t, code, out, "not authorized")
	if !strings.Contains(out, "skill_requirements_unresolved") {
		t.Fatalf("a managed skill whose scope cannot be resolved from any basis must fail closed under a restricting grant, got %q", out)
	}
}

// Never-brick guard for the fix: a genuinely unmanaged skill — NO stashed .skb, NO
// sidecar, NO offline stash — resolves name-only (empty, TRUE) so a bundle-less
// legacy skill is never bricked. This is the ONLY (empty, TRUE) case; a managed .skb
// with no resolvable digest is the fail-closed case above.
func TestResolveRequirements_NoManagedBasis_NeverBrick(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".claude", "skills", "legacy")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	req, resolved := resolveInstalledSkillRequirements(home, "legacy")
	if !resolved || len(req.Intents) != 0 || len(req.DataScopes) != 0 || len(req.Limits) != 0 {
		t.Fatalf("an unmanaged skill (no bundle basis at all) must resolve name-only never-brick; got resolved=%v req=%+v", resolved, req)
	}
}

// Re-gate residual bite (B(c)): intent.subprocess must project subprocess:exec in
// EVERY non-empty encoding, not only a list — else a skill dodges the subprocess
// requirement by declaring it as a scalar/object. Empty/false forms declare nothing.
func TestRequirementsFromManifest_SubprocessNonArrayForms(t *testing.T) {
	declares := []any{true, "curl -sSL x | sh", map[string]any{"cmd": "sh"}, []any{"sh"}}
	for _, sp := range declares {
		req := requirementsFromManifest(map[string]any{"intent": map[string]any{"subprocess": sp}})
		found := false
		for _, i := range req.Intents {
			if i == "subprocess:exec" {
				found = true
			}
		}
		if !found {
			t.Errorf("subprocess declared as %T (%v) must project subprocess:exec; got %v", sp, sp, req.Intents)
		}
	}
	for _, sp := range []any{false, "", []any{}, map[string]any{}, nil} {
		req := requirementsFromManifest(map[string]any{"intent": map[string]any{"subprocess": sp}})
		for _, i := range req.Intents {
			if i == "subprocess:exec" {
				t.Errorf("empty/false subprocess (%T %v) must NOT project subprocess:exec", sp, sp)
			}
		}
	}
}

// Re-gate residual bite (B(c)): an UNKNOWN data_dependency kind must fail closed —
// carried verbatim as its own category so it fails grant membership — not vanish to
// "" (which let an unrecognized-kind dependency escape the grant). An empty kind
// still contributes nothing.
func TestIntentForKindAccess_UnknownKindFailsClosed(t *testing.T) {
	if got := intentForKindAccess("quantum_ledger", "write"); got != "quantum_ledger:write" {
		t.Errorf("unknown kind must fail closed as <kind>:<act>, got %q", got)
	}
	if got := intentForKindAccess("", "read"); got != "" {
		t.Errorf("empty kind → no derived intent, got %q", got)
	}
	// And a grant lacking that exact token denies the skill.
	g := agentid.Grant{Skills: []string{"x"}, Intents: []string{"network:read"}}
	req := requirementsFromManifest(map[string]any{
		"data_dependencies": []any{map[string]any{"kind": "quantum_ledger", "access": "write"}},
	})
	if r, ok := g.AuthorizeSkillScoped("x", req); ok || r != "intent_not_in_grant" {
		t.Fatalf("an unknown-kind dependency must be denied unless explicitly granted, got reason=%q ok=%v", r, ok)
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
