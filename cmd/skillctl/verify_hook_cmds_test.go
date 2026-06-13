package main

// Tests for `skillctl verify-hook` (SPEC-0247 P0.1).
//
// The network-dependent §7 chain is behind the verifyManagedFn seam, stubbed
// here so the decision logic is exercised offline. "Managed" skills are faked
// by creating ~/.claude/skills/<name>/<name>.skb under a temp $HOME.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// feed runs runVerifyHook with the given event JSON and returns (exit, stdout, stderr).
func feed(t *testing.T, event string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := runVerifyHook(strings.NewReader(event), &out, &errb)
	return code, out.String(), errb.String()
}

// assertDeny checks the three-way deny contract: exit 2 + a deny-shaped JSON on
// stdout whose reason contains `want`.
func assertDeny(t *testing.T, code int, stdout, want string) {
	t.Helper()
	if code != exitHookBlock {
		t.Fatalf("exit = %d, want %d (deny)", code, exitHookBlock)
	}
	var d hookDecisionOut
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &d); err != nil {
		t.Fatalf("stdout is not decision JSON: %v\nstdout=%q", err, stdout)
	}
	if d.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("permissionDecision = %q, want deny", d.HookSpecificOutput.PermissionDecision)
	}
	if want != "" && !strings.Contains(d.HookSpecificOutput.PermissionDecisionReason, want) {
		t.Fatalf("reason %q does not contain %q", d.HookSpecificOutput.PermissionDecisionReason, want)
	}
}

func assertAllow(t *testing.T, code int, stdout string) {
	t.Helper()
	if code != exitOK {
		t.Fatalf("exit = %d, want %d (allow)", code, exitOK)
	}
	if strings.TrimSpace(stdout) != "" {
		t.Fatalf("allow should emit nothing on stdout, got %q", stdout)
	}
}

// withManagedSkill creates a temp $HOME containing an installed (managed) skill
// with a stashed .skb, and stubs the verification seam to return (code,reason).
func withManagedSkill(t *testing.T, name string, retCode int, retReason string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".claude", "skills", name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".skb"), []byte("fake-bundle"), 0o644); err != nil {
		t.Fatal(err)
	}
	orig := verifyManagedFn
	verifyManagedFn = func(string, gatePolicy) (int, string) { return retCode, retReason }
	t.Cleanup(func() { verifyManagedFn = orig })
}

func TestVerifyHook_MalformedStdin_Denies(t *testing.T) {
	code, out, _ := feed(t, "this is not json")
	assertDeny(t, code, out, "malformed")
}

func TestVerifyHook_EmptyStdin_Denies(t *testing.T) {
	code, out, _ := feed(t, "   ")
	assertDeny(t, code, out, "unreadable")
}

func TestVerifyHook_NonSkillTool_Allows(t *testing.T) {
	code, out, _ := feed(t, `{"tool_name":"Bash","tool_input":{"command":"ls"}}`)
	assertAllow(t, code, out)
}

func TestVerifyHook_NoSkillField_Allows(t *testing.T) {
	code, out, _ := feed(t, `{"tool_name":"Skill","tool_input":{"args":"foo"}}`)
	assertAllow(t, code, out)
}

func TestVerifyHook_PathTraversalName_Denies(t *testing.T) {
	code, out, _ := feed(t, `{"tool_name":"Skill","tool_input":{"skill":"../../etc/passwd"}}`)
	// SEC F12: the name now fails the canonical fixed point; the deny reason
	// announces an unsafe name (was "path traversal") — the behavior (deny,
	// exit 2) is unchanged; the wording converged on the shared validator.
	assertDeny(t, code, out, "unsafe skill name")
}

func TestVerifyHook_UnmanagedNamespaced_DefaultAllow(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SKILLCTL_GATE_UNMANAGED", "") // default = allow
	code, out, _ := feed(t, `{"tool_name":"Skill","tool_input":{"skill":"ouroboros:welcome"}}`)
	assertAllow(t, code, out)
}

func TestVerifyHook_UnmanagedPolicyDeny_Blocks(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SKILLCTL_GATE_UNMANAGED", "deny")
	code, out, _ := feed(t, `{"tool_name":"Skill","tool_input":{"skill":"some-plugin:thing"}}`)
	assertDeny(t, code, out, "not skillctl-managed")
}

func TestVerifyHook_ManagedBadSignature_Denies(t *testing.T) {
	// exit 11 = author signature invalid — the headline case (SPEC-0247 §10).
	withManagedSkill(t, "evil-skill", 11, "author signature invalid")
	code, out, errb := feed(t, `{"tool_name":"Skill","tool_input":{"skill":"evil-skill"}}`)
	assertDeny(t, code, out, "author signature invalid")
	// reason cites the exit code and is actionable
	if !strings.Contains(out, "exit 11") || !strings.Contains(out, "skillctl verify evil-skill") {
		t.Fatalf("deny reason not actionable: %q", out)
	}
	if !strings.Contains(errb, "author signature invalid") {
		t.Fatalf("stderr should carry the reason for the exit-2 path, got %q", errb)
	}
}

func TestVerifyHook_ManagedDigestMismatch_Denies(t *testing.T) {
	withManagedSkill(t, "tampered", 10, "bundle modified after signing (digest mismatch)")
	code, out, _ := feed(t, `{"tool_name":"Skill","tool_input":{"skill":"tampered"}}`)
	assertDeny(t, code, out, "digest mismatch")
}

func TestVerifyHook_ManagedClean_Allows(t *testing.T) {
	withManagedSkill(t, "good-skill", exitOK, "")
	code, out, _ := feed(t, `{"tool_name":"Skill","tool_input":{"skill":"good-skill"}}`)
	assertAllow(t, code, out)
}

func TestVerifyHook_AllowlistBypassesGate(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	// Write a policy that allowlists "code-review".
	pdir := filepath.Join(home, ".claude", "skillctl")
	if err := os.MkdirAll(pdir, 0o755); err != nil {
		t.Fatal(err)
	}
	policy := "unmanaged_skills: deny\nallowlist:\n  - code-review\n"
	if err := os.WriteFile(filepath.Join(pdir, "gate-policy.yaml"), []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}
	// code-review is unmanaged + policy=deny, but allowlisted → allow.
	code, out, _ := feed(t, `{"tool_name":"Skill","tool_input":{"skill":"code-review"}}`)
	assertAllow(t, code, out)
}

func TestVerifyHook_OfflineFirst_DeniesBadSig(t *testing.T) {
	// When offline verify is "available" and returns a trust failure, the hook
	// must deny WITHOUT consulting the online path.
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".claude", "skills", "evil")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "evil.skb"), []byte("blob"), 0o644); err != nil {
		t.Fatal(err)
	}
	onlineCalls := 0
	origOn := verifyManagedFn
	verifyManagedFn = func(string, gatePolicy) (int, string) { onlineCalls++; return exitOK, "" }
	t.Cleanup(func() { verifyManagedFn = origOn })

	origOff := verifyManagedOfflineFn
	verifyManagedOfflineFn = func(string, gatePolicy, string) (int, string, bool) {
		return 11, "author signature invalid", true // available + trust fail
	}
	t.Cleanup(func() { verifyManagedOfflineFn = origOff })

	code, out, _ := feed(t, `{"tool_name":"Skill","tool_input":{"skill":"evil"}}`)
	assertDeny(t, code, out, "author signature invalid")
	if onlineCalls != 0 {
		t.Fatalf("offline was decisive; online must NOT be called (got %d)", onlineCalls)
	}
}

func TestVerifyHook_OfflineUnavailable_FallsBackOnline(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".claude", "skills", "legacy")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "legacy.skb"), []byte("blob"), 0o644); err != nil {
		t.Fatal(err)
	}
	origOff := verifyManagedOfflineFn
	verifyManagedOfflineFn = func(string, gatePolicy, string) (int, string, bool) { return 0, "", false } // no stash
	t.Cleanup(func() { verifyManagedOfflineFn = origOff })

	called := false
	origOn := verifyManagedFn
	verifyManagedFn = func(string, gatePolicy) (int, string) { called = true; return exitOK, "" }
	t.Cleanup(func() { verifyManagedFn = origOn })

	code, out, _ := feed(t, `{"tool_name":"Skill","tool_input":{"skill":"legacy"}}`)
	assertAllow(t, code, out)
	if !called {
		t.Fatal("offline unavailable → must fall back to the online chain")
	}
}

func TestVerifyHook_SidecarSkill_IsManaged(t *testing.T) {
	// A skill with ONLY a .m3c-provenance.json (self/ER1 pull format, no .skb)
	// must be treated as managed → routed through verify, not skipped.
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".claude", "skills", "pulled")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".m3c-provenance.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	origOff := verifyManagedOfflineFn
	verifyManagedOfflineFn = func(string, gatePolicy, string) (int, string, bool) {
		return 13, "governance below required minimum", true
	}
	t.Cleanup(func() { verifyManagedOfflineFn = origOff })

	code, out, _ := feed(t, `{"tool_name":"Skill","tool_input":{"skill":"pulled"}}`)
	assertDeny(t, code, out, "governance below required minimum")
}

// SEC-M4: when the offline tier is unavailable (legacy install, no stash) the
// hook falls back to the ONLINE chain (install.VerifyInstalled). That chain now
// runs content-binding unconditionally, so an edited body surfaces as exit 10.
// Here we drive that wiring through the seam: offline unavailable + online
// returns the digest-mismatch verdict → the hook must DENY (exit 2) and cite it.
func TestVerifyHook_OnlinePath_EditedBody_Denies(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".claude", "skills", "online-edited")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "online-edited.skb"), []byte("blob"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Offline tier reports "not available" → force the online fallback.
	origOff := verifyManagedOfflineFn
	verifyManagedOfflineFn = func(string, gatePolicy, string) (int, string, bool) { return 0, "", false }
	t.Cleanup(func() { verifyManagedOfflineFn = origOff })

	// Online chain returns the SEC-M4 content-binding verdict.
	onlineCalls := 0
	origOn := verifyManagedFn
	verifyManagedFn = func(string, gatePolicy) (int, string) {
		onlineCalls++
		return 10, "bundle modified after signing (digest mismatch)"
	}
	t.Cleanup(func() { verifyManagedFn = origOn })

	code, out, _ := feed(t, `{"tool_name":"Skill","tool_input":{"skill":"online-edited"}}`)
	assertDeny(t, code, out, "digest mismatch")
	if onlineCalls != 1 {
		t.Fatalf("online chain must be consulted once on offline-unavailable, got %d", onlineCalls)
	}
	if !strings.Contains(out, "exit 10") {
		t.Fatalf("deny reason must cite exit 10, got %q", out)
	}
}

// SPEC-0251 P1 (GATE PANIC-SAFETY): a panic anywhere in the gate body must be
// converted into the canonical three-way DENY (decision JSON + stderr + exit 2),
// never a process crash. A crash would exit non-2 and the harness could read a
// non-block exit as "allow", silently opening the hole the gate exists to close.
// We inject the panic through the hookPreflight seam.
func TestVerifyHook_PanicInGate_FailsClosedDeny(t *testing.T) {
	orig := hookPreflight
	hookPreflight = func() { panic("boom: simulated internal gate failure") }
	t.Cleanup(func() { hookPreflight = orig })

	// A perfectly valid allow-shaped event — without the recover this would have
	// returned exit 0; the injected panic must instead force a DENY.
	code, out, errb := feed(t, `{"tool_name":"Skill","tool_input":{"skill":"anything"}}`)
	assertDeny(t, code, out, "internal error")
	if !strings.Contains(errb, "failing closed") {
		t.Fatalf("stderr should announce the fail-closed deny, got %q", errb)
	}
}

// SPEC-0251 SEC-L2: a PRESENT gate-policy.yaml with an unknown/misspelled field
// must NOT be silently discarded (which would revert to unmanaged=allow and let
// an unmanaged skill through). Strict parsing fails closed: the unmanaged
// disposition becomes deny.
func TestVerifyHook_UnknownPolicyField_FailsClosed(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SKILLCTL_GATE_UNMANAGED", "") // do not let the env override mask the fix
	pdir := filepath.Join(home, ".claude", "skillctl")
	if err := os.MkdirAll(pdir, 0o755); err != nil {
		t.Fatal(err)
	}
	// `unmanaged_skils` is a typo of `unmanaged_skills`. The operator clearly
	// meant deny; a non-strict parser would ignore the line and allow-all.
	policy := "unmanaged_skils: deny\n"
	if err := os.WriteFile(filepath.Join(pdir, "gate-policy.yaml"), []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}
	// An unmanaged (namespaced) skill must now be DENIED, not allowed.
	code, out, errb := feed(t, `{"tool_name":"Skill","tool_input":{"skill":"some-plugin:thing"}}`)
	assertDeny(t, code, out, "not skillctl-managed")
	if !strings.Contains(errb, "failing closed") {
		t.Fatalf("a broken policy should warn about failing closed, got stderr=%q", errb)
	}
}

// A MALFORMED (unparseable) policy file also fails closed.
func TestVerifyHook_MalformedPolicy_FailsClosed(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SKILLCTL_GATE_UNMANAGED", "")
	pdir := filepath.Join(home, ".claude", "skillctl")
	if err := os.MkdirAll(pdir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Broken YAML (unterminated/garbled mapping).
	if err := os.WriteFile(filepath.Join(pdir, "gate-policy.yaml"), []byte("unmanaged_skills: [deny\n  : : :"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ := feed(t, `{"tool_name":"Skill","tool_input":{"skill":"some-plugin:thing"}}`)
	assertDeny(t, code, out, "not skillctl-managed")
}

// Guard the load directly: a MISSING policy keeps the safe default (allow), a
// broken one fails closed (deny). This pins the asymmetry SEC-L2 introduces.
func TestLoadGatePolicy_MissingVsBroken(t *testing.T) {
	t.Setenv("SKILLCTL_GATE_UNMANAGED", "")

	// Missing file → default allow.
	home1 := t.TempDir()
	t.Setenv("HOME", home1)
	if got := loadGatePolicy().Unmanaged; got != "allow" {
		t.Fatalf("missing policy: Unmanaged=%q, want allow (safe default)", got)
	}

	// Present-but-unknown-field file → deny (fail closed).
	home2 := t.TempDir()
	t.Setenv("HOME", home2)
	pdir := filepath.Join(home2, ".claude", "skillctl")
	if err := os.MkdirAll(pdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pdir, "gate-policy.yaml"), []byte("bogus_field: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := loadGatePolicy().Unmanaged; got != "deny" {
		t.Fatalf("broken policy: Unmanaged=%q, want deny (fail closed)", got)
	}
}

func TestSkillID_FallbackOrder(t *testing.T) {
	cases := []struct {
		in   hookToolInput
		want string
	}{
		{hookToolInput{Skill: "a"}, "a"},
		{hookToolInput{SkillName: "b"}, "b"},
		{hookToolInput{Name: "c"}, "c"},
		{hookToolInput{Skill: " a ", SkillName: "b"}, "a"}, // skill wins, trimmed
		{hookToolInput{}, ""},
	}
	for _, tc := range cases {
		if got := tc.in.skillID(); got != tc.want {
			t.Errorf("skillID(%+v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
