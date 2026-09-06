package pin

// Tests for the R-8.2 wiring (Welle-1 Befund 1.5): skillctlRequireLocalAudit is
// consumed ONLY by `skillctl enforce` (the escalation lives in runEnforce, not
// in runVerifyHook), so every managed file that sets the flag must wire the
// PreToolUse gate to enforce; Generate, Merge and Verify all participate:
//   - Generate(RequireLocalAudit) emits `<bin> enforce` instead of verify-hook;
//   - Merge(RequireLocalAudit) upgrades an existing verify-hook gate in place
//     (one gate hook, not two) and stays idempotent;
//   - Verify accepts either verb as the pinned gate, reports HasEnforceHook,
//     and flags the inert combination (flag set + verify-hook wiring).

import (
	"encoding/json"
	"strings"
	"testing"
)

// preToolUseGateCommands extracts every PreToolUse hook command under a
// covering (Skill) matcher from managed-settings bytes.
func preToolUseGateCommands(t *testing.T, settings []byte) []string {
	t.Helper()
	var doc struct {
		Hooks struct {
			PreToolUse []struct {
				Matcher string `json:"matcher"`
				Hooks   []struct {
					Command string `json:"command"`
					Timeout int    `json:"timeout"`
				} `json:"hooks"`
			} `json:"PreToolUse"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(settings, &doc); err != nil {
		t.Fatalf("unmarshal settings: %v\n%s", err, settings)
	}
	var cmds []string
	for _, m := range doc.Hooks.PreToolUse {
		if !preToolUseCovers(m.Matcher) {
			continue
		}
		for _, h := range m.Hooks {
			cmds = append(cmds, h.Command)
		}
	}
	return cmds
}

func TestGenerate_RequireLocalAudit_WiresEnforce(t *testing.T) {
	b, err := Generate(GenerateOptions{BinaryPath: "/usr/local/bin/skillctl", RequireLocalAudit: true})
	if err != nil {
		t.Fatal(err)
	}
	cmds := preToolUseGateCommands(t, b)
	if len(cmds) != 1 || cmds[0] != "/usr/local/bin/skillctl enforce" {
		t.Fatalf("require-local-audit must wire the enforce verb (the only consumer of the flag), got %q", cmds)
	}
	if !RequireLocalAuditFromBytes(b) {
		t.Error("generated settings must round-trip the R-8.2 flag")
	}
	res := Verify(b)
	if res.Level != LevelPinned {
		t.Errorf("enforce-wired settings must classify as pinned, got %s (%v)", res.Level, res.Findings)
	}
	if !res.HasEnforceHook || !res.HasVerifyHook {
		t.Errorf("expected HasEnforceHook + HasVerifyHook, got %+v", res)
	}
	for _, f := range res.Findings {
		if strings.Contains(f, "skillctlRequireLocalAudit") {
			t.Errorf("a correctly wired file must not carry the inert-flag finding: %s", f)
		}
	}
}

func TestGenerate_Default_KeepsVerifyHookVerb(t *testing.T) {
	b, err := Generate(GenerateOptions{BinaryPath: "/usr/local/bin/skillctl"})
	if err != nil {
		t.Fatal(err)
	}
	cmds := preToolUseGateCommands(t, b)
	if len(cmds) != 1 || cmds[0] != "/usr/local/bin/skillctl verify-hook" {
		t.Fatalf("without the flag the gate verb must stay verify-hook, got %q", cmds)
	}
}

// The drift detector: flag set, but the gate still runs verify-hook (the state
// every pre-fix `pin generate --require-local-audit` file is in). The gate is
// still pinned, but pin status must call out the never-enforced promise.
func TestVerify_RequireLocalAuditWithVerifyHookIsFlagged(t *testing.T) {
	stale := `{
	  "skillctlEnterprise": true,
	  "skillctlRequireLocalAudit": true,
	  "hooks": {
	    "SessionStart": [{"matcher":"*","hooks":[{"type":"command","command":"skillctl verify --all --quarantine"}]}],
	    "PreToolUse":   [{"matcher":"Skill","hooks":[{"type":"command","command":"skillctl verify-hook"}]}]
	  }
	}`
	res := Verify([]byte(stale))
	if !res.Pinned() {
		t.Fatalf("the gate itself IS pinned, got %s", res.Level)
	}
	if res.HasEnforceHook {
		t.Error("verify-hook wiring must not report HasEnforceHook")
	}
	found := false
	for _, f := range res.Findings {
		if strings.Contains(f, "skillctlRequireLocalAudit") && strings.Contains(f, "enforce") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the inert-flag finding, got %v", res.Findings)
	}
	// Without the enterprise key the R-8.2 reader is gated off, so no finding.
	nonEnt := strings.Replace(stale, `"skillctlEnterprise": true,`, "", 1)
	for _, f := range Verify([]byte(nonEnt)).Findings {
		if strings.Contains(f, "skillctlRequireLocalAudit") {
			t.Errorf("non-enterprise flag is gated off; no finding expected: %s", f)
		}
	}
}

// Upgrade path: `pin install --require-local-audit` on an ALREADY pinned host
// goes through Merge. The pre-existing verify-hook gate must be rewritten in
// place (same binary, timeout preserved, ONE gate hook), else the new flag is
// exactly as inert as the Generate bug this fixes.
func TestMerge_RequireLocalAuditUpgradesVerifyHookInPlace(t *testing.T) {
	existing := `{
	  "permissions": {"deny": ["WebFetch"]},
	  "hooks": {
	    "SessionStart": [{"matcher":"*","hooks":[{"type":"command","command":"/opt/sec/skillctl verify --all --quarantine","timeout":90}]}],
	    "PreToolUse":   [{"matcher":"Skill","hooks":[{"type":"command","command":"/opt/sec/skillctl verify-hook","timeout":33}]}]
	  }
	}`
	merged, err := Merge([]byte(existing), GenerateOptions{BinaryPath: "/usr/local/bin/skillctl", RequireLocalAudit: true})
	if err != nil {
		t.Fatal(err)
	}
	cmds := preToolUseGateCommands(t, merged)
	if len(cmds) != 1 || cmds[0] != "/opt/sec/skillctl enforce" {
		t.Fatalf("expected the existing gate upgraded in place (own binary kept, one hook), got %q\n%s", cmds, merged)
	}
	s := string(merged)
	if !strings.Contains(s, `"timeout": 33`) {
		t.Errorf("upgrade must preserve the hook's other keys (timeout):\n%s", s)
	}
	if !strings.Contains(s, "WebFetch") {
		t.Errorf("foreign policy must survive the merge:\n%s", s)
	}
	// Idempotent: merging again must not add a second gate hook.
	again, err := Merge(merged, GenerateOptions{BinaryPath: "/usr/local/bin/skillctl", RequireLocalAudit: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := preToolUseGateCommands(t, again); len(got) != 1 {
		t.Fatalf("merge must stay idempotent, got %q", got)
	}
}

// A quoted binary path survives the in-place upgrade with its quoting.
func TestMerge_RequireLocalAuditUpgradeKeepsQuoting(t *testing.T) {
	existing := `{"hooks":{"PreToolUse":[{"matcher":"Skill","hooks":[{"type":"command","command":"\"/Applications/My Tools/skillctl\" verify-hook"}]}]}}`
	merged, err := Merge([]byte(existing), GenerateOptions{BinaryPath: "/Applications/My Tools/skillctl", RequireLocalAudit: true})
	if err != nil {
		t.Fatal(err)
	}
	cmds := preToolUseGateCommands(t, merged)
	if len(cmds) != 1 || cmds[0] != `"/Applications/My Tools/skillctl" enforce` {
		t.Fatalf("quoted binary must stay one argv[0] after the upgrade, got %q", cmds)
	}
}

// The reverse direction: a plain (no-flag) merge over a file already wired to
// enforce must recognize it as the gate and not append a verify-hook twin.
func TestMerge_PlainPinAcceptsEnforceAsGate(t *testing.T) {
	existing := `{"hooks":{"PreToolUse":[{"matcher":"Skill","hooks":[{"type":"command","command":"skillctl enforce","timeout":20}]}],"SessionStart":[{"matcher":"*","hooks":[{"type":"command","command":"skillctl verify --all --quarantine"}]}]}}`
	merged, err := Merge([]byte(existing), GenerateOptions{BinaryPath: "skillctl"})
	if err != nil {
		t.Fatal(err)
	}
	if got := preToolUseGateCommands(t, merged); len(got) != 1 || got[0] != "skillctl enforce" {
		t.Fatalf("an enforce gate satisfies a plain pin (decision-identical superset), got %q", got)
	}
	res := Verify(merged)
	if !res.Pinned() || !res.HasEnforceHook {
		t.Errorf("enforce-wired file must verify as pinned with HasEnforceHook, got %+v", res)
	}
}

// Decoy hardening carries over to the new verb: shell control and non-skillctl
// binaries must not count as an enforce gate.
func TestVerify_EnforceDecoysRejected(t *testing.T) {
	for _, cmd := range []string{
		"skillctl enforce || true",
		"echo enforce",
		"skillctl enforce --extra",
		"skillctlenforce",
	} {
		j := `{"hooks":{"PreToolUse":[{"matcher":"Skill","hooks":[{"type":"command","command":"` + cmd + `"}]}]}}`
		res := Verify([]byte(j))
		if res.HasEnforceHook || res.HasVerifyHook {
			t.Errorf("decoy %q must not count as the gate", cmd)
		}
	}
}
