package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillgate"
)

// guardTestHome creates a fake home with a real skill dir under ~/.claude/skills.
func guardTestHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	sk := filepath.Join(home, ".claude", "skills", "victim")
	if err := os.MkdirAll(sk, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sk, "SKILL.md"), []byte("body"), 0o644); err != nil {
		t.Fatal(err)
	}
	return home
}

// captureGuardSink swaps guardPathSink for a capturing one and restores it.
func captureGuardSink(t *testing.T) *[][]byte {
	t.Helper()
	var lines [][]byte
	orig := guardPathSink
	guardPathSink = func(home string, line []byte) error {
		cp := append([]byte(nil), line...)
		lines = append(lines, cp)
		return nil
	}
	t.Cleanup(func() { guardPathSink = orig })
	return &lines
}

func readEvent(tool, filePath string) string {
	ev := map[string]any{
		"tool_name":  tool,
		"session_id": "sess:guard",
		"tool_input": map[string]any{"file_path": filePath},
	}
	b, _ := json.Marshal(ev)
	return string(b)
}

func bashEvent(cmd string) string {
	ev := map[string]any{
		"tool_name":  "Bash",
		"session_id": "sess:guard",
		"tool_input": map[string]any{"command": cmd},
	}
	b, _ := json.Marshal(ev)
	return string(b)
}

func runGP(t *testing.T, args []string, stdinJSON string) (int, string, string) {
	t.Helper()
	var out, errB bytes.Buffer
	code := runGuardPath(args, strings.NewReader(stdinJSON), &out, &errB)
	return code, out.String(), errB.String()
}

// TestGuardPath_SymlinkedSkillPathResolves — R-6.2/AC-6: a Read reaching a skill
// through a symlink resolves to the real skill dir (a hit), NOT missed by a
// lexical check.
func TestGuardPath_SymlinkedSkillPathResolves(t *testing.T) {
	home := guardTestHome(t)
	skillsDir := filepath.Join(home, ".claude", "skills")
	realDir := filepath.Join(skillsDir, "victim")
	alias := filepath.Join(skillsDir, "alias")
	if err := os.Symlink(realDir, alias); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	lines := captureGuardSink(t)

	// Deny mode so a hit is observable as exit 2.
	code, _, _ := runGP(t, []string{"--home", home, "--deny"},
		readEvent("Read", filepath.Join(alias, "SKILL.md")))
	if code != exitHookBlock {
		t.Fatalf("symlinked skill Read: exit=%d, want %d (deny — the symlink must resolve to a hit)", code, exitHookBlock)
	}
	if len(*lines) != 1 {
		t.Fatalf("expected 1 guard event, got %d", len(*lines))
	}
	// The recorded target must be the RESOLVED real path, and the skill name derived.
	var rec guardPathLine
	if err := json.Unmarshal((*lines)[0], &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Decision != "deny" || rec.SkillName != "victim" {
		t.Errorf("guard event = %+v, want decision=deny skill=victim", rec)
	}
	if rec.DeviceSignatureB64 == "" {
		t.Error("guard event not device-signed")
	}
}

// TestGuardPath_SelfReadNotDenied — R-6.3/AC-6: skillctl's own inventory read is
// never denied, even in deny mode.
func TestGuardPath_SelfReadNotDenied(t *testing.T) {
	home := guardTestHome(t)
	victim := filepath.Join(home, ".claude", "skills", "victim", "SKILL.md")
	lines := captureGuardSink(t)

	code, _, _ := runGP(t, []string{"--home", home, "--deny"},
		bashEvent("skillctl compliance --inventory "+victim))
	if code != exitOK {
		t.Fatalf("self read: exit=%d, want %d (skillctl's own read must never be denied)", code, exitOK)
	}
	if len(*lines) != 0 {
		t.Errorf("self-exempt access must not emit a guard event; got %d", len(*lines))
	}
}

// TestGuardPath_CompoundSkillctlStillHits — R-6.3: self-exemption whitelists ONLY
// a SOLE skillctl command. A compound command (`skillctl …; cat <victim>`)
// forfeits the exemption, so the victim read still emits a skill-dir hit and,
// under --deny, is blocked (the escape must not defeat --deny nor blind the audit).
func TestGuardPath_CompoundSkillctlStillHits(t *testing.T) {
	home := guardTestHome(t)
	victim := filepath.Join(home, ".claude", "skills", "victim", "SKILL.md")
	lines := captureGuardSink(t)

	code, _, _ := runGP(t, []string{"--home", home, "--deny"},
		bashEvent("skillctl version; cat "+victim))
	if code != exitHookBlock {
		t.Fatalf("compound skillctl+victim: exit=%d, want %d (a chained command forfeits self-exemption)", code, exitHookBlock)
	}
	if len(*lines) != 1 {
		t.Fatalf("compound command must emit the skill-dir hit; got %d events", len(*lines))
	}
	var rec guardPathLine
	if err := json.Unmarshal((*lines)[0], &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Decision != "deny" || rec.SkillName != "victim" {
		t.Errorf("guard event = %+v, want decision=deny skill=victim", rec)
	}
}

// TestGuardPath_DenyOnlyInOptInMode — R-6.1/AC-6: a skill-dir Read is
// audited-allowed by default and denied ONLY in opt-in deny mode.
func TestGuardPath_DenyOnlyInOptInMode(t *testing.T) {
	home := guardTestHome(t)
	victim := filepath.Join(home, ".claude", "skills", "victim", "SKILL.md")

	// Default: audited-allow (exit 0) but a guard event IS recorded.
	lines := captureGuardSink(t)
	code, out, errOut := runGP(t, []string{"--home", home}, readEvent("Read", victim))
	if code != exitOK {
		t.Fatalf("default mode: exit=%d, want %d (audited-allow)", code, exitOK)
	}
	if out != "" || errOut != "" {
		t.Errorf("audited-allow must be silent; stdout=%q stderr=%q", out, errOut)
	}
	if len(*lines) != 1 || func() string {
		var r guardPathLine
		_ = json.Unmarshal((*lines)[0], &r)
		return r.Decision
	}() != "audited-allow" {
		t.Errorf("default mode must record one audited-allow event; got %d", len(*lines))
	}

	// Opt-in deny: exit 2 + three-way deny shape.
	code, out, errOut = runGP(t, []string{"--home", home, "--deny"}, readEvent("Read", victim))
	if code != exitHookBlock {
		t.Fatalf("deny mode: exit=%d, want %d", code, exitHookBlock)
	}
	if !strings.Contains(errOut, guardPathRefusalToken) {
		t.Errorf("deny stderr missing refusal token %q: %q", guardPathRefusalToken, errOut)
	}
	var dec hookDecisionOut
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &dec); err != nil {
		t.Fatalf("deny stdout is not a decision JSON: %v (%q)", err, out)
	}
	if dec.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("deny decision = %q, want deny", dec.HookSpecificOutput.PermissionDecision)
	}
}

// TestGuardPath_EnvOptInDeny — the SKILLCTL_GUARD_PATH env switch also engages
// deny mode (the enterprise-profile wiring reuses this switch).
func TestGuardPath_EnvOptInDeny(t *testing.T) {
	home := guardTestHome(t)
	victim := filepath.Join(home, ".claude", "skills", "victim", "SKILL.md")
	t.Setenv("SKILLCTL_GUARD_PATH", "deny")
	captureGuardSink(t)

	code, _, _ := runGP(t, []string{"--home", home}, readEvent("Read", victim))
	if code != exitHookBlock {
		t.Fatalf("env deny: exit=%d, want %d", code, exitHookBlock)
	}
}

// TestGuardPath_NonHitSilent — R-6.1 volume-bounding: a non-skill file op is a
// silent allow that emits NOTHING (even in deny mode).
func TestGuardPath_NonHitSilent(t *testing.T) {
	home := guardTestHome(t)
	lines := captureGuardSink(t)

	code, out, errOut := runGP(t, []string{"--home", home, "--deny"},
		readEvent("Read", filepath.Join(home, "notes.txt")))
	if code != exitOK {
		t.Fatalf("non-hit: exit=%d, want %d", code, exitOK)
	}
	if out != "" || errOut != "" {
		t.Errorf("non-hit must be silent; stdout=%q stderr=%q", out, errOut)
	}
	if len(*lines) != 0 {
		t.Errorf("non-hit must not emit a guard event; got %d", len(*lines))
	}
}

// TestGuardPath_SkillToolNotGuarded — the Skill tool is verify-hook's job; guard
// silently allows it so it never overrides the Skill decision.
func TestGuardPath_SkillToolNotGuarded(t *testing.T) {
	home := guardTestHome(t)
	captureGuardSink(t)
	ev := `{"tool_name":"Skill","tool_input":{"skill":"victim"}}`
	code, out, errOut := runGP(t, []string{"--home", home, "--deny"}, ev)
	if code != exitOK || out != "" || errOut != "" {
		t.Errorf("Skill tool must be a silent allow; exit=%d out=%q err=%q", code, out, errOut)
	}
}

// TestGuardPath_UnreadableFailsOpen — a malformed/empty event is a silent allow
// (fail-open; the guard is not a seal and must not block on its own parse fail).
func TestGuardPath_UnreadableFailsOpen(t *testing.T) {
	home := guardTestHome(t)
	for _, in := range []string{"", "   ", "{not json"} {
		code, out, errOut := runGP(t, []string{"--home", home, "--deny"}, in)
		if code != exitOK || out != "" || errOut != "" {
			t.Errorf("input %q: exit=%d out=%q err=%q, want silent allow", in, code, out, errOut)
		}
	}
}

// TestGuardPath_BashPathExtraction — a Bash command touching a skill file is
// classified from the extracted path arg.
func TestGuardPath_BashPathExtraction(t *testing.T) {
	home := guardTestHome(t)
	victim := filepath.Join(home, ".claude", "skills", "victim", "SKILL.md")
	captureGuardSink(t)
	code, _, _ := runGP(t, []string{"--home", home, "--deny"},
		bashEvent("cat "+victim+" | base64"))
	if code != exitHookBlock {
		t.Fatalf("bash skill read: exit=%d, want %d", code, exitHookBlock)
	}
}

// TestGuardPath_Explain prints the honest scope + coverage gaps and exits 0.
func TestGuardPath_Explain(t *testing.T) {
	code, out, _ := runGP(t, []string{"--explain"}, "")
	if code != exitOK {
		t.Fatalf("--explain exit=%d, want 0", code)
	}
	for _, want := range []string{"NOT A SEAL", "coverage gaps", "AUDITED-ALLOW", "/slash"} {
		if !strings.Contains(out, want) {
			t.Errorf("--explain output missing %q", want)
		}
	}
}

// TestGuardPath_EventReusesSignedVocabulary — the emitted event embeds a valid
// signed InvocationRecord with an inv: event id (no new vocabulary).
func TestGuardPath_EventReusesSignedVocabulary(t *testing.T) {
	home := guardTestHome(t)
	victim := filepath.Join(home, ".claude", "skills", "victim", "SKILL.md")
	lines := captureGuardSink(t)
	if code, _, _ := runGP(t, []string{"--home", home}, readEvent("Edit", victim)); code != exitOK {
		t.Fatalf("audited-allow exit=%d", code)
	}
	if len(*lines) != 1 {
		t.Fatalf("want 1 event, got %d", len(*lines))
	}
	var rec skillgate.InvocationRecord
	if err := json.Unmarshal((*lines)[0], &rec); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(rec.EventID, "inv:") {
		t.Errorf("event id %q does not reuse the inv: vocabulary", rec.EventID)
	}
	if rec.Schema != skillgate.InvocationSchema {
		t.Errorf("schema = %q, want %q", rec.Schema, skillgate.InvocationSchema)
	}
	if rec.Tool != "Edit" {
		t.Errorf("tool = %q, want Edit", rec.Tool)
	}
}

// TestLooksPathLike_CrossPlatform locks the Windows regression that made the
// Trust Surface (windows-latest) job red: a native `C:\...\SKILL.md` token
// carries no '/', no '~' and no leading '.', so a POSIX-only check classified
// it as "not a path" and the guard never fired.
func TestLooksPathLike_CrossPlatform(t *testing.T) {
	pathLike := []string{
		"/home/u/.claude/skills/x/SKILL.md",   // posix absolute
		"~/.claude/skills/x/SKILL.md",         // tilde
		"./relative/file",                     // leading dot
		".claude/skills/x",                    // leading dot
		`C:\Users\runner\.claude\skills\x.md`, // windows native
		`C:/Users/runner/skills/x.md`,         // windows w/ forward slashes
		`skills\x\SKILL.md`,                   // windows relative
		"C:file",                              // drive-qualified, no separator
	}
	for _, p := range pathLike {
		if !looksPathLike(p) {
			t.Errorf("looksPathLike(%q) = false, want true", p)
		}
	}
	notPathLike := []string{"", ".", "..", "cat", "base64", "skillctl", "version", "C", "5:30"}
	for _, p := range notPathLike {
		if looksPathLike(p) {
			t.Errorf("looksPathLike(%q) = true, want false", p)
		}
	}
}
