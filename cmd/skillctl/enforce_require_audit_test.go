package main

// Tests for SPEC-0317 R-8.2 — require_local_audit, the OPT-IN inversion of the
// SPEC-0255 fire-and-forget contract.
//
// When require_local_audit is set (managed settings, enterprise-gated), a skill
// ALLOW whose evidence could not be durably recorded (outbox + spool both failed)
// is escalated to a fail-closed deny (exit 26). Everything else is unchanged:
//   - flag unset → decision-invariance preserved (covered by TestEnforce_OutboxFailure_*);
//   - a DENY already stands (never re-escalated);
//   - a non-Skill / no-skill passthrough allow is NOT audited → NOT escalated.
//
// These tests set the seams MANUALLY (not via runOne, which pins
// gateRequireLocalAudit OFF for hermeticity and would clobber the value here).

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/outbox"
	"github.com/kamir/m3c-tools/pkg/skillgate"
)

// runEnforceGatedSkill sets up a managed skill on a fresh $HOME with the §7 chain
// stubbed to (verifyCode, verifyReason) and the locked path pinned OFF, then runs
// enforce for that skill. The require_local_audit source and the outbox durability
// are left to the CALLER's seams (set before invoking).
func runEnforceGatedSkill(t *testing.T, skill string, verifyCode int, verifyReason string) (int, string, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	mkManagedSkill(t, home, skill)
	oe := gateManagedEnterprise
	gateManagedEnterprise = func() bool { return false } // keep the R-7.2 locked rung inert
	t.Cleanup(func() { gateManagedEnterprise = oe })
	of, oo := verifyManagedFn, verifyManagedOfflineFn
	verifyManagedFn = func(string, gatePolicy) (int, string) { return verifyCode, verifyReason }
	verifyManagedOfflineFn = func(string, gatePolicy, string) (int, string, bool) { return verifyCode, verifyReason, true }
	t.Cleanup(func() { verifyManagedFn, verifyManagedOfflineFn = of, oo })

	var out, errb bytes.Buffer
	code := runEnforce(strings.NewReader(
		`{"tool_name":"Skill","tool_input":{"skill":"`+skill+`"},"session_id":"s"}`), &out, &errb)
	return code, out.String(), errb.String()
}

func withRequireLocalAudit(t *testing.T, v bool) {
	t.Helper()
	orig := gateRequireLocalAudit
	gateRequireLocalAudit = func() bool { return v }
	t.Cleanup(func() { gateRequireLocalAudit = orig })
}
func withOutboxDurable(t *testing.T, ok bool) {
	t.Helper()
	orig := enforceOutboxSink
	enforceOutboxSink = func(string, skillgate.InvocationRecord) bool { return ok }
	t.Cleanup(func() { enforceOutboxSink = orig })
}

// Headline R-8.2: an allow that could not be durably recorded fails closed (26).
func TestRequireLocalAudit_UnrecordableAllowFailsClosed(t *testing.T) {
	withRequireLocalAudit(t, true)
	withOutboxDurable(t, false) // outbox + spool both failed
	code, _, se := runEnforceGatedSkill(t, "subject", exitOK, "")
	if code != exitHookBlock {
		t.Fatalf("require_local_audit + unrecordable allow: want exit %d, got %d (stderr=%s)", exitHookBlock, code, se)
	}
	if !strings.Contains(se, "exit 26") || !strings.Contains(se, "require_local_audit") {
		t.Errorf("expected a local_audit_unavailable deny naming exit 26:\n%s", se)
	}
}

// A durable write → the allow stands.
func TestRequireLocalAudit_DurableAllowPasses(t *testing.T) {
	withRequireLocalAudit(t, true)
	withOutboxDurable(t, true) // recorded (outbox or spool)
	code, out, _ := runEnforceGatedSkill(t, "subject", exitOK, "")
	if code != exitOK {
		t.Fatalf("durable allow must pass, got exit %d", code)
	}
	if strings.TrimSpace(out) != "" {
		t.Errorf("a passing allow must emit nothing, got %q", out)
	}
}

// A DENY is never re-escalated — it keeps its own reason (not exit 26).
func TestRequireLocalAudit_DenyIsUnchanged(t *testing.T) {
	withRequireLocalAudit(t, true)
	withOutboxDurable(t, false) // even with a failed write
	code, _, se := runEnforceGatedSkill(t, "subject", 11, "author signature invalid")
	if code != exitHookBlock {
		t.Fatalf("deny should exit %d, got %d", exitHookBlock, code)
	}
	if strings.Contains(se, "local_audit_unavailable") || strings.Contains(se, "exit 26") {
		t.Errorf("a real deny must keep its own reason, not the audit deny:\n%s", se)
	}
	if !strings.Contains(se, "author signature invalid") {
		t.Errorf("expected the original deny reason:\n%s", se)
	}
}

// THE critical false-positive guard: a non-Skill tool (Bash/Read/…) and a
// no-skill-field event are passthrough allows — nothing is gated, so
// require_local_audit must NOT escalate them even with a failing outbox.
// Breaking this would deny every file op on an enterprise host.
func TestRequireLocalAudit_PassthroughNotEscalated(t *testing.T) {
	withRequireLocalAudit(t, true)
	withOutboxDurable(t, false)
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, ev := range []string{
		`{"tool_name":"Bash","tool_input":{"command":"ls"}}`,
		`{"tool_name":"Skill","tool_input":{"args":"x"}}`, // Skill tool, no skill field
	} {
		var out, errb bytes.Buffer
		code := runEnforce(strings.NewReader(ev), &out, &errb)
		if code != exitOK {
			t.Fatalf("passthrough %q must allow (exit %d), got %d (stderr=%s)", ev, exitOK, code, errb.String())
		}
	}
}

// F1 regression: a CORRUPT outbox.db on a WRITABLE dir must NOT spuriously deny.
// The real sink spools directly (no db I/O) when Open fails → durable → the allow
// stands, and the evidence lands — so a fail-closed deny can never coexist with a
// trail that recorded the allow.
func TestRequireLocalAudit_OpenFailSpoolsNotSpuriousDeny(t *testing.T) {
	withRequireLocalAudit(t, true)
	// NOTE: exercise the REAL enforceOutboxSink here — do NOT stub it.
	home := t.TempDir()
	t.Setenv("HOME", home)
	mkManagedSkill(t, home, "subject")
	oe := gateManagedEnterprise
	gateManagedEnterprise = func() bool { return false }
	t.Cleanup(func() { gateManagedEnterprise = oe })
	of, oo := verifyManagedFn, verifyManagedOfflineFn
	verifyManagedFn = func(string, gatePolicy) (int, string) { return exitOK, "" }
	verifyManagedOfflineFn = func(string, gatePolicy, string) (int, string, bool) { return exitOK, "", true }
	t.Cleanup(func() { verifyManagedFn, verifyManagedOfflineFn = of, oo })

	// Corrupt the db so outbox.Open fails, but keep the dir writable.
	if err := os.MkdirAll(filepath.Dir(outbox.DBPath(home)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outbox.DBPath(home), []byte("not a sqlite database"), 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errb bytes.Buffer
	code := runEnforce(strings.NewReader(
		`{"tool_name":"Skill","tool_input":{"skill":"subject"},"session_id":"s"}`), &out, &errb)
	if code != exitOK {
		t.Fatalf("corrupt db on a writable dir must NOT spuriously deny (F1): got exit %d stderr=%s", code, errb.String())
	}
	spool := filepath.Join(home, ".claude", "skillctl", "spool.jsonl")
	if b, err := os.ReadFile(spool); err != nil || len(b) == 0 {
		t.Fatalf("expected a spooled record after Open failure (durability = writable dir); read err=%v len=%d", err, len(b))
	}
}

// F2: require_local_audit escalates UNMANAGED (default-allow) skill allows too —
// on an unrecordable outbox it denies the plugin ecosystem. Documented posture.
func TestRequireLocalAudit_UnmanagedAllowEscalated(t *testing.T) {
	withRequireLocalAudit(t, true)
	withOutboxDurable(t, false)
	home := t.TempDir()
	t.Setenv("HOME", home)
	oe := gateManagedEnterprise
	gateManagedEnterprise = func() bool { return false }
	t.Cleanup(func() { gateManagedEnterprise = oe })

	var out, errb bytes.Buffer
	code := runEnforce(strings.NewReader(
		`{"tool_name":"Skill","tool_input":{"skill":"some-plugin:thing"},"session_id":"s"}`), &out, &errb)
	if code != exitHookBlock || !strings.Contains(errb.String(), "exit 26") {
		t.Fatalf("an unmanaged allow under require_local_audit + failed outbox must escalate to exit 26; got %d stderr=%s", code, errb.String())
	}
}
