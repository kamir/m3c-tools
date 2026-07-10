package main

// Tests for `skillctl enforce` (SPEC-0317 P0).
//
// AC-1  — enforce is BYTE-IDENTICAL to verify-hook (exit + stdout + stderr) for
//         an allow and for every deny class. enforce must be a pure silent router
//         that only adds an outbox sink; it must never change a byte of output.
// AC-2a — DECISION-INVARIANCE: a forced outbox-write failure (a panicking sink)
//         leaves exit + stdout + stderr byte-identical to the healthy path, so the
//         SPEC-0255 landed contract is preserved.
//
// The §7 chain stays behind the verifyManagedFn / verifyManagedOfflineFn seams,
// stubbed here so the decision logic runs offline. Managed skills are faked with
// a stashed .skb under a temp $HOME.

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/outbox"
	"github.com/kamir/m3c-tools/pkg/skillgate"
)

// runOne executes a single gate function against event on a FRESH temp $HOME with
// the two verification seams stubbed to (retCode, retReason). Each call gets its
// own home so state written by one run (trail, verdict cache, outbox) can never
// leak into a comparison run — the only intended difference between enforce and
// verify-hook is the outbox side effect, never the (exit, stdout, stderr) tuple.
func runOne(t *testing.T, gate func(r *strings.Reader, o, e *bytes.Buffer) int, name, event string, retCode int, retReason string) (int, string, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	if name != "" {
		mkManagedSkill(t, home, name)
	}
	origF, origO := verifyManagedFn, verifyManagedOfflineFn
	verifyManagedFn = func(string, gatePolicy) (int, string) { return retCode, retReason }
	verifyManagedOfflineFn = func(string, gatePolicy, string) (int, string, bool) { return retCode, retReason, true }
	t.Cleanup(func() { verifyManagedFn, verifyManagedOfflineFn = origF, origO })
	// Hermetic: the shipped default reads the real platform managed-settings file
	// (root-owned /Library/…), which must never influence a unit test. Pin the
	// enterprise source OFF so the R-7.2 `locked` rung is inert here unless a test
	// explicitly overrides gateOfflineStateDeniesManaged (the higher seam runOne
	// leaves untouched).
	origEnt := gateManagedEnterprise
	gateManagedEnterprise = func() bool { return false }
	t.Cleanup(func() { gateManagedEnterprise = origEnt })
	// Same hermetic pin for the R-8.2 require_local_audit source: OFF unless a test
	// overrides it, so every runOne-based parity test keeps the fire-and-forget
	// contract regardless of the machine's real managed-settings file.
	origRLA := gateRequireLocalAudit
	gateRequireLocalAudit = func() bool { return false }
	t.Cleanup(func() { gateRequireLocalAudit = origRLA })

	var out, errb bytes.Buffer
	code := gate(strings.NewReader(event), &out, &errb)
	return code, out.String(), errb.String()
}

var hookViaVerify = func(r *strings.Reader, o, e *bytes.Buffer) int { return runVerifyHook(r, o, e) }
var hookViaEnforce = func(r *strings.Reader, o, e *bytes.Buffer) int { return runEnforce(r, o, e) }

// assertParity runs the same scenario through verify-hook and through enforce
// (each on its own fresh home) and asserts the (exit, stdout, stderr) tuples are
// byte-identical.
func assertParity(t *testing.T, label, name, event string, retCode int, retReason string) {
	t.Helper()
	vc, vo, ve := runOne(t, hookViaVerify, name, event, retCode, retReason)
	ec, eo, ee := runOne(t, hookViaEnforce, name, event, retCode, retReason)
	if vc != ec {
		t.Fatalf("[%s] exit: verify-hook=%d enforce=%d", label, vc, ec)
	}
	if vo != eo {
		t.Fatalf("[%s] stdout diverged:\n verify-hook=%q\n enforce   =%q", label, vo, eo)
	}
	if ve != ee {
		t.Fatalf("[%s] stderr diverged:\n verify-hook=%q\n enforce   =%q", label, ve, ee)
	}
}

// TestEnforce_ByteParity_AllowAndDenyClasses is AC-1: enforce matches verify-hook
// byte-for-byte across an allow and a representative set of deny classes.
func TestEnforce_ByteParity_AllowAndDenyClasses(t *testing.T) {
	skillEvent := `{"tool_name":"Skill","tool_input":{"skill":"subject"},"session_id":"s"}`

	cases := []struct {
		label  string
		name   string // "" → unmanaged/no skill dir
		event  string
		code   int
		reason string
	}{
		{"allow-managed", "subject", skillEvent, exitOK, ""},
		{"deny-author-sig", "subject", skillEvent, 11, "author signature invalid"},
		{"deny-digest-mismatch", "subject", skillEvent, 10, "bundle modified after signing (digest mismatch)"},
		{"deny-governance", "subject", skillEvent, 13, "governance below required minimum"},
		{"deny-revoked-author", "subject", skillEvent, 17, "author identity revoked"},
		// Non-managed / input-validation paths (seams not consulted):
		{"non-skill-tool", "", `{"tool_name":"Bash","tool_input":{"command":"ls"}}`, exitOK, ""},
		{"no-skill-field", "", `{"tool_name":"Skill","tool_input":{"args":"x"}}`, exitOK, ""},
		{"malformed-stdin", "", "not json at all", exitOK, ""},
		{"unsafe-name", "", `{"tool_name":"Skill","tool_input":{"skill":"../../etc/passwd"}}`, exitOK, ""},
	}
	for _, c := range cases {
		assertParity(t, c.label, c.name, c.event, c.code, c.reason)
	}
}

// TestEnforce_UnmanagedPolicyDeny_Parity checks a deny that comes from policy
// (unmanaged_skills=deny) rather than the §7 chain — a distinct deny class.
func TestEnforce_UnmanagedPolicyDeny_Parity(t *testing.T) {
	t.Setenv("SKILLCTL_GATE_UNMANAGED", "deny")
	event := `{"tool_name":"Skill","tool_input":{"skill":"some-plugin:thing"}}`
	assertParity(t, "unmanaged-policy-deny", "", event, exitOK, "")
}

// TestEnforce_WritesOutboxRow proves the added behaviour: on an allow decision,
// enforce lands exactly one write-once evidence row in the outbox whose signed
// payload re-verifies, and whose event_id matches the trail projection (dual-sink
// consistency).
func TestEnforce_WritesOutboxRow(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	mkManagedSkill(t, home, "subject")
	orig := verifyManagedOfflineFn
	verifyManagedOfflineFn = func(string, gatePolicy, string) (int, string, bool) { return exitOK, "ok", true }
	t.Cleanup(func() { verifyManagedOfflineFn = orig })

	var out, errb bytes.Buffer
	if code := runEnforce(strings.NewReader(`{"tool_name":"Skill","tool_input":{"skill":"subject"},"session_id":"s"}`), &out, &errb); code != exitOK {
		t.Fatalf("expected allow, got exit %d (stderr=%q)", code, errb.String())
	}

	st, err := outbox.Open(home)
	if err != nil {
		t.Fatalf("open outbox: %v", err)
	}
	defer st.Close()
	n, err := st.PendingCount()
	if err != nil {
		t.Fatalf("pending count: %v", err)
	}
	if n != 1 {
		t.Fatalf("outbox pending rows = %d, want exactly 1", n)
	}

	batch, err := st.PendingBatch(10)
	if err != nil {
		t.Fatalf("pending batch: %v", err)
	}
	row := batch[0]
	if row.Decision != "allow" || row.Tool != "Skill" || row.SkillName != "subject" {
		t.Fatalf("row index columns wrong: %+v", row)
	}
	// Dual-sink consistency: the outbox row's event_id must be one the signed
	// trail also carries (same fanned-out record). Re-derive the payload hash from
	// the stored payload_json and confirm it matches the column.
	var rec skillgate.InvocationRecord
	if err := json.Unmarshal([]byte(row.PayloadJSON), &rec); err != nil {
		t.Fatalf("payload_json not a record: %v", err)
	}
	if rec.EventID != row.EventID {
		t.Fatalf("event_id divergence: column=%q payload=%q", row.EventID, rec.EventID)
	}
	_, wantHash, err := outbox.RecordPayload(rec)
	if err != nil {
		t.Fatalf("re-derive payload: %v", err)
	}
	if wantHash != row.PayloadHash {
		t.Fatalf("payload_hash divergence: column=%q re-derived=%q", row.PayloadHash, wantHash)
	}
}

// TestEnforce_OutboxFailure_DecisionInvariant is AC-2a: with a panicking outbox
// sink, enforce's (exit, stdout, stderr) stays byte-identical to verify-hook —
// the SPEC-0255 decision-invariance contract holds even when the write blows up.
func TestEnforce_OutboxFailure_DecisionInvariant(t *testing.T) {
	// Force the sink to panic on every call.
	origSink := enforceOutboxSink
	enforceOutboxSink = func(string, skillgate.InvocationRecord) bool { panic("outbox is on fire") }
	t.Cleanup(func() { enforceOutboxSink = origSink })

	skillEvent := `{"tool_name":"Skill","tool_input":{"skill":"subject"},"session_id":"s"}`
	cases := []struct {
		label  string
		name   string
		event  string
		code   int
		reason string
	}{
		{"allow", "subject", skillEvent, exitOK, ""},
		{"deny", "subject", skillEvent, 11, "author signature invalid"},
	}
	for _, c := range cases {
		// verify-hook baseline (no sink) vs enforce with the panicking sink.
		vc, vo, ve := runOne(t, hookViaVerify, c.name, c.event, c.code, c.reason)
		ec, eo, ee := runOne(t, hookViaEnforce, c.name, c.event, c.code, c.reason)
		if vc != ec || vo != eo || ve != ee {
			t.Fatalf("[%s] outbox panic altered output:\n exit %d/%d\n stdout %q/%q\n stderr %q/%q",
				c.label, vc, ec, vo, eo, ve, ee)
		}
	}
}

// TestEnforce_OutboxFailure_StillDecidesAllow confirms a panicking sink does not
// even flip the exit code on the healthy allow path (the specific worst case: an
// outbox failure must not become a fail-open OR a spurious deny).
func TestEnforce_OutboxFailure_StillDecidesAllow(t *testing.T) {
	origSink := enforceOutboxSink
	enforceOutboxSink = func(string, skillgate.InvocationRecord) bool { panic("boom") }
	t.Cleanup(func() { enforceOutboxSink = origSink })

	code, out, _ := runOne(t, hookViaEnforce, "subject",
		`{"tool_name":"Skill","tool_input":{"skill":"subject"},"session_id":"s"}`, exitOK, "")
	if code != exitOK {
		t.Fatalf("outbox panic changed the decision: exit=%d, want %d (allow)", code, exitOK)
	}
	if strings.TrimSpace(out) != "" {
		t.Fatalf("allow must emit nothing on stdout, got %q", out)
	}
}
