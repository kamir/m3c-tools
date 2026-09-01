package main

// Tests for SPEC-0202 §9 — the verify-hook deferred block emits ONE
// device-signed invocation record per gated skill, for BOTH allow AND deny,
// into the separate signed trail. Asserts the record is written AND verifies.

import (
	"testing"
)

func TestHook_EmitsSignedTrailRecord_OnAllow(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	mkManagedSkill(t, home, "good")
	orig := verifyManagedOfflineFn
	verifyManagedOfflineFn = func(string, gatePolicy, string) (int, string, bool) { return exitOK, "ok", true }
	t.Cleanup(func() { verifyManagedOfflineFn = orig })

	if c, _, _ := feed(t, `{"tool_name":"Skill","tool_input":{"skill":"good"},"session_id":"sess-allow"}`); c != exitOK {
		t.Fatalf("expected allow, got exit %d", c)
	}

	tv := readAndVerifyTrail(home)
	if tv.Total != 1 || tv.Verified != 1 {
		t.Fatalf("signed trail = %+v, want 1 verified record on allow", tv)
	}
}

func TestHook_EmitsSignedTrailRecord_OnDeny(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	mkManagedSkill(t, home, "bad")
	orig := verifyManagedOfflineFn
	verifyManagedOfflineFn = func(string, gatePolicy, string) (int, string, bool) {
		return 11, "author signature invalid", true
	}
	t.Cleanup(func() { verifyManagedOfflineFn = orig })

	c, _, _ := feed(t, `{"tool_name":"Skill","tool_input":{"skill":"bad"},"session_id":"sess-deny"}`)
	if c != exitHookBlock {
		t.Fatalf("expected deny (exit %d), got %d", exitHookBlock, c)
	}

	tv := readAndVerifyTrail(home)
	if tv.Total != 1 || tv.Verified != 1 {
		t.Fatalf("signed trail = %+v, want 1 verified record on deny", tv)
	}
}

func TestHook_SignedTrailIsSeparateFromGateAudit(t *testing.T) {
	// The two logs are distinct files (unambiguous trust posture).
	home := t.TempDir()
	t.Setenv("HOME", home)
	mkManagedSkill(t, home, "good")
	orig := verifyManagedOfflineFn
	verifyManagedOfflineFn = func(string, gatePolicy, string) (int, string, bool) { return exitOK, "ok", true }
	t.Cleanup(func() { verifyManagedOfflineFn = orig })

	_, _, _ = feed(t, `{"tool_name":"Skill","tool_input":{"skill":"good"},"session_id":"s"}`)

	if gateAuditPath(home) == invocationTrailPath(home) {
		t.Fatalf("advisory and signed logs share a path")
	}
	// Both exist; the gate-audit is unsigned, the trail is signed.
	if evs := readGateAudit(t, home); len(evs) != 1 {
		t.Errorf("gate-audit advisory log missing")
	}
	if tv := readAndVerifyTrail(home); tv.Total != 1 {
		t.Errorf("signed trail missing")
	}
}
