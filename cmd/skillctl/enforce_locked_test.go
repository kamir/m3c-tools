package main

// Tests for SPEC-0317 R-7.2 — the `locked` state wired into the runtime gate.
//
// locked = a MANAGED-ENTERPRISE host (opt-in via the root-owned managed settings)
// with NO trust basis at all (no trust roots, self/ER1 roots, or provenance
// sidecar) denies non-allowlisted managed skills (exit 28 `offline_locked`). It must:
//   - be REACHABLE (the whole point — the old file-existence trust-basis check
//     made it dead by construction);
//   - be INERT on every non-enterprise host (byte-parity preserved, never-brick);
//   - NEVER affect unmanaged skills.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// withGateLocked stubs the higher-level R-7.2 seam (which runOne leaves
// untouched) so a ladder test can force the locked outcome deterministically.
func withGateLocked(t *testing.T, v bool) {
	t.Helper()
	orig := gateOfflineStateDeniesManaged
	gateOfflineStateDeniesManaged = func(string, time.Time) bool { return v }
	t.Cleanup(func() { gateOfflineStateDeniesManaged = orig })
}

func TestGate_LockedDeniesManaged(t *testing.T) {
	withGateLocked(t, true)
	code, _, se := runOne(t, hookViaEnforce, "subject",
		`{"tool_name":"Skill","tool_input":{"skill":"subject"}}`, exitOK, "")
	if code != exitHookBlock {
		t.Fatalf("locked managed skill: want exit %d, got %d (stderr=%s)", exitHookBlock, code, se)
	}
	if !strings.Contains(se, "locked") || !strings.Contains(se, "exit 28") {
		t.Errorf("expected an offline_locked deny naming exit 28:\n%s", se)
	}
}

// Byte-parity holds when the rung is inert (the shipped, non-enterprise default).
func TestGate_LockedInertPreservesParity(t *testing.T) {
	withGateLocked(t, false)
	assertParity(t, "locked-inert-allow", "subject",
		`{"tool_name":"Skill","tool_input":{"skill":"subject"}}`, exitOK, "")
	assertParity(t, "locked-inert-deny", "subject",
		`{"tool_name":"Skill","tool_input":{"skill":"subject"}}`, 11, "author signature invalid")
}

// locked must NEVER touch unmanaged skills — they return via the unmanaged policy
// BEFORE the rung.
func TestGate_LockedNeverAffectsUnmanaged(t *testing.T) {
	withGateLocked(t, true) // even fully locked
	code, _, se := runOne(t, hookViaEnforce, "",
		`{"tool_name":"Skill","tool_input":{"skill":"some-plugin:thing"}}`, exitOK, "")
	if strings.Contains(se, "locked") {
		t.Errorf("locked must never affect an unmanaged skill:\n%s", se)
	}
	if code != exitOK {
		t.Errorf("unmanaged under shipped default (allow) should exit %d, got %d", exitOK, code)
	}
}

// The refusal token is the queryable Art.12 label for the deny.
func TestRefusalCode_OfflineLocked(t *testing.T) {
	got := refusalCodeForHook(exitHookBlock,
		"offline_locked (managed-enterprise, no trust basis; SPEC-0317 R-7.2)")
	if got != "offline_locked" {
		t.Errorf("want offline_locked, got %q", got)
	}
}

// TestGate_LockedReachable_RealPath exercises the REAL defaultGateOfflineStateDeniesManaged
// (resolve policy → gather inputs → Compute), driven only by the managed-enterprise
// source seam. It proves locked is genuinely reachable AND that any trust basis
// (here a provenance sidecar) lifts the host out of locked (never-brick breadth).
func TestGate_LockedReachable_RealPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	mkManagedSkill(t, home, "subject") // managed, but NO trust roots / sidecar → no trust basis

	// managed-enterprise ON via the ONLY enterprise source (managed settings).
	origEnt := gateManagedEnterprise
	gateManagedEnterprise = func() bool { return true }
	t.Cleanup(func() { gateManagedEnterprise = origEnt })

	// Stub the §7 chain to an ALLOW, so if the locked rung did NOT fire we would
	// wrongly see exit 0 — the test then only passes because locked denied first.
	of, oo := verifyManagedFn, verifyManagedOfflineFn
	verifyManagedFn = func(string, gatePolicy) (int, string) { return exitOK, "" }
	verifyManagedOfflineFn = func(string, gatePolicy, string) (int, string, bool) { return exitOK, "", true }
	t.Cleanup(func() { verifyManagedFn, verifyManagedOfflineFn = of, oo })

	event := `{"tool_name":"Skill","tool_input":{"skill":"subject"}}`

	var out, errb bytes.Buffer
	if code := runEnforce(strings.NewReader(event), &out, &errb); code != exitHookBlock ||
		!strings.Contains(errb.String(), "exit 28") {
		t.Fatalf("enterprise + no trust basis must LOCK (exit 28); got code=%d stderr=%s", code, errb.String())
	}

	// Add a trust basis (a provenance sidecar next to the skill) → NOT locked → the
	// stubbed allow wins. This is the never-brick breadth: a sidecar counts.
	sidecar := filepath.Join(home, ".claude", "skills", "subject", ".m3c-provenance.json")
	if err := os.WriteFile(sidecar, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	if code := runEnforce(strings.NewReader(event), &out, &errb); code != exitOK {
		t.Fatalf("with a trust basis (sidecar) the host must NOT lock; got code=%d stderr=%s", code, errb.String())
	}
}

// F2 (adversarial finding, honest scope): the operator allowlist (§9.4, read from
// the USER-owned gate-policy.yaml) sits ABOVE the locked rung, so a same-uid user
// can allowlist a specific managed skill past the lock. This test PINS that
// behaviour so the "non-allowlisted" wording stays honest.
func TestGate_LockedBypassedByAllowlist(t *testing.T) {
	withGateLocked(t, true) // host is fully locked
	home := t.TempDir()
	t.Setenv("HOME", home)
	mkManagedSkill(t, home, "subject")
	if err := os.MkdirAll(verdictDir(home), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(verdictDir(home), "gate-policy.yaml"),
		[]byte("allowlist:\n  - subject\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := runEnforce(strings.NewReader(`{"tool_name":"Skill","tool_input":{"skill":"subject"}}`), &out, &errb)
	if code != exitOK {
		t.Fatalf("an allowlisted skill must bypass locked (exit %d), got %d (stderr=%s)", exitOK, code, errb.String())
	}
	if strings.Contains(errb.String(), "locked") {
		t.Errorf("allowlisted skill must not hit the locked deny:\n%s", errb.String())
	}
}

// Never-brick breadth: a PRESENT-but-malformed skill-trust-roots.yaml still counts
// as a trust basis (file-existence breadth), so even a managed-enterprise host does
// NOT lock. Locking on a broken config would be exactly the brick R-7.2 forbids.
func TestGate_MalformedTrustRootsDoesNotLock(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	mkManagedSkill(t, home, "subject")
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude", "skill-trust-roots.yaml"),
		[]byte("this: is: : not: valid: yaml\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	origEnt := gateManagedEnterprise
	gateManagedEnterprise = func() bool { return true } // enterprise ON
	t.Cleanup(func() { gateManagedEnterprise = origEnt })
	of, oo := verifyManagedFn, verifyManagedOfflineFn
	verifyManagedFn = func(string, gatePolicy) (int, string) { return exitOK, "" }
	verifyManagedOfflineFn = func(string, gatePolicy, string) (int, string, bool) { return exitOK, "", true }
	t.Cleanup(func() { verifyManagedFn, verifyManagedOfflineFn = of, oo })

	var out, errb bytes.Buffer
	code := runEnforce(strings.NewReader(`{"tool_name":"Skill","tool_input":{"skill":"subject"}}`), &out, &errb)
	if code != exitOK || strings.Contains(errb.String(), "locked") {
		t.Fatalf("a present (even malformed) trust-roots file is a trust basis → must NOT lock; got code=%d stderr=%s", code, errb.String())
	}
}
