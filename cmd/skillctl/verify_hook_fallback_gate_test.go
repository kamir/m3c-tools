package main

// Tests for SPEC-0317 R-1.4 P2 — state-gating the verify-hook ONLINE fallback.
//
// The online §7 fallback (verifyManagedFn) runs ONLY for a LEGACY managed install
// with no stashed offline metadata (verifyManagedOfflineFn returns ok=false). When
// the enterprise `state_gate_fallback` opt-in is set, that fallback is SUPPRESSED
// outside the `online` state so the hot path stays strictly local: such an install
// fails CLOSED (exit 30 `offline_unverifiable_managed`) instead of blocking on an
// 8s network round-trip. The invariants under test:
//   - opted in + no offline metadata → deny, and the online seam is NEVER reached
//     (no network on the hot path);
//   - the shipped default (opt-out) still reaches the online fallback (byte-parity,
//     never-brick for disconnected non-enterprise hosts);
//   - an offline-verifiable install allows regardless (the gate is only consulted
//     on the legacy no-metadata branch);
//   - the REAL reader→compute path (managed settings → statemachine) suppresses,
//     and a trust basis keeps the host out of `locked` so we exercise R-1.4 P2, not
//     R-7.2.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/exitcode"
)

// withGateSkipFallback forces the R-1.4 P2 suppression seam and keeps the R-7.2
// `locked` rung inert, so a ladder test isolates the fallback decision from both
// the state machine internals and the test machine's real managed-settings file.
func withGateSkipFallback(t *testing.T, v bool) {
	t.Helper()
	orig := gateSkipOnlineFallback
	gateSkipOnlineFallback = func(string, time.Time) bool { return v }
	t.Cleanup(func() { gateSkipOnlineFallback = orig })
	origL := gateOfflineStateDeniesManaged
	gateOfflineStateDeniesManaged = func(string, time.Time) bool { return false }
	t.Cleanup(func() { gateOfflineStateDeniesManaged = origL })
}

// onlineSpy stubs the two §7 seams: the offline chain returns (0,"",ok) and the
// online chain records whether it was reached before returning an ALLOW — so a test
// can prove the gate blocked WITHOUT the online call even though it would allow.
func onlineSpy(t *testing.T, offlineOK bool) *bool {
	t.Helper()
	called := new(bool)
	of, oo := verifyManagedFn, verifyManagedOfflineFn
	verifyManagedFn = func(string, gatePolicy) (int, string) { *called = true; return exitOK, "" }
	verifyManagedOfflineFn = func(string, gatePolicy, string) (int, string, bool) {
		if offlineOK {
			return exitOK, "ok", true
		}
		return 0, "", false // legacy install: no offline metadata → falls through
	}
	t.Cleanup(func() { verifyManagedFn, verifyManagedOfflineFn = of, oo })
	return called
}

const skillEventNoSession = `{"tool_name":"Skill","tool_input":{"skill":"subject"}}`

// Opted in + legacy install → fail closed, and the network is never touched.
func TestGate_StateGateFallback_SuppressesOnlineFallback(t *testing.T) {
	withGateSkipFallback(t, true)
	home := t.TempDir()
	t.Setenv("HOME", home)
	mkManagedSkill(t, home, "subject")
	onlineCalled := onlineSpy(t, false)

	var out, errb bytes.Buffer
	code := runVerifyHook(strings.NewReader(skillEventNoSession), &out, &errb)
	if code != exitHookBlock {
		t.Fatalf("state-gated fallback must fail closed (exit %d), got %d (stderr=%s)", exitHookBlock, code, errb.String())
	}
	if *onlineCalled {
		t.Error("online §7 fallback must NOT be reached when the state-gate suppresses it (no network on the hot path)")
	}
	if !strings.Contains(errb.String(), "offline_unverifiable_managed") || !strings.Contains(errb.String(), "exit 25") {
		t.Errorf("expected an offline_unverifiable_managed deny naming exit 25:\n%s", errb.String())
	}
}

// The shipped default (opt-out) still reaches the online fallback for a legacy
// install — byte-parity / never-brick for disconnected non-enterprise hosts.
func TestGate_StateGateFallback_DefaultRunsOnlineFallback(t *testing.T) {
	withGateSkipFallback(t, false)
	home := t.TempDir()
	t.Setenv("HOME", home)
	mkManagedSkill(t, home, "subject")
	onlineCalled := onlineSpy(t, false)

	var out, errb bytes.Buffer
	code := runVerifyHook(strings.NewReader(skillEventNoSession), &out, &errb)
	if code != exitOK {
		t.Fatalf("default (opt-out) must reach the online fallback and allow, got %d (stderr=%s)", code, errb.String())
	}
	if !*onlineCalled {
		t.Error("default must reach the online §7 fallback for a legacy install (byte-parity preserved)")
	}
	if strings.Contains(errb.String(), "offline_unverifiable_managed") {
		t.Errorf("opt-out must never emit the unverifiable deny:\n%s", errb.String())
	}
}

// Opted in, but the install IS offline-verifiable → allow. The gate is only on the
// legacy no-metadata branch, so the online seam is never reached and no deny fires.
func TestGate_StateGateFallback_OfflineOkAllows(t *testing.T) {
	withGateSkipFallback(t, true)
	home := t.TempDir()
	t.Setenv("HOME", home)
	mkManagedSkill(t, home, "subject")
	onlineCalled := onlineSpy(t, true) // offline chain PASSES

	var out, errb bytes.Buffer
	code := runVerifyHook(strings.NewReader(`{"tool_name":"Skill","tool_input":{"skill":"subject"},"session_id":"s"}`), &out, &errb)
	if code != exitOK {
		t.Fatalf("an offline-verifiable install must allow even when state-gate is on, got %d (stderr=%s)", code, errb.String())
	}
	if *onlineCalled {
		t.Error("an offline PASS must short-circuit before the fallback gate (no online call)")
	}
	if strings.Contains(errb.String(), "offline_unverifiable_managed") {
		t.Errorf("must not emit the unverifiable deny when offline verify passed:\n%s", errb.String())
	}
}

// TestGate_StateGateFallback_RealPath exercises the REAL reader→compute chain
// (gateStateGatesFallback → defaultGateSkipOnlineFallback → statemachine.Compute),
// driven only by the managed-settings source seams. A trust basis (provenance
// sidecar) keeps the host OUT of `locked`, so the deny we observe is genuinely the
// R-1.4 P2 fallback suppression (exit 25), not the R-7.2 locked rung (exit 28).
func TestGate_StateGateFallback_RealPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	mkManagedSkill(t, home, "subject")
	sidecar := filepath.Join(home, ".claude", "skills", "subject", ".m3c-provenance.json")
	if err := os.WriteFile(sidecar, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Both enterprise knobs ON via their managed-settings readers (in production
	// --state-gate-fallback implies --enterprise, so both are set together).
	origEnt, origSGF := gateManagedEnterprise, gateStateGatesFallback
	gateManagedEnterprise = func() bool { return true }
	gateStateGatesFallback = func() bool { return true }
	t.Cleanup(func() { gateManagedEnterprise, gateStateGatesFallback = origEnt, origSGF })

	onlineCalled := onlineSpy(t, false) // legacy install, no offline metadata

	var out, errb bytes.Buffer
	code := runVerifyHook(strings.NewReader(skillEventNoSession), &out, &errb)
	if code != exitHookBlock || *onlineCalled || !strings.Contains(errb.String(), "offline_unverifiable_managed") {
		t.Fatalf("real path: opted-in + legacy install must suppress the fallback and deny (exit 25); code=%d onlineCalled=%v stderr=%s",
			code, *onlineCalled, errb.String())
	}
	if strings.Contains(errb.String(), "exit 28") {
		t.Errorf("a trust basis is present → must be offline_unverifiable (25), not locked (28):\n%s", errb.String())
	}
}

// TestGate_StateGateFallback_LockedWins is the R-7.2-vs-R-1.4-P2 precedence
// invariant: enterprise + state-gate-fallback ON but NO trust basis (no sidecar/
// roots) → the `locked` rung fires FIRST (exit 28 offline_locked), never the
// fallback-suppression deny (exit 25). If the two rungs were ever reordered, a
// no-trust-basis enterprise host would silently downgrade 28→25; this pins it.
func TestGate_StateGateFallback_LockedWins(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	mkManagedSkill(t, home, "subject") // NO sidecar / roots → no trust basis

	origEnt, origSGF := gateManagedEnterprise, gateStateGatesFallback
	gateManagedEnterprise = func() bool { return true }
	gateStateGatesFallback = func() bool { return true }
	t.Cleanup(func() { gateManagedEnterprise, gateStateGatesFallback = origEnt, origSGF })

	onlineCalled := onlineSpy(t, false)

	var out, errb bytes.Buffer
	code := runVerifyHook(strings.NewReader(skillEventNoSession), &out, &errb)
	if code != exitHookBlock || *onlineCalled {
		t.Fatalf("no trust basis must deny without touching the network; code=%d onlineCalled=%v stderr=%s",
			code, *onlineCalled, errb.String())
	}
	if !strings.Contains(errb.String(), "exit 28") || strings.Contains(errb.String(), "exit 25") {
		t.Errorf("locked must win over the fallback gate (exit 28, not 25):\n%s", errb.String())
	}
}

// TestGate_StateGateFallback_UnmanagedNotEscalated pins scope: even fully opted in,
// an UNMANAGED skill follows the unmanaged policy (default allow) and is NEVER
// escalated to the R-1.4 P2 deny — the suppression is structurally reachable only
// on the managed legacy branch.
func TestGate_StateGateFallback_UnmanagedNotEscalated(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	origSGF := gateStateGatesFallback
	gateStateGatesFallback = func() bool { return true } // fully opted in
	t.Cleanup(func() { gateStateGatesFallback = origSGF })
	origL := gateOfflineStateDeniesManaged
	gateOfflineStateDeniesManaged = func(string, time.Time) bool { return false }
	t.Cleanup(func() { gateOfflineStateDeniesManaged = origL })

	var out, errb bytes.Buffer
	code := runVerifyHook(strings.NewReader(`{"tool_name":"Skill","tool_input":{"skill":"some-plugin:thing"}}`), &out, &errb)
	if code != exitOK {
		t.Fatalf("an unmanaged skill under default-allow must exit %d even when opted in, got %d (stderr=%s)", exitOK, code, errb.String())
	}
	if strings.Contains(errb.String(), "offline_unverifiable_managed") {
		t.Errorf("R-1.4 P2 must never escalate an unmanaged skill:\n%s", errb.String())
	}
}

// Never-brick: with the opt-in OFF, the REAL compute path must NOT suppress — a
// disconnected non-enterprise host keeps its online fallback. This pins that
// gateStateGatesFallback is the sole switch (its false fast-paths before compute).
func TestGate_StateGateFallback_RealPath_OptOutKeepsFallback(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	mkManagedSkill(t, home, "subject")

	origSGF := gateStateGatesFallback
	gateStateGatesFallback = func() bool { return false } // opt-out (shipped default)
	t.Cleanup(func() { gateStateGatesFallback = origSGF })
	// Keep R-7.2 inert so only the fallback decision is under test.
	origL := gateOfflineStateDeniesManaged
	gateOfflineStateDeniesManaged = func(string, time.Time) bool { return false }
	t.Cleanup(func() { gateOfflineStateDeniesManaged = origL })

	onlineCalled := onlineSpy(t, false)

	var out, errb bytes.Buffer
	code := runVerifyHook(strings.NewReader(skillEventNoSession), &out, &errb)
	if code != exitOK || !*onlineCalled {
		t.Fatalf("opt-out real path must reach the online fallback and allow; code=%d onlineCalled=%v stderr=%s",
			code, *onlineCalled, errb.String())
	}
}

// The refusal token is the queryable Art.12 label for the deny.
func TestRefusalCode_OfflineUnverifiable(t *testing.T) {
	got := refusalCodeForHook(exitHookBlock,
		"offline_unverifiable_managed (state-gated online fallback; SPEC-0317 R-1.4 P2)")
	if got != "offline_unverifiable_managed" {
		t.Errorf("want offline_unverifiable_managed, got %q", got)
	}
}

// TestExitConsts_MatchRegistry binds the message-borne semantic exit numbers to the
// canonical exitcode registry, so a registry renumber can't silently drift from the
// hard-coded numbers in the deny messages + signed refusal records. Covers the
// R-1.4 P2 code and the sibling R-7.2 / R-8.2 codes (previously unpinned).
func TestExitConsts_MatchRegistry(t *testing.T) {
	for _, c := range []struct {
		name string
		got  int
		want exitcode.Code
	}{
		{"offline_unverifiable", exitOfflineUnverifiable, exitcode.OfflineUnverifiable},
		{"offline_locked", exitOfflineLocked, exitcode.OfflineLocked},
		{"local_audit_unavailable", exitLocalAuditUnavailable, exitcode.LocalAuditUnavailable},
	} {
		if c.got != c.want.Number {
			t.Errorf("%s: const %d != registry %d (%s) — messages would misreport the code",
				c.name, c.got, c.want.Number, c.want.Label)
		}
	}
}
