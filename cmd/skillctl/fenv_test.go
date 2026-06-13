package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

// TestGatePolicy_RejectsBogusUnmanaged proves SEC F-ENV: a bogus
// SKILLCTL_GATE_UNMANAGED value (an attacker hitting the permissive default
// branch, or a typo) FAILS CLOSED to deny with a WARN.
func TestGatePolicy_RejectsBogusUnmanaged(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // no policy file → start from default
	t.Setenv("SKILLCTL_GATE_UNMANAGED", "allowall")
	var warn bytes.Buffer
	p := loadGatePolicyW(&warn)
	if p.Unmanaged != "deny" {
		t.Errorf("bogus SKILLCTL_GATE_UNMANAGED must fail closed to deny, got %q", p.Unmanaged)
	}
	if !strings.Contains(warn.String(), "failing closed") {
		t.Errorf("expected a fail-closed WARN; got %q", warn.String())
	}
}

// TestGatePolicy_AcceptsValidUnmanaged confirms the legitimate values still work.
func TestGatePolicy_AcceptsValidUnmanaged(t *testing.T) {
	for _, v := range []string{"deny", "warn", "allow"} {
		t.Setenv("HOME", t.TempDir())
		t.Setenv("SKILLCTL_GATE_UNMANAGED", v)
		if got := loadGatePolicyW(io.Discard).Unmanaged; got != v {
			t.Errorf("SKILLCTL_GATE_UNMANAGED=%q → Unmanaged=%q, want %q", v, got, v)
		}
	}
}
