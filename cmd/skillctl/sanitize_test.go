package main

import (
	"strings"
	"testing"
)

// TestSafeCell: the git-registry render paths must strip terminal-escape and
// control bytes from untrusted repo-sourced fields (challenge-gate finding:
// a malicious rationale could rewrite `status: REVOKED` -> `ok`).
func TestSafeCell(t *testing.T) {
	// ANSI cursor-up + carriage-return spoof is neutralized (ESC + CR dropped).
	spoof := "green\x1b[3A\r    status:          ok"
	got := safeCell(spoof)
	if strings.ContainsRune(got, '\x1b') || strings.ContainsRune(got, '\r') || strings.ContainsRune(got, '\n') {
		t.Errorf("control chars survived: %q", got)
	}
	// The ESC + CR are dropped (so the cursor cannot move); the printable "[3A"
	// remnant stays as inert text, that is the correct, safe outcome.
	if got != "green[3A    status:          ok" {
		t.Errorf("safeCell = %q", got)
	}
	// A tab becomes a space (kept printable, not a layout break).
	if got := safeCell("a\tb"); got != "a b" {
		t.Errorf("tab handling: %q", got)
	}
	// Length is capped.
	if got := safeCell(strings.Repeat("x", 500)); len([]rune(got)) > 205 {
		t.Errorf("safeCell did not cap length: %d runes", len([]rune(got)))
	}
	// Clean input is unchanged.
	if got := safeCell("sha256:deadbeef"); got != "sha256:deadbeef" {
		t.Errorf("clean input mutated: %q", got)
	}
}
