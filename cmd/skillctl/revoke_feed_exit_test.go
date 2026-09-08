package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// AUDIT-0001 Befund 2.1 follow-up. `skillctl revoke feed --refresh` is the one
// path under the `revoke` verb that leaves the 0/1/2/15 space: on a MANAGED host
// whose revoked-set fetch is unavailable it fails closed with 22, the same
// revocation_stale number the PreToolUse gate and the `verify --all` sweep use,
// so one script branch catches the signal at all three sites.
//
// The number is documented in docs/CLI-VERBS.md and docs/manual-skillctl.md, and
// cmd/exitaudit cannot check it: exitaudit reads documents, and only `pull` is
// read as code. This test is the missing half.
func TestRevokeFeedRefresh_ManagedFetchUnavailable_Exits22(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // windows

	// A trust-roots.yaml that is PRESENT but unloadable makes the host managed
	// (selfTrustPosture: corruption must not downgrade to fail-open) while
	// leaving no pinned key, so the revoked-set fetch is unavailable and there
	// is no authenticated grace cache to bound the staleness.
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	roots := filepath.Join(home, ".claude", "trust-roots.yaml")
	if err := os.WriteFile(roots, []byte("registry: self\npubkey_b64: \"!!!not-base64!!!\"\n"), 0o600); err != nil {
		t.Fatalf("write trust-roots: %v", err)
	}

	var out, errb bytes.Buffer
	if got := runRevokeFeed([]string{"--refresh"}, &out, &errb); got != exitRevocationStale {
		t.Fatalf("runRevokeFeed --refresh = %d, want %d (fail-closed under managed trust roots)\nstderr: %s",
			got, exitRevocationStale, errb.String())
	}
}
