package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

// writeSidecarDigest installs a minimal managed skill (stashed .skb + sidecar
// recording bundleDigest) under home.
func writeSidecarDigest(t *testing.T, home, name, bundleDigest string) {
	t.Helper()
	dir := filepath.Join(home, ".claude", "skills", name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# "+name), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".skb"), []byte("blob"), 0o644); err != nil {
		t.Fatal(err)
	}
	side := registry.ProvenanceSidecar{
		SchemaVersion: registry.ProvenanceSchemaVersion, Skill: name, Version: "1.0.0",
		BundleDigest: bundleDigest, Registry: "self", GovernanceLevel: "green",
	}
	b, _ := json.Marshal(side)
	if err := os.WriteFile(filepath.Join(dir, registry.ProvenanceSidecarName), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestVerifyHook_RevokedBundle_Denied proves SPEC-0266 F1 on the offline gate:
// a fresh revoked-digest cache entry for the installed skill's digest → DENY,
// without any network.
func TestVerifyHook_RevokedBundle_Denied(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeSidecarDigest(t, home, "er1-push", "sha256:beef")
	writeRevokedCache(home, map[string]struct{}{"sha256:beef": {}}) // fetched_at = now → fresh

	code, out, _ := feed(t, `{"tool_name":"Skill","tool_input":{"skill":"er1-push"}}`)
	assertDeny(t, code, out, "revoked")
}

// TestVerifyHook_StaleRevokedCache_NotEnforced ensures an EXPIRED cache is not
// used (the sweep is the authority; a stale cache must not block indefinitely).
func TestVerifyHook_StaleRevokedCache_NotEnforced(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeSidecarDigest(t, home, "er1-push", "sha256:beef")
	// Hand-write a cache with a long-past fetched_at so it is not fresh.
	stale := `{"digests":["sha256:beef"],"fetched_at":"2000-01-01T00:00:00Z"}`
	p := revokedCachePath(home)
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(stale), 0o644); err != nil {
		t.Fatal(err)
	}
	// Stub the managed verify to ALLOW so a non-revoked outcome is reachable.
	orig := verifyManagedFn
	verifyManagedFn = func(string, gatePolicy) (int, string) { return exitOK, "" }
	verifyManagedOfflineFn2 := verifyManagedOfflineFn
	verifyManagedOfflineFn = func(string, gatePolicy, string) (int, string, bool) { return 0, "", false }
	t.Cleanup(func() { verifyManagedFn = orig; verifyManagedOfflineFn = verifyManagedOfflineFn2 })

	code, _, _ := feed(t, `{"tool_name":"Skill","tool_input":{"skill":"er1-push"}}`)
	if code == exitHookBlock {
		t.Errorf("a STALE revoked cache must not block (sweep is the authority); got deny")
	}
}

// TestSweep_RevokedBundle_Quarantined proves F1 on the sweep: a managed skill
// whose digest is in the (stubbed) live revoked set is quarantined regardless of
// its §7 result.
func TestSweep_RevokedBundle_Quarantined(t *testing.T) {
	home := t.TempDir()
	writeSidecarDigest(t, home, "er1-push", "sha256:dead")

	orig := sweepRevokedFn
	sweepRevokedFn = func(string) (map[string]struct{}, bool) {
		return map[string]struct{}{"sha256:dead": {}}, true
	}
	t.Cleanup(func() { sweepRevokedFn = orig })

	code, out := runSweep(t, home, "--quarantine")
	_ = code
	if q, _ := quarantined(t, home, "er1-push"); !q {
		t.Errorf("revoked skill must be quarantined by the sweep; out=\n%s", out)
	}
}
