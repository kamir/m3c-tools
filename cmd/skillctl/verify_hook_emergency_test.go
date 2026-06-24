package main

// SPEC-0279 P4 (review finding #1, the merge-blocker) — the EMERGENCY DENY-LIST
// is consulted for the installed bundle DIGEST + AUTHOR at the runtime SPEC-0247
// gate, FIRST and UNCONDITIONALLY:
//
//   - with NO AgentID mandate configured (the common case the old code skipped);
//   - even when the SPEC-0266 sweep cache is STALE (the cadence cannot keep a
//     burned bundle alive);
//   - a present-but-forged emergency file fails CLOSED;
//   - a non-listed digest/author is still ALLOWED (no false-deny).
//
// These drive the REAL gate (runVerifyHook) — the emergency check runs before the
// revoked-cache, the verdict cache and the chain — with a managed skill carrying
// a provenance sidecar (digest + author) and a signed emergency list at the
// conventional gate path (~/.claude/skillctl/emergency-deny.json).

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/signing"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// emergencyGateEnv is a managed skill + pinned default trust-roots, with NO
// AgentID mandate (proving the emergency check is independent of the mandate).
type emergencyGateEnv struct {
	home string
	f    agentFixture
}

// setupEmergencyGate builds the fixture, installs its trust-roots at the default
// path the gate's loadRootsFn("") resolves, and installs a managed skill with a
// provenance sidecar recording the bundle digest + author identity. The skill
// chain seam is stubbed to ALLOW so any deny is purely the emergency channel.
func setupEmergencyGate(t *testing.T, skill, digest, author string) emergencyGateEnv {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // Windows: os.UserHomeDir() reads %USERPROFILE%, not $HOME — without this loadRootsFn("") misses the test trust-root and fails closed.

	f := buildAgentFixture(t, false)
	defaultTR := filepath.Join(home, ".claude", "skill-trust-roots.yaml")
	if err := os.MkdirAll(filepath.Dir(defaultTR), 0o755); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(f.trPath)
	if err := os.WriteFile(defaultTR, data, 0o600); err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(home, ".claude", "skills", skill)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, skill+".skb"), []byte("blob"), 0o644); err != nil {
		t.Fatal(err)
	}
	side := registry.ProvenanceSidecar{
		SchemaVersion: registry.ProvenanceSchemaVersion, Skill: skill, Version: "1.0.0",
		BundleDigest: digest, Registry: "self", GovernanceLevel: "green",
		Signatures: []registry.SignatureSidecar{
			{Role: "author", IdentityID: author},
		},
	}
	b, _ := json.Marshal(side)
	if err := os.WriteFile(filepath.Join(dir, registry.ProvenanceSidecarName), b, 0o644); err != nil {
		t.Fatal(err)
	}

	// Skill chain passes (we are testing the emergency channel, not the chain).
	origOn := verifyManagedFn
	verifyManagedFn = func(string, gatePolicy) (int, string) { return exitOK, "" }
	origOff := verifyManagedOfflineFn
	verifyManagedOfflineFn = func(string, gatePolicy, string) (int, string, bool) { return exitOK, "", true }
	t.Cleanup(func() { verifyManagedFn = origOn; verifyManagedOfflineFn = origOff })

	return emergencyGateEnv{home: home, f: f}
}

// writeEmergencyAt signs an emergency deny-list with the given key and writes it
// to the gate's conventional path.
func (e emergencyGateEnv) writeEmergencyAt(t *testing.T, priv ed25519.PrivateKey, tokens ...string) {
	t.Helper()
	em, err := verify.NewSignedEmergencyDenyList(e.f.regURL, signing.FormatAttestationTimestamp(time.Now().Add(-10*time.Minute)), 1, tokens, priv)
	if err != nil {
		t.Fatal(err)
	}
	p := emergencyDenyPath(e.home)
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	writeJSON(t, p, em)
}

func (e emergencyGateEnv) regKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	priv, err := signing.LoadPrivateKey(e.f.regKeyPath)
	if err != nil {
		t.Fatalf("load reg key: %v", err)
	}
	return priv
}

// (a) An emergency-listed DIGEST is denied at the runtime gate with NO AgentID
// mandate configured — the common case the old code skipped entirely.
func TestVerifyHookEmergency_DigestDenied_NoMandate(t *testing.T) {
	e := setupEmergencyGate(t, "er1-push", "sha256:beef", "id:author@m3c")
	// Pre-emergency: allowed (no mandate, chain passes).
	if code, out, _ := feed(t, hookEventFor("er1-push")); code != exitOK {
		t.Fatalf("pre-emergency should allow, got %d out=%q", code, out)
	}
	// Burn the digest.
	e.writeEmergencyAt(t, e.regKey(t), "sha256:beef")
	code, out, _ := feed(t, hookEventFor("er1-push"))
	assertDeny(t, code, out, "emergency deny-list")
	if !strings.Contains(out, "sha256:beef") {
		t.Fatalf("deny must cite the burned digest token, got %q", out)
	}
}

// An emergency-listed AUTHOR identity is denied (burns everything that author
// signed), with no mandate.
func TestVerifyHookEmergency_AuthorDenied_NoMandate(t *testing.T) {
	e := setupEmergencyGate(t, "er1-push", "sha256:cafe", "id:badactor@m3c")
	e.writeEmergencyAt(t, e.regKey(t), "id:badactor@m3c")
	code, out, _ := feed(t, hookEventFor("er1-push"))
	assertDeny(t, code, out, "emergency deny-list")
}

// (b) An emergency-listed digest is denied even when the SPEC-0266 sweep cache is
// STALE — the cadence (which SKIPS the revoked-digest check when not fresh) can
// NOT keep a burned bundle alive. This is the exact hole the merge-blocker named.
func TestVerifyHookEmergency_DigestDenied_StaleSweepCache(t *testing.T) {
	e := setupEmergencyGate(t, "er1-push", "sha256:beef", "id:author@m3c")
	// A STALE revoked cache (fetched_at far in the past) → readRevokedCache returns
	// fresh=false, so the revoked-digest gate is skipped entirely.
	stale := `{"digests":[],"fetched_at":"2000-01-01T00:00:00Z"}`
	cp := revokedCachePath(e.home)
	_ = os.MkdirAll(filepath.Dir(cp), 0o755)
	if err := os.WriteFile(cp, []byte(stale), 0o644); err != nil {
		t.Fatal(err)
	}
	// Burn the digest via the emergency channel.
	e.writeEmergencyAt(t, e.regKey(t), "sha256:beef")
	code, out, _ := feed(t, hookEventFor("er1-push"))
	assertDeny(t, code, out, "emergency deny-list")
	if !strings.Contains(out, "regardless of cache freshness") {
		t.Fatalf("deny must announce it short-circuits the cache cadence, got %q", out)
	}
}

// A forged emergency file (signed by an unpinned key) at the gate path fails
// CLOSED — the gate refuses the skill rather than ignore an operator-placed list.
func TestVerifyHookEmergency_ForgedFile_FailsClosed(t *testing.T) {
	e := setupEmergencyGate(t, "er1-push", "sha256:beef", "id:author@m3c")
	_, forged, _ := ed25519.GenerateKey(rand.Reader)
	// The forged list does not even name our digest — fail-closed must deny anyway.
	e.writeEmergencyAt(t, forged, "sha256:someoneelse")
	code, out, _ := feed(t, hookEventFor("er1-push"))
	assertDeny(t, code, out, "emergency deny-list")
}

// A non-listed digest/author is still ALLOWED (no false-deny): the emergency list
// names a DIFFERENT digest.
func TestVerifyHookEmergency_NonListedAllowed(t *testing.T) {
	e := setupEmergencyGate(t, "er1-push", "sha256:beef", "id:author@m3c")
	e.writeEmergencyAt(t, e.regKey(t), "sha256:adifferentbundle", "id:someoneelse@m3c")
	code, out, _ := feed(t, hookEventFor("er1-push"))
	assertAllow(t, code, out)
}
