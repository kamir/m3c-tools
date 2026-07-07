package main

// FR-0045 kill-switch HARDENING tests — the enforcement negatives the 3-reviewer
// adversarial gate found missing (the ed25519 envelope had negatives; the
// ENFORCEMENT did not). Each test drives the REAL enforcement surface:
//
//   Fix A — the epoch/issued_at floor is authenticated against the pinned registry
//           key and is monotonic: it cannot be rolled back by rewriting the
//           unsigned json, and a replayed lower-epoch signed HEAD is rejected.
//   Fix B — a set-root mismatch retains last-known-good; a revoked digest still
//           denies at the gate (the truncated set cannot un-revoke a bundle).
//   Fix C — a digest placed in the SIGNED HEAD.emergency denies at the gate, with
//           no local emergency-deny.json present.
//   Fix D — the stale-revocation deny carries the machine-readable
//           `bundle_revocation_stale` refusal code on the signed invocation record.
//   +     — an adopted HEAD whose fetch then fails eventually DENIES once its
//           signed issued_at ages past max_staleness (not merely "floor kept").

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/er1"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// khSetupHome points HOME (and USERPROFILE for Windows parity) at a fresh temp
// dir so the gate + the registry SelfTrustRoots loader resolve into it.
func khSetupHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	return home
}

// khWriteSelfTrustRoots writes ~/.claude/trust-roots.yaml (registry.SelfTrustRoots)
// pinning pub, so verifiedAdoptedHead / readRevokedCacheHead / headEmergencyDenies-
// Digest re-verify a persisted signed HEAD against it.
func khWriteSelfTrustRoots(t *testing.T, home string, pub ed25519.PublicKey) {
	t.Helper()
	body := "registry: self\n" +
		"pubkey_b64: " + base64.StdEncoding.EncodeToString(pub) + "\n" +
		"governance_minimum: green\n"
	p := filepath.Join(home, ".claude", "trust-roots.yaml")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// khSignHead builds + ed25519-signs a revocation HEAD with priv.
func khSignHead(t *testing.T, priv ed25519.PrivateKey, epoch int, issuedAt time.Time, digests, emergency []string) map[string]any {
	t.Helper()
	h, err := registry.BuildRevocationHead(registry.RevocationHeadInput{
		Epoch: epoch, IssuedAt: issuedAt, Digests: digests, Emergency: emergency,
	})
	if err != nil {
		t.Fatalf("build head: %v", err)
	}
	if _, err := registry.SignEnvelopeSignature(priv, h); err != nil {
		t.Fatalf("sign head: %v", err)
	}
	return h
}

// khInstallSkill installs a managed skill (stashed .skb + provenance sidecar
// recording the bundle digest + author) and stubs the chain seams to ALLOW, so any
// deny that follows is purely the kill-switch enforcement under test.
func khInstallSkill(t *testing.T, home, skill, digest, author string) {
	t.Helper()
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
		Signatures: []registry.SignatureSidecar{{Role: "author", IdentityID: author}},
	}
	b, _ := json.Marshal(side)
	if err := os.WriteFile(filepath.Join(dir, registry.ProvenanceSidecarName), b, 0o644); err != nil {
		t.Fatal(err)
	}
	origOn := verifyManagedFn
	verifyManagedFn = func(string, gatePolicy) (int, string) { return exitOK, "" }
	origOff := verifyManagedOfflineFn
	verifyManagedOfflineFn = func(string, gatePolicy, string) (int, string, bool) { return exitOK, "", true }
	t.Cleanup(func() { verifyManagedFn = origOn; verifyManagedOfflineFn = origOff })
}

// --- Fix A — authenticated + monotonic floor ---

// TestRevokedFloor_UnforgeableViaUnsignedJson: with a signed HEAD present, the
// floor is derived from the RE-VERIFIED HEAD, so rewriting the unsigned json cannot
// roll it back (finding F2).
func TestRevokedFloor_UnforgeableViaUnsignedJson(t *testing.T) {
	home := khSetupHome(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	khWriteSelfTrustRoots(t, home, pub)
	dig := headTestDigest('a')
	set := map[string]struct{}{dig: {}}
	issued := time.Date(2026, 7, 6, 18, 0, 0, 0, time.UTC)

	fetchRevocationHeadFn = func(_ *er1.Config, _ string, _ ed25519.PublicKey) (map[string]any, bool) {
		return khSignHead(t, priv, 9, issued, []string{dig}, nil), true
	}
	defer func() { fetchRevocationHeadFn = nil }()

	if _, refreshed := applyFetchedRevokedSet(home, nil, "skills", pub, set); !refreshed {
		t.Fatalf("adopted set must be persisted (refreshed=true)")
	}
	if ep, iss := readRevokedCacheHead(home); ep != 9 || iss != "2026-07-06T18:00:00Z" {
		t.Fatalf("authenticated floor = %d,%q, want 9,<ts>", ep, iss)
	}

	// The cache file must be owner-only (0o600) — Fix A perms tightening.
	if fi, err := os.Stat(revokedCachePath(home)); err != nil {
		t.Fatal(err)
	} else if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("revoked cache perms = %o, want owner-only (no group/other bits)", perm)
	}

	// Attacker rewrites the UNSIGNED json to a lower epoch + older issued_at.
	writeRevokedCacheHead(home, set, 0, "2000-01-01T00:00:00Z")
	if ep, iss := readRevokedCacheHead(home); ep != 9 || iss != "2026-07-06T18:00:00Z" {
		t.Fatalf("floor rolled back via unsigned json: got %d,%q, want 9,<ts>", ep, iss)
	}
}

// TestRevokedFloor_ReplayedLowerEpochRejected: a validly-signed but OLDER HEAD
// replayed over the signed-head file cannot lower the floor below the high-water
// mark, and its (replayed) freshness is distrusted.
func TestRevokedFloor_ReplayedLowerEpochRejected(t *testing.T) {
	home := khSetupHome(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	khWriteSelfTrustRoots(t, home, pub)
	dig := headTestDigest('a')
	set := map[string]struct{}{dig: {}}

	// High-water mark 9 recorded in the unsigned json.
	writeRevokedCacheHead(home, set, 9, "2026-07-06T18:00:00Z")
	// Attacker replays a validly-signed, LOWER-epoch HEAD into the signed-head file.
	persistSignedHead(home, khSignHead(t, priv, 4, time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), []string{dig}, nil))

	ep, iss := readRevokedCacheHead(home)
	if ep != 9 {
		t.Fatalf("replayed lower-epoch HEAD lowered the floor: epoch %d, want 9 (high-water)", ep)
	}
	if iss != "" {
		t.Fatalf("replayed HEAD freshness must be distrusted (issued_at cleared), got %q", iss)
	}
}

// --- Fix B — set-root mismatch retains last-known-good; revoked digest still denies ---

func TestFetchedSetRootMismatch_RetainsAndDenies(t *testing.T) {
	home := khSetupHome(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	khWriteSelfTrustRoots(t, home, pub)
	dig := headTestDigest('a') // the revocation an attacker wants to drop

	// Prior last-known-good cache: contains the revoked digest, fresh, epoch 5.
	priorSet := map[string]struct{}{dig: {}}
	writeRevokedCacheHead(home, priorSet, 5, time.Now().Add(-1*time.Hour).UTC().Format(time.RFC3339))
	priorBytes, _ := os.ReadFile(revokedCachePath(home))

	// The registry's SIGNED HEAD still binds the FULL {dig} set at epoch 6.
	fetchRevocationHeadFn = func(_ *er1.Config, _ string, _ ed25519.PublicKey) (map[string]any, bool) {
		return khSignHead(t, priv, 6, time.Now().Add(-30*time.Minute), []string{dig}, nil), true
	}
	defer func() { fetchRevocationHeadFn = nil }()

	// The attacker-truncated fetch DROPS dig (empty set) → set-root mismatch.
	set, refreshed := applyFetchedRevokedSet(home, nil, "skills", pub, map[string]struct{}{})
	if refreshed {
		t.Fatalf("a set-root-mismatched (truncated) set must NOT refresh the cache")
	}
	if _, ok := set[dig]; !ok {
		t.Fatalf("prior good set must be retained (dig present); got %v", set)
	}
	// The on-disk cache is untouched (last-known-good retained, FetchedAt not bumped).
	if after, _ := os.ReadFile(revokedCachePath(home)); string(after) != string(priorBytes) {
		t.Fatalf("cache overwritten with truncated set:\n before=%s\n after=%s", priorBytes, after)
	}

	// And the RETAINED revoked digest STILL denies at the gate.
	khInstallSkill(t, home, "er1-push", dig, "id:author@m3c")
	code, out, _ := feed(t, hookEventFor("er1-push"))
	assertDeny(t, code, out, "revoked")
}

// --- Fix C — the signed HEAD's emergency list denies at the gate ---

func TestGate_SignedHeadEmergencyDenies(t *testing.T) {
	home := khSetupHome(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	khWriteSelfTrustRoots(t, home, pub)
	dig := headTestDigest('a')
	khInstallSkill(t, home, "er1-push", dig, "id:author@m3c")

	// No signed HEAD yet → allowed.
	if code, out, _ := feed(t, hookEventFor("er1-push")); code != exitOK {
		t.Fatalf("pre-emergency should allow, got %d out=%q", code, out)
	}

	// Registry burns the digest in the SIGNED HEAD.emergency — NO local
	// emergency-deny.json is present, proving the HEAD channel is enforced on its own.
	persistSignedHead(home, khSignHead(t, priv, 3, time.Now().Add(-1*time.Hour), []string{dig}, []string{dig}))
	if fileExists(emergencyDenyPath(home)) {
		t.Fatal("test invariant: no emergency-deny.json should be present")
	}

	code, out, _ := feed(t, hookEventFor("er1-push"))
	assertDeny(t, code, out, "emergency deny-list")
	if !strings.Contains(out, dig) {
		t.Fatalf("deny must cite the burned digest %q, got %q", dig, out)
	}
}

// A digest NOT in the signed HEAD.emergency is still allowed (no false-deny).
func TestGate_SignedHeadEmergencyNonListedAllowed(t *testing.T) {
	home := khSetupHome(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	khWriteSelfTrustRoots(t, home, pub)
	installed := headTestDigest('a')
	burned := headTestDigest('b') // a DIFFERENT digest is burned
	khInstallSkill(t, home, "er1-push", installed, "id:author@m3c")
	persistSignedHead(home, khSignHead(t, priv, 3, time.Now().Add(-1*time.Hour), []string{burned}, []string{burned}))

	code, out, _ := feed(t, hookEventFor("er1-push"))
	assertAllow(t, code, out)
}

// --- Fix D — the stale-revocation deny carries the bundle_revocation_stale code ---

func TestGate_StaleRevocation_RefusalCode(t *testing.T) {
	home := khSetupHome(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	khWriteSelfTrustRoots(t, home, pub)

	// Gate freshness policy: max_staleness 24h, fail-closed (via the loadRootsFn seam).
	origLoad := loadRootsFn
	loadRootsFn = func(string) (*verify.TrustRoots, *verify.TrustRoot, error) {
		return nil, &verify.TrustRoot{MaxStaleness: "24h", FailPolicy: "closed"}, nil
	}
	t.Cleanup(func() { loadRootsFn = origLoad })

	revoked := headTestDigest('b')   // the revoked set — NOT the skill's digest
	installed := headTestDigest('a') // the installed skill digest (not revoked/emergency)
	khInstallSkill(t, home, "er1-push", installed, "id:author@m3c")

	// Adopt a STALE HEAD (issued 48h ago) as the authenticated anchor.
	stale := time.Now().Add(-48 * time.Hour)
	persistSignedHead(home, khSignHead(t, priv, 5, stale, []string{revoked}, nil))
	writeRevokedCacheHead(home, map[string]struct{}{revoked: {}}, 5, stale.UTC().Format(time.RFC3339))

	code, out, _ := feed(t, hookEventFor("er1-push"))
	assertDeny(t, code, out, "revocation snapshot too stale")

	// The signed invocation record's machine-readable refusal_code is the "22"
	// semantic token — the qa exit-22 assertion the gate said was missing.
	data, err := os.ReadFile(invocationTrailPath(home))
	if err != nil {
		t.Fatalf("read invocation trail: %v", err)
	}
	if !strings.Contains(string(data), `"refusal_code":"bundle_revocation_stale"`) {
		t.Fatalf("stale-revocation refusal_code not asserted on the signed trail:\n%s", data)
	}
}

// --- Fix N1 — a present-but-unverifiable signed HEAD FAILS CLOSED (not no-op) ---

// TestGate_CorruptSignedHead_FailsClosed proves the regression fix: a one-byte
// corruption of revoked-head.signed.json must NOT flip the kill-switch open. On the
// OLD code readRevokedCacheHead returned issued_at="" for the corrupt HEAD and
// revocationSnapshotStale treated that identically to the ABSENT case (no anchor →
// allow); this test asserts the gate now DENIES. It also asserts the ABSENT case
// (with the same max_staleness policy) still no-ops, so pre-D2 installs are not
// bricked.
func TestGate_CorruptSignedHead_FailsClosed(t *testing.T) {
	home := khSetupHome(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	khWriteSelfTrustRoots(t, home, pub)

	origLoad := loadRootsFn
	loadRootsFn = func(string) (*verify.TrustRoots, *verify.TrustRoot, error) {
		return nil, &verify.TrustRoot{MaxStaleness: "24h", FailPolicy: "closed"}, nil
	}
	t.Cleanup(func() { loadRootsFn = origLoad })

	revoked := headTestDigest('b')
	installed := headTestDigest('a')
	khInstallSkill(t, home, "er1-push", installed, "id:author@m3c")

	// (0) ABSENT signed HEAD + no checkpoint, even WITH a max_staleness policy →
	// no-op (must not brick pre-D2 installs that never adopted a HEAD).
	if code, out, _ := feed(t, hookEventFor("er1-push")); code != exitOK {
		t.Fatalf("absent signed HEAD must no-op (allow), got %d out=%q", code, out)
	}

	// (1) A VALID, fresh signed HEAD → the gate allows (fresh anchor).
	fresh := time.Now().Add(-1 * time.Hour)
	persistSignedHead(home, khSignHead(t, priv, 5, fresh, []string{revoked}, nil))
	writeRevokedCacheHead(home, map[string]struct{}{revoked: {}}, 5, fresh.UTC().Format(time.RFC3339))
	if code, out, _ := feed(t, hookEventFor("er1-push")); code != exitOK {
		t.Fatalf("valid fresh signed HEAD should allow, got %d out=%q", code, out)
	}

	// (2) Corrupt the signed HEAD on disk (one-byte flip) → present-but-unverifiable.
	p := revokedHeadSignedPath(home)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)/2] ^= 0xff
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	// Sanity: it really no longer verifies.
	if _, ok := verifiedAdoptedHead(home); ok {
		t.Fatal("test invariant: the corrupted HEAD must not verify")
	}

	// The gate must now DENY (fail-closed) — the one-byte corruption must not open
	// the kill-switch. On the OLD code this fed() ALLOWED.
	code, out, _ := feed(t, hookEventFor("er1-push"))
	assertDeny(t, code, out, "signed revocation HEAD is present but")

	// The machine-readable refusal_code distinguishes tampering from mere staleness.
	data, err := os.ReadFile(invocationTrailPath(home))
	if err != nil {
		t.Fatalf("read invocation trail: %v", err)
	}
	if !strings.Contains(string(data), `"refusal_code":"bundle_revocation_head_untrusted"`) {
		t.Fatalf("tampered-HEAD refusal_code not asserted on the signed trail:\n%s", data)
	}
}

// --- fetch-failure eventually denies (not merely "floor kept") ---

func TestGate_AdoptedHeadFetchFailure_EventuallyDenies(t *testing.T) {
	home := khSetupHome(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	khWriteSelfTrustRoots(t, home, pub)

	origLoad := loadRootsFn
	loadRootsFn = func(string) (*verify.TrustRoots, *verify.TrustRoot, error) {
		return nil, &verify.TrustRoot{MaxStaleness: "24h", FailPolicy: "closed"}, nil
	}
	t.Cleanup(func() { loadRootsFn = origLoad })

	revoked := headTestDigest('b')
	installed := headTestDigest('a')
	khInstallSkill(t, home, "er1-push", installed, "id:author@m3c")

	// 1) A successful adopt whose issued_at is already 48h old (the last time the
	//    feed was reachable). Persists the signed HEAD + json floor at epoch 5.
	t0 := time.Now().Add(-48 * time.Hour)
	fetchRevocationHeadFn = func(_ *er1.Config, _ string, _ ed25519.PublicKey) (map[string]any, bool) {
		return khSignHead(t, priv, 5, t0, []string{revoked}, nil), true
	}
	if _, refreshed := applyFetchedRevokedSet(home, nil, "skills", pub, map[string]struct{}{revoked: {}}); !refreshed {
		t.Fatalf("initial adopt must persist (refreshed=true)")
	}

	// 2) The fetch now FAILS (no HEAD) → the floor is KEPT, never advanced.
	fetchRevocationHeadFn = func(_ *er1.Config, _ string, _ ed25519.PublicKey) (map[string]any, bool) {
		return nil, false
	}
	defer func() { fetchRevocationHeadFn = nil }()
	if ep, _, rej := adoptHeadOrKeepFloor(home, nil, "skills", pub, map[string]struct{}{revoked: {}}); ep != 5 || rej {
		t.Fatalf("fetch failure must keep the floor (epoch 5, not rejected), got ep=%d rej=%v", ep, rej)
	}

	// 3) With the anchor now 48h old and max_staleness 24h, the gate must DENY —
	//    not merely keep the floor. (The local cache TTL still looks fresh; the D4
	//    gate judges the SIGNED issued_at, which cannot be refreshed while the feed
	//    is down.)
	code, out, _ := feed(t, hookEventFor("er1-push"))
	assertDeny(t, code, out, "revocation snapshot too stale")
}
