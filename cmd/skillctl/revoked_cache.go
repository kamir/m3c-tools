package main

// revoked_cache.go — SPEC-0266 F1: post-install bundle-digest revocation.
//
// The per-invocation offline gate (verify-hook) and the install-time stash
// cannot see a BundleRevokedEvent published AFTER install. The SessionStart
// sweep is the online "revocation authority": it fetches the live revoked-digest
// set, QUARANTINES any installed skill whose digest is now revoked, and writes a
// short-TTL cache the offline gate consults so revocation also propagates to the
// fast per-invocation path until the next sweep.
//
// Fail-OPEN on fetch: if the registry is unreachable / unconfigured we fall back
// to the cache (or empty). We only ever quarantine a digest that is DEFINITELY
// in a verified revoked set — a fetch failure never false-quarantines.

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kamir/m3c-tools/pkg/er1"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

// revokedCacheTTL bounds how long the offline gate trusts a cached revoked set.
const revokedCacheTTL = 12 * time.Hour

// exitBundleRevoked is the exit/verdict code recorded when a skill is denied or
// quarantined because its bundle digest carries a BundleRevokedEvent. 17 is the
// SPEC-0198 revoke theme (exitcode.RevokeIdentityRevoked.Number).
const exitBundleRevoked = 17

// exitRevocationStale is the SPEC-0279 R3 code recorded when a skill is denied
// because the revocation snapshot is too stale to trust (fail-closed for a
// high-risk action past the trust-root max_staleness). 22 = verify.ExitRevocationStale.
// As with exitBundleRevoked, the verify-hook PROCESS still exits exitHookBlock (2)
// to block the call; 22 is carried in the human message + the signed refusal_code.
const exitRevocationStale = 22

type revokedCacheFile struct {
	Digests   []string `json:"digests"`
	FetchedAt string   `json:"fetched_at"`
	// Epoch / IssuedAt carry the last ADOPTED revocation HEAD (FR-0045 D3).
	// omitempty keeps legacy caches (pre-HEAD) valid: absent => epoch 0, "".
	// Epoch is the monotonicity floor for the next AdoptRevocationHead; IssuedAt
	// is the freshness anchor the gate (D4) evaluates against SPEC-0279.
	Epoch    int    `json:"epoch,omitempty"`
	IssuedAt string `json:"issued_at,omitempty"`
}

func revokedCachePath(home string) string {
	return filepath.Join(home, ".claude", "skillctl", "revoked-digests.json")
}

// revokedHeadSignedPath is the sibling file that stores the RAW BYTES of the last
// ADOPTED, ed25519-signed revocation HEAD (FR-0045 Fix A / finding F2). Because the
// envelope signature covers epoch/issued_at/emergency, re-verifying these bytes
// against the pinned registry key means the unsigned revoked-digests.json ALONE can
// no longer be rewritten to roll the floor back or drop an emergency digest — the
// values are authenticated, not merely cached. This is NOT a claim of being
// unforgeable: a same-uid attacker can still replace THIS file with a validly-signed
// OLDER HEAD, and combined with a rewrite of the unsigned high-water-mark can roll
// the floor back (the combined-vector residual documented in readRevokedCacheHeadRaw).
func revokedHeadSignedPath(home string) string {
	return filepath.Join(home, ".claude", "skillctl", "revoked-head.signed.json")
}

// writeRevokedCache persists the set with no HEAD freshness (epoch 0). Used by
// the SPEC-0266 set-only path and tests.
func writeRevokedCache(home string, set map[string]struct{}) {
	writeRevokedCacheHead(home, set, 0, "")
}

// writeRevokedCacheHead persists the set plus the adopted HEAD's epoch/issued_at.
func writeRevokedCacheHead(home string, set map[string]struct{}, epoch int, issuedAt string) {
	digs := make([]string, 0, len(set))
	for d := range set {
		digs = append(digs, d)
	}
	sort.Strings(digs)
	b, _ := json.MarshalIndent(revokedCacheFile{
		Digests:   digs,
		FetchedAt: sweepClockFn().UTC().Format(time.RFC3339),
		Epoch:     epoch,
		IssuedAt:  issuedAt,
	}, "", "  ")
	p := revokedCachePath(home)
	_ = os.MkdirAll(filepath.Dir(p), 0o700)
	// 0o600 (was 0o644): the revoked-digest floor is security state; a
	// world-readable cache leaks the revocation set and, more importantly, a
	// group/other-writable file would let a non-owner rewrite the epoch/issued_at
	// floor (finding F2 / hacker#1). Owner-only.
	_ = os.WriteFile(p, b, 0o600)
	// os.WriteFile does NOT chmod an EXISTING file, so a machine upgraded from the
	// pre-fix 0o644 cache would stay world-readable. Chmod after the write to
	// tighten it on first upgrade (best-effort; a chmod failure is not fatal).
	_ = os.Chmod(p, 0o600)
}

// persistSignedHead writes the raw bytes of a VERIFIED, adopted revocation HEAD to
// the sibling signed-head file (0o600). Called only from AdoptRevocationHead's
// success path (via adoptHeadOrKeepFloor) — the head passed here has already had
// its envelope signature + epoch monotonicity + set-root binding checked, so its
// bytes are a trustworthy anchor for a later re-verify (readRevokedCacheHead /
// headEmergencyDeniesDigest). Best-effort: a write failure just means the next
// read falls back to the unsigned json floor.
func persistSignedHead(home string, head map[string]any) {
	b, err := json.MarshalIndent(head, "", "  ")
	if err != nil {
		return
	}
	p := revokedHeadSignedPath(home)
	_ = os.MkdirAll(filepath.Dir(p), 0o700)
	_ = os.WriteFile(p, b, 0o600)
	// Tighten an existing (upgraded) file too — os.WriteFile won't chmod one that
	// already exists. Best-effort.
	_ = os.Chmod(p, 0o600)
}

// verifiedAdoptedHead loads the persisted signed HEAD and RE-VERIFIES its ed25519
// envelope signature against the pinned SelfTrustRoots registry key. ok=false when
// there is no signed HEAD on disk, the trust roots are unavailable, or the
// signature does not verify (a tampered/forged file). This is the single
// authenticator both the freshness floor (Fix A) and the HEAD emergency list
// (Fix C) route through, so neither can be forged without the registry key.
func verifiedAdoptedHead(home string) (map[string]any, bool) {
	p := revokedHeadSignedPath(home)
	if !fileExists(p) {
		return nil, false
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, false
	}
	var head map[string]any
	if json.Unmarshal(b, &head) != nil {
		return nil, false
	}
	tr, err := registry.LoadSelfTrustRoots("")
	if err != nil || tr == nil || len(tr.PubKey()) == 0 {
		return nil, false
	}
	if registry.VerifyEnvelopeSignature(tr.PubKey(), head) != nil {
		return nil, false
	}
	return head, true
}

// headEmergencyDeniesDigest reports whether the installed skill's bundle digest is
// on the ADOPTED signed HEAD's `emergency` list (FR-0045 Fix C / finding F4). The
// emergency set is read from the RE-VERIFIED HEAD (verifiedAdoptedHead), so a
// digest the registry placed in HEAD.emergency denies at the gate even with no
// local emergency-deny.json present, and the list cannot be edited without the
// registry key. Returns the matched token + true on a hit.
func headEmergencyDeniesDigest(home, digest string) (string, bool) {
	if strings.TrimSpace(digest) == "" {
		return "", false
	}
	head, ok := verifiedAdoptedHead(home)
	if !ok {
		return "", false
	}
	em, err := registry.HeadEmergency(head)
	if err != nil {
		return "", false
	}
	want := strings.ToLower(strings.TrimSpace(digest))
	for _, e := range em {
		if strings.ToLower(strings.TrimSpace(e)) == want {
			return e, true
		}
	}
	return "", false
}

// readRevokedCacheHeadRaw returns the epoch + issued_at as stored in the UNSIGNED
// revoked-digests.json (0 / "" if none or a legacy cache). This is the forgeable
// on-disk value; it doubles as the monotonic high-water-mark store — writeRevoked-
// CacheHead only ever writes it with an epoch that AdoptRevocationHead has already
// proven >= the prior floor, so it never decreases through the legitimate path.
//
// CAVEAT (documented same-uid residual): the high-water-mark lives in this UNSIGNED
// file, so the monotonic clamp is only same-uid-defeatable, NOT unforgeable. A
// process running as the owning uid can rewrite BOTH this json epoch AND replace
// the signed-head file with a validly-signed OLDER HEAD to roll the floor back
// (the "combined-vector rollback"). We defeat each SINGLE vector (json-only, or
// signed-head-only), which is all local-file state without a hardware root of trust
// can promise; the combined vector is a knowingly-accepted residual, not closed.
func readRevokedCacheHeadRaw(home string) (int, string) {
	b, err := os.ReadFile(revokedCachePath(home))
	if err != nil {
		return 0, ""
	}
	var rc revokedCacheFile
	if json.Unmarshal(b, &rc) != nil {
		return 0, ""
	}
	return rc.Epoch, rc.IssuedAt
}

// readRevokedCacheHead returns the AUTHENTICATED epoch + issued_at floor (FR-0045
// Fix A / finding F2). It is the rollback floor for the next AdoptRevocationHead
// and the freshness anchor the gate (D4) evaluates.
//
// If a persisted signed HEAD exists, its ed25519 envelope is RE-VERIFIED against
// the pinned SelfTrustRoots key and the floor is derived from the verified HEAD —
// so an attacker who rewrites the unsigned json cannot move the floor. The unsigned
// json is used ONLY when no signed HEAD is present (legacy / pre-adopt caches), and
// as the (same-uid-defeatable — see readRevokedCacheHeadRaw) high-water-mark store:
//
//   - a signed HEAD present but unverifiable (tampered/forged, or trust roots gone):
//     keep the high-water epoch and return issued_at="" to signal UNKNOWN freshness.
//     NB: "" here is NOT by itself a deny — a caller that ignores it would fail OPEN.
//     revocationSnapshotStale (N1) therefore separately detects this present-but-bad
//     state and fails closed for a high-risk action under a max_staleness policy,
//     mirroring freshness.go's "missing issued_at = infinitely stale" rule.
//   - a signed HEAD whose epoch is BELOW the high-water-mark is a replayed older
//     HEAD → reject its (lower) epoch and its freshness, keep the high-water floor.
func readRevokedCacheHead(home string) (int, string) {
	hwEpoch, jsonIssued := readRevokedCacheHeadRaw(home)

	if !fileExists(revokedHeadSignedPath(home)) {
		// No signed HEAD → fall back to the unsigned json (legacy / pre-adopt).
		return hwEpoch, jsonIssued
	}
	head, ok := verifiedAdoptedHead(home)
	if !ok {
		// Present but unverifiable → do NOT fall back to the (forgeable) json
		// freshness; keep the high-water epoch and return "" for UNKNOWN freshness.
		// The deny for this case lives in revocationSnapshotStale (N1) — returning
		// "" alone is not a deny.
		return hwEpoch, ""
	}
	epoch, eerr := registry.HeadEpoch(head)
	issuedAt, ierr := registry.HeadIssuedAt(head)
	if eerr != nil || ierr != nil {
		return hwEpoch, ""
	}
	// Monotonic high-water-mark: never accept a floor epoch below the highest
	// previously-verified epoch. A replayed older-but-validly-signed HEAD is
	// rejected — keep the floor and distrust the replay's freshness.
	if epoch < hwEpoch {
		return hwEpoch, ""
	}
	return epoch, issuedAt.UTC().Format(time.RFC3339)
}

// readRevokedCache returns the cached revoked set and whether it is within ttl.
func readRevokedCache(home string, ttl time.Duration) (map[string]struct{}, bool) {
	b, err := os.ReadFile(revokedCachePath(home))
	if err != nil {
		return map[string]struct{}{}, false
	}
	var rc revokedCacheFile
	if json.Unmarshal(b, &rc) != nil {
		return map[string]struct{}{}, false
	}
	fresh := false
	if t, e := time.Parse(time.RFC3339, rc.FetchedAt); e == nil && sweepClockFn().Sub(t) <= ttl {
		fresh = true
	}
	set := make(map[string]struct{}, len(rc.Digests))
	for _, d := range rc.Digests {
		set[d] = struct{}{}
	}
	return set, fresh
}

// sweepRevokedFn is the seam the sweep uses to obtain the revoked set; tests
// stub it. Production = fetchRevokedOnline. Returns (set, fetchedOnline).
var sweepRevokedFn = fetchRevokedOnline

// fetchRevocationHeadFn is the seam that fetches a signed revocation HEAD from
// the registry (FR-0045 D2 endpoint). nil until the HEAD endpoint ships; while
// nil, fetchRevokedOnline keeps the SPEC-0266 set-only behaviour (epoch floor is
// preserved, never advanced). Returns (head, ok); ok=false means "no head
// available" (not an error). Tests stub it.
var fetchRevocationHeadFn func(cfg *er1.Config, ctx string, pub ed25519.PublicKey) (map[string]any, bool)

// fetchRevokedOnline fetches the live verified revoked-digest set and refreshes
// the cache. Fail-OPEN on availability: any fetch error → the cached set
// (possibly stale/empty), online=false. Never returns an error — revocation
// enforcement is best-effort availability, exactly as the offline-verify tradeoff
// documents. When a signed HEAD is available it is adopted (freshness +
// rollback), and its epoch/issued_at are persisted for the gate (FR-0045 D3/D4).
func fetchRevokedOnline(home string) (map[string]struct{}, bool) {
	tr, err := registry.LoadSelfTrustRoots("")
	if err != nil || tr == nil || len(tr.PubKey()) == 0 {
		cached, _ := readRevokedCache(home, revokedCacheTTL)
		return cached, false
	}
	cfg, err := resolveER1Config(envOr("ER1_TARGET", "prod"))
	if err != nil {
		cached, _ := readRevokedCache(home, revokedCacheTTL)
		return cached, false
	}
	ctx := envOr("ER1_CONTEXT", "skills")
	set, err := registry.FetchRevokedDigests(cfg, ctx, tr.PubKey())
	if err != nil {
		cached, _ := readRevokedCache(home, revokedCacheTTL)
		return cached, false
	}
	return applyFetchedRevokedSet(home, cfg, ctx, tr.PubKey(), set)
}

// applyFetchedRevokedSet reconciles a freshly-fetched revoked set with the signed
// HEAD and decides the authoritative set to trust. On the happy path it adopts the
// HEAD (freshness + rollback), persists the set + floor, and returns (set, true).
//
// FR-0045 Fix B / finding F1 — when the signed HEAD verifies but binds a DIFFERENT
// revoked_set_root than the fetched set (ErrHeadSetRootMismatch), the fetched set
// is truncated/forged relative to the signed HEAD: we REFUSE to overwrite the cache
// with it, retain the prior last-known-good set, do NOT refresh FetchedAt (staleness
// accrues against the prior issued_at so the D4 gate can eventually fail closed),
// and return the prior set as authoritative (refreshed=false).
func applyFetchedRevokedSet(home string, cfg *er1.Config, ctx string, pub ed25519.PublicKey, set map[string]struct{}) (map[string]struct{}, bool) {
	epoch, issuedAt, setRejected := adoptHeadOrKeepFloor(home, cfg, ctx, pub, set)
	if setRejected {
		prior, _ := readRevokedCache(home, revokedCacheTTL)
		return prior, false
	}
	writeRevokedCacheHead(home, set, epoch, issuedAt)
	return set, true
}

// adoptHeadOrKeepFloor tries to adopt a signed HEAD for the freshly-fetched set.
// If there is no HEAD source, or the HEAD fails to verify (bad sig / rollback), it
// KEEPS the previously-persisted epoch as the floor and returns the prior issued_at
// — so the gate (D4) sees a non-advancing snapshot and applies its fail-closed
// staleness policy under trust-root config. A verified HEAD returns its epoch +
// issued_at to persist AND persists the signed HEAD bytes (Fix A) for a later
// authenticated re-verify.
//
// The third return, setRejected, is true ONLY for ErrHeadSetRootMismatch (finding
// F1): the HEAD verified but bound a different set-root, so the fetched set is
// truncated/forged and the caller MUST discard it and retain last-known-good.
func adoptHeadOrKeepFloor(home string, cfg *er1.Config, ctx string, pub ed25519.PublicKey, set map[string]struct{}) (int, string, bool) {
	prevEpoch, prevIssued := readRevokedCacheHead(home)
	if fetchRevocationHeadFn == nil {
		return prevEpoch, prevIssued, false
	}
	head, ok := fetchRevocationHeadFn(cfg, ctx, pub)
	if !ok {
		return prevEpoch, prevIssued, false
	}
	epoch, issued, aerr := registry.AdoptRevocationHead(pub, head, setToSortedSlice(set), prevEpoch)
	if aerr != nil {
		if errors.Is(aerr, registry.ErrHeadSetRootMismatch) {
			fmt.Fprintf(os.Stderr, "skillctl: revocation HEAD set-root mismatch (%v); REJECTING the fetched set as truncated/forged and retaining last-known-good (staleness accrues against prior issued_at)\n", aerr)
			return prevEpoch, prevIssued, true
		}
		fmt.Fprintf(os.Stderr, "skillctl: revocation HEAD rejected (%v); keeping epoch floor %d\n", aerr, prevEpoch)
		return prevEpoch, prevIssued, false
	}
	// Verified HEAD → persist its raw bytes as the authenticated floor / emergency
	// anchor (Fix A / Fix C).
	persistSignedHead(home, head)
	return epoch, issued.UTC().Format(time.RFC3339), false
}

func setToSortedSlice(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for d := range set {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// revocationHeadTimeout bounds the HEAD fetch. Short by design: this runs inside
// the best-effort sweep, so a slow/unreachable registry must not stall it.
const revocationHeadTimeout = 2 * time.Second

// fetchRevocationHeadOnline is the production wiring for fetchRevocationHeadFn
// (FR-0045 D5): it resolves the registry URL from trust-roots and GETs the signed
// HEAD from the FR-0045 D2 endpoint. Fail-safe: no trust roots / no registry URL /
// any fetch error → (nil, false), so the sweep keeps the prior epoch floor and the
// gate applies its own fail-closed staleness policy. main() installs this seam;
// tests leave it nil (the pre-D2 set-only behaviour).
func fetchRevocationHeadOnline(cfg *er1.Config, ctx string, pub ed25519.PublicKey) (map[string]any, bool) {
	_, root, err := loadRootsFn("")
	if err != nil || root == nil || strings.TrimSpace(root.RegistryURL) == "" {
		return nil, false
	}
	head, ferr := registry.FetchRevocationHead(root.RegistryURL, "", revocationHeadTimeout)
	if ferr != nil {
		return nil, false
	}
	return head, true
}

// installedSkillDigest reads the provenance sidecar's bundle_digest for an
// installed skill, or "" if there is no sidecar / it's unreadable.
func installedSkillDigest(home, name string) string {
	side, ok := loadInstalledSidecar(home, name)
	if !ok {
		return ""
	}
	return side.BundleDigest
}

// installedSkillAuthor reads the provenance sidecar's author identity (the
// identity_id of the "author"-role signature) for an installed skill, or "" if
// there is no sidecar / no author signature. Used by the runtime emergency gate
// so a burned AUTHOR (not just a burned digest) is denied on sight.
func installedSkillAuthor(home, name string) string {
	side, ok := loadInstalledSidecar(home, name)
	if !ok {
		return ""
	}
	for _, s := range side.Signatures {
		if s.Role == "author" && s.IdentityID != "" {
			return s.IdentityID
		}
	}
	return ""
}

// loadInstalledSidecar reads + decodes the provenance sidecar for an installed
// skill. ok=false when there is no sidecar / it is unreadable / malformed.
func loadInstalledSidecar(home, name string) (registry.ProvenanceSidecar, bool) {
	b, err := os.ReadFile(filepath.Join(home, ".claude", "skills", name, registry.ProvenanceSidecarName))
	if err != nil {
		return registry.ProvenanceSidecar{}, false
	}
	var side registry.ProvenanceSidecar
	if json.Unmarshal(b, &side) != nil {
		return registry.ProvenanceSidecar{}, false
	}
	return side, true
}
