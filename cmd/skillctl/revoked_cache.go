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
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	_ = os.WriteFile(p, b, 0o644)
}

// readRevokedCacheHead returns the epoch + issued_at persisted from the last
// adopted HEAD (0 / "" if none or a legacy cache). The epoch is the rollback
// floor for the next AdoptRevocationHead; issued_at feeds the gate freshness
// policy (D4).
func readRevokedCacheHead(home string) (int, string) {
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
	epoch, issuedAt := adoptHeadOrKeepFloor(home, cfg, ctx, tr.PubKey(), set)
	writeRevokedCacheHead(home, set, epoch, issuedAt)
	return set, true
}

// adoptHeadOrKeepFloor tries to adopt a signed HEAD for the freshly-fetched set.
// If there is no HEAD source, or the HEAD fails to verify (bad sig / rollback /
// set-root mismatch), it KEEPS the previously-persisted epoch as the floor and
// returns the prior issued_at — so the gate (D4) sees a non-advancing snapshot
// and applies its fail-closed staleness policy under trust-root config. A
// verified HEAD returns its epoch + issued_at to persist.
func adoptHeadOrKeepFloor(home string, cfg *er1.Config, ctx string, pub ed25519.PublicKey, set map[string]struct{}) (int, string) {
	prevEpoch, prevIssued := readRevokedCacheHead(home)
	if fetchRevocationHeadFn == nil {
		return prevEpoch, prevIssued
	}
	head, ok := fetchRevocationHeadFn(cfg, ctx, pub)
	if !ok {
		return prevEpoch, prevIssued
	}
	epoch, issued, aerr := registry.AdoptRevocationHead(pub, head, setToSortedSlice(set), prevEpoch)
	if aerr != nil {
		fmt.Fprintf(os.Stderr, "skillctl: revocation HEAD rejected (%v); keeping epoch floor %d\n", aerr, prevEpoch)
		return prevEpoch, prevIssued
	}
	return epoch, issued.UTC().Format(time.RFC3339)
}

func setToSortedSlice(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for d := range set {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
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
