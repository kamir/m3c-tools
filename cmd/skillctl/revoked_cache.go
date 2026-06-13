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
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"

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
}

func revokedCachePath(home string) string {
	return filepath.Join(home, ".claude", "skillctl", "revoked-digests.json")
}

func writeRevokedCache(home string, set map[string]struct{}) {
	digs := make([]string, 0, len(set))
	for d := range set {
		digs = append(digs, d)
	}
	sort.Strings(digs)
	b, _ := json.MarshalIndent(revokedCacheFile{Digests: digs, FetchedAt: sweepClockFn().UTC().Format(time.RFC3339)}, "", "  ")
	p := revokedCachePath(home)
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	_ = os.WriteFile(p, b, 0o644)
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

// fetchRevokedOnline fetches the live verified revoked-digest set and refreshes
// the cache. Fail-OPEN: any error → the cached set (possibly stale/empty),
// online=false. Never returns an error — revocation enforcement is best-effort
// availability, exactly as the offline-verify tradeoff documents.
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
	set, err := registry.FetchRevokedDigests(cfg, envOr("ER1_CONTEXT", "skills"), tr.PubKey())
	if err != nil {
		cached, _ := readRevokedCache(home, revokedCacheTTL)
		return cached, false
	}
	writeRevokedCache(home, set)
	return set, true
}

// installedSkillDigest reads the provenance sidecar's bundle_digest for an
// installed skill, or "" if there is no sidecar / it's unreadable.
func installedSkillDigest(home, name string) string {
	b, err := os.ReadFile(filepath.Join(home, ".claude", "skills", name, registry.ProvenanceSidecarName))
	if err != nil {
		return ""
	}
	var side registry.ProvenanceSidecar
	if json.Unmarshal(b, &side) != nil {
		return ""
	}
	return side.BundleDigest
}
