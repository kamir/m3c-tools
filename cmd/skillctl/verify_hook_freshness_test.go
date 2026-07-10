package main

import (
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// TestRevocationSnapshotStale exercises the FR-0045 D4 fail-closed freshness gate
// on the bundle-revocation snapshot: stale + a max_staleness policy denies a
// high-risk skill invocation; anything short of that (no anchor, fresh, or no
// policy) is a no-op so existing installs are not bricked.
func TestRevocationSnapshotStale(t *testing.T) {
	origLoad := loadRootsFn
	defer func() { loadRootsFn = origLoad }()

	withPolicy := func(maxStaleness string) {
		loadRootsFn = func(string) (*verify.TrustRoots, *verify.TrustRoot, error) {
			return nil, &verify.TrustRoot{MaxStaleness: maxStaleness, FailPolicy: "closed"}, nil
		}
	}
	set := map[string]struct{}{headTestDigest('a'): {}}
	stale := time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339)
	fresh := time.Now().UTC().Format(time.RFC3339)

	t.Run("no signed anchor -> no deny (pre-D2 behaviour preserved)", func(t *testing.T) {
		home := t.TempDir()
		writeRevokedCache(home, set) // epoch 0, issued_at ""
		withPolicy("24h")
		if deny, _, _ := revocationSnapshotStale(home, "s"); deny {
			t.Errorf("denied with no signed anchor")
		}
	})

	t.Run("stale anchor + max_staleness policy -> DENY (fail-closed)", func(t *testing.T) {
		home := t.TempDir()
		writeRevokedCacheHead(home, set, 5, stale)
		withPolicy("24h")
		deny, reason, msg := revocationSnapshotStale(home, "s")
		if !deny || reason != "bundle_revocation_stale" {
			t.Fatalf("stale not fail-closed: deny=%v reason=%q", deny, reason)
		}
		if msg == "" {
			t.Errorf("empty deny message")
		}
	})

	t.Run("fresh anchor + policy -> no deny", func(t *testing.T) {
		home := t.TempDir()
		writeRevokedCacheHead(home, set, 5, fresh)
		withPolicy("24h")
		if deny, _, _ := revocationSnapshotStale(home, "s"); deny {
			t.Errorf("fresh anchor denied")
		}
	})

	t.Run("anchor present but no max_staleness policy -> no deny (opt-in)", func(t *testing.T) {
		home := t.TempDir()
		writeRevokedCacheHead(home, set, 5, stale)
		withPolicy("") // no ceiling configured
		if deny, _, _ := revocationSnapshotStale(home, "s"); deny {
			t.Errorf("denied without a max_staleness policy (should be opt-in)")
		}
	})
}
