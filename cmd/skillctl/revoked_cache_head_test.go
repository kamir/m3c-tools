package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/er1"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

func headTestDigest(c byte) string { return "sha256:" + strings.Repeat(string(c), 64) }

func TestRevokedCacheHead_RoundTrip(t *testing.T) {
	home := t.TempDir()
	set := map[string]struct{}{headTestDigest('a'): {}}

	writeRevokedCacheHead(home, set, 7, "2026-07-06T18:00:00Z")
	if ep, iss := readRevokedCacheHead(home); ep != 7 || iss != "2026-07-06T18:00:00Z" {
		t.Fatalf("head round-trip = %d,%q", ep, iss)
	}
	// A legacy set-only write (pre-HEAD) reads back as 0,"" — backward compatible.
	writeRevokedCache(home, set)
	if ep, iss := readRevokedCacheHead(home); ep != 0 || iss != "" {
		t.Errorf("legacy head = %d,%q, want 0,\"\"", ep, iss)
	}
}

func TestAdoptHeadOrKeepFloor(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dg := headTestDigest('a')
	set := map[string]struct{}{dg: {}}
	ts := time.Date(2026, 7, 6, 18, 0, 0, 0, time.UTC)

	signedHead := func(epoch int) map[string]any {
		h, err := registry.BuildRevocationHead(registry.RevocationHeadInput{Epoch: epoch, IssuedAt: ts, Digests: []string{dg}})
		if err != nil {
			t.Fatalf("build head: %v", err)
		}
		if _, err := registry.SignEnvelopeSignature(priv, h); err != nil {
			t.Fatalf("sign head: %v", err)
		}
		return h
	}

	t.Run("no head source keeps floor", func(t *testing.T) {
		home := t.TempDir()
		writeRevokedCacheHead(home, set, 3, "2026-01-01T00:00:00Z")
		fetchRevocationHeadFn = nil
		if ep, iss, rej := adoptHeadOrKeepFloor(home, nil, "skills", pub, set); ep != 3 || iss != "2026-01-01T00:00:00Z" || rej {
			t.Errorf("= %d,%q,%v, want 3,<prev>,false", ep, iss, rej)
		}
	})

	t.Run("valid head adopted", func(t *testing.T) {
		home := t.TempDir()
		fetchRevocationHeadFn = func(_ *er1.Config, _ string, _ ed25519.PublicKey) (map[string]any, bool) {
			return signedHead(5), true
		}
		defer func() { fetchRevocationHeadFn = nil }()
		if ep, iss, rej := adoptHeadOrKeepFloor(home, nil, "skills", pub, set); ep != 5 || iss != "2026-07-06T18:00:00Z" || rej {
			t.Errorf("= %d,%q,%v, want 5,<ts>,false", ep, iss, rej)
		}
	})

	t.Run("rollback head keeps floor (does not advance)", func(t *testing.T) {
		home := t.TempDir()
		writeRevokedCacheHead(home, set, 9, "2026-06-01T00:00:00Z")
		fetchRevocationHeadFn = func(_ *er1.Config, _ string, _ ed25519.PublicKey) (map[string]any, bool) {
			return signedHead(4), true // lower epoch than the persisted floor 9
		}
		defer func() { fetchRevocationHeadFn = nil }()
		if ep, iss, rej := adoptHeadOrKeepFloor(home, nil, "skills", pub, set); ep != 9 || iss != "2026-06-01T00:00:00Z" || rej {
			t.Errorf("rollback advanced floor = %d,%q,%v, want 9,<prev>,false", ep, iss, rej)
		}
	})

	// FR-0045 Fix B / finding F1 — a signed HEAD that binds a DIFFERENT set-root
	// than the fetched set signals setRejected=true (the fetched set is
	// truncated/forged) and keeps the prior floor.
	t.Run("set-root mismatch is signalled and keeps floor", func(t *testing.T) {
		home := t.TempDir()
		writeRevokedCacheHead(home, set, 2, "2026-05-01T00:00:00Z")
		// The signed HEAD binds the full {dg} set; feed a set MISSING dg (empty) so
		// the recomputed set-root cannot match the head's revoked_set_root.
		fetchRevocationHeadFn = func(_ *er1.Config, _ string, _ ed25519.PublicKey) (map[string]any, bool) {
			return signedHead(5), true
		}
		defer func() { fetchRevocationHeadFn = nil }()
		truncated := map[string]struct{}{} // dropped dg
		ep, iss, rej := adoptHeadOrKeepFloor(home, nil, "skills", pub, truncated)
		if !rej {
			t.Fatalf("set-root mismatch not signalled: rej=%v", rej)
		}
		if ep != 2 || iss != "2026-05-01T00:00:00Z" {
			t.Errorf("mismatch must keep prior floor, got %d,%q", ep, iss)
		}
	})
}
