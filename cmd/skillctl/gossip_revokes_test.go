package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/artifact"
	"github.com/kamir/m3c-tools/pkg/skillctl/registry"
)

func gd(seed byte) string {
	s := make([]byte, 64)
	for i := range s {
		s[i] = "0123456789abcdef"[int(seed)%16]
	}
	return "sha256:" + string(s)
}

func signedRevoke(t *testing.T, priv ed25519.PrivateKey, digest string) map[string]any {
	t.Helper()
	ev := map[string]any{
		"schema_version": registry.EventSchemaVersion,
		"event_id":       "r-" + digest,
		"occurred_at":    "2026-08-01T00:00:00Z",
		"bundle_digest":  digest,
		"revoked_by":     "id:gov@org",
	}
	if _, err := registry.SignEnvelopeSignature(priv, ev); err != nil {
		t.Fatal(err)
	}
	return ev
}

// signedAttestEvent is a genuinely-signed ATTESTATION (reviewer_id + governance_level,
// no revoked_by) — used to prove a signed non-revoke unions nothing even when the
// carrier relabels its EventRecord.Kind to revoke.
func signedAttestEvent(t *testing.T, priv ed25519.PrivateKey, digest string) map[string]any {
	t.Helper()
	ev := map[string]any{
		"schema_version":   registry.EventSchemaVersion,
		"event_id":         "a-" + digest,
		"occurred_at":      "2026-08-01T00:00:00Z",
		"bundle_digest":    digest,
		"reviewer_id":      "id:gov@org",
		"governance_level": "green",
	}
	if _, err := registry.SignEnvelopeSignature(priv, ev); err != nil {
		t.Fatal(err)
	}
	return ev
}

// TestUnionVerifiedRevokes: only revoke events that verify against the peer's key
// are unioned; wrong-key/unsigned are dropped (integrity fail-closed). Classification
// is by the SIGNED envelope shape (FR-0090 IS-T2), so a signed revoke is unioned on
// its SIGNED bundle_digest regardless of how the carrier labelled EventRecord.Kind.
func TestUnionVerifiedRevokes(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
	good := gd(1)
	forged := gd(2)

	events := []artifact.EventRecord{
		{Kind: artifact.KindRevoke, Digest: good, Envelope: signedRevoke(t, priv, good)},          // valid
		{Kind: artifact.KindRevoke, Digest: forged, Envelope: signedRevoke(t, wrongPriv, forged)}, // wrong key → dropped
	}
	into := map[string]struct{}{}
	n := unionVerifiedRevokes(events, pub, into)
	if n != 1 {
		t.Fatalf("unioned %d, want 1 (only the validly-signed revoke)", n)
	}
	if _, ok := into[good]; !ok {
		t.Error("the valid revoke was not unioned")
	}
	if _, ok := into[forged]; ok {
		t.Error("a revoke signed by the WRONG key must be dropped (integrity fail-closed)")
	}
}

// TestUnionVerifiedRevokesSignedIdentity is the FR-0090 IS-T2 regression. A hostile
// peer serves signed events whose EventRecord carrier fields (Kind/Digest) LIE:
//
//   - a genuinely-signed revoke of X wrapped in EventRecord{Kind:revoke, Digest:Y}
//     must union X (the SIGNED bundle_digest), never the carrier Digest Y;
//   - a genuinely-signed ATTEST relabelled EventRecord{Kind:revoke, Digest:Y}
//     must union NOTHING (it is not a signed revoke).
//
// Against the old code (which keyed on ev.Digest and filtered on ev.Kind) BOTH
// events would have unioned Y — revoking an innocent digest and honouring a forged
// revocation. The signed-identity union defeats both.
func TestUnionVerifiedRevokesSignedIdentity(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	x := gd(7) // the digest the SIGNED revoke actually targets
	y := gd(8) // the digest the carrier LABELS both records with

	events := []artifact.EventRecord{
		// Signed revoke of X, but the carrier claims Digest:Y.
		{Kind: artifact.KindRevoke, Digest: y, Envelope: signedRevoke(t, priv, x)},
		// Signed attest of Y, but the carrier claims Kind:revoke.
		{Kind: artifact.KindRevoke, Digest: y, Envelope: signedAttestEvent(t, priv, y)},
	}
	into := map[string]struct{}{}
	unionVerifiedRevokes(events, pub, into)

	if _, ok := into[x]; !ok {
		t.Error("a signed revoke of X must union X (its SIGNED bundle_digest), not the carrier's Digest")
	}
	if _, ok := into[y]; ok {
		t.Error("must NOT union Y: neither the carrier Digest of the revoke nor a relabelled signed attest may add a digest")
	}
}

// TestGossipedRevokedGrowOnly: the durable gossip cache only grows — a later merge
// that omits a digest cannot un-revoke it (anti-rollback).
func TestGossipedRevokedGrowOnly(t *testing.T) {
	home := t.TempDir()
	now := time.Now()
	if _, err := mergeGossipedRevoked(home, map[string]struct{}{gd(1): {}, gd(2): {}}, now); err != nil {
		t.Fatal(err)
	}
	// A second merge that OMITS gd(1) must not drop it.
	total, err := mergeGossipedRevoked(home, map[string]struct{}{gd(3): {}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 {
		t.Errorf("grow-only cache = %d, want 3 (nothing dropped)", total)
	}
	got := loadGossipedRevoked(home)
	for _, d := range []string{gd(1), gd(2), gd(3)} {
		if _, ok := got[d]; !ok {
			t.Errorf("digest %s missing after grow-only merge", d)
		}
	}
	// Perms: 0600 (POSIX only — Windows does not model unix mode bits).
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(gossipedRevokedPath(home)); err == nil && fi.Mode().Perm() != 0o600 {
			t.Errorf("gossip cache perms = %o, want 600", fi.Mode().Perm())
		}
	}
}

// TestFetchRevokedWithGossipUnions: the sweep seam unions the durable gossip cache
// on top of the (stubbed) online set.
func TestFetchRevokedWithGossipUnions(t *testing.T) {
	home := t.TempDir()
	if _, err := mergeGossipedRevoked(home, map[string]struct{}{gd(9): {}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	// Seed a valid revoked-cache file with one online digest so fetchRevokedOnline's
	// fail-open path returns it.
	if err := os.MkdirAll(filepath.Dir(revokedCachePath(home)), 0o700); err != nil {
		t.Fatal(err)
	}
	writeRevokedCache(home, map[string]struct{}{gd(8): {}})

	set, _, _ := fetchRevokedWithGossip(home)
	if _, ok := set[gd(9)]; !ok {
		t.Error("gossiped revoke not unioned into the sweep set")
	}
}
