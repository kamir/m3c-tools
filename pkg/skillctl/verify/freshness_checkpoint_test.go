package verify

// SPEC-0279 R4 — signed freshness checkpoint tests.
//
// A valid fresh checkpoint at epoch ≥ the synced list's epoch resets the
// staleness clock; a forged / stale / rollback checkpoint is refused fail-closed.

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func TestCheckpoint_SignVerifyRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := revocationRoot(t, pub)
	cp, err := NewSignedFreshnessCheckpoint(root.RegistryURL, 5, "2026-06-22T12:00:00Z", priv)
	if err != nil {
		t.Fatal(err)
	}
	at, err := VerifyFreshnessCheckpoint(cp, root, 0)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if at != "2026-06-22T12:00:00Z" {
		t.Errorf("issued_at = %q, want 2026-06-22T12:00:00Z", at)
	}
}

func TestCheckpoint_ForgedSignatureRefused(t *testing.T) {
	_, attacker, _ := ed25519.GenerateKey(rand.Reader)
	pinned, _, _ := ed25519.GenerateKey(rand.Reader)
	root := revocationRoot(t, pinned)
	cp, _ := NewSignedFreshnessCheckpoint(root.RegistryURL, 5, "2026-06-22T12:00:00Z", attacker)
	if _, err := VerifyFreshnessCheckpoint(cp, root, 0); !errors.Is(err, ErrRegistryNotTrusted) {
		t.Fatalf("forged checkpoint must be ErrRegistryNotTrusted, got: %v", err)
	}
}

func TestCheckpoint_RollbackEpochRefused(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := revocationRoot(t, pub)
	cp, _ := NewSignedFreshnessCheckpoint(root.RegistryURL, 3, "2026-06-22T12:00:00Z", priv)
	// Verifier floor is 5 → an epoch-3 checkpoint cannot reset the clock.
	if _, err := VerifyFreshnessCheckpoint(cp, root, 5); !errors.Is(err, ErrRegistryNotTrusted) {
		t.Fatalf("rollback checkpoint must be refused, got: %v", err)
	}
}

func TestCheckpoint_WrongRegistryRefused(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := revocationRoot(t, pub) // root is https://reg.example/api/skills
	cp, _ := NewSignedFreshnessCheckpoint("https://other.example/api/skills", 5, "2026-06-22T12:00:00Z", priv)
	if _, err := VerifyFreshnessCheckpoint(cp, root, 0); !errors.Is(err, ErrRegistryNotTrusted) {
		t.Fatalf("wrong-registry checkpoint must be refused, got: %v", err)
	}
}

func TestCheckpoint_TamperedEpochBreaksSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := revocationRoot(t, pub)
	cp, _ := NewSignedFreshnessCheckpoint(root.RegistryURL, 5, "2026-06-22T12:00:00Z", priv)
	cp.Epoch = 9 // bump epoch after signing → canonical bytes change → sig fails
	if _, err := VerifyFreshnessCheckpoint(cp, root, 0); !errors.Is(err, ErrRegistryNotTrusted) {
		t.Fatalf("tampered-epoch checkpoint must be refused, got: %v", err)
	}
}

// AC3 (checkpoint half): a valid fresh checkpoint at epoch ≥ synced RESETS the
// staleness clock; the same list that would be stale on its own issued_at is
// fresh against the checkpoint anchor.
func TestCheckpoint_ResetsStalenessClock(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := revocationRoot(t, pub)
	p := freshPolicy(t, "24h", "closed", nil)

	listIssued := "2026-06-20T00:00:00Z" // 48h old at `now` → would be stale
	now := mustTime(t, "2026-06-22T00:00:00Z")

	// Without a checkpoint: high-risk action is stale-denied.
	if _, err := EvaluateFreshness(5, listIssued, p, RiskHigh, now); !errors.Is(err, ErrRevocationStale) {
		t.Fatalf("baseline: must be stale-denied, got: %v", err)
	}

	// A fresh checkpoint at epoch 5 (== synced), issued 1h ago → resets clock.
	cp, _ := NewSignedFreshnessCheckpoint(root.RegistryURL, 5, "2026-06-21T23:00:00Z", priv)
	anchor, applied, err := ApplyCheckpoint(listIssued, 5, cp, root, 0)
	if err != nil {
		t.Fatalf("apply checkpoint: %v", err)
	}
	if !applied {
		t.Fatal("checkpoint should have advanced the anchor")
	}
	dec, err := EvaluateFreshness(5, anchor, p, RiskHigh, now)
	if err != nil {
		t.Fatalf("with fresh checkpoint, high-risk must pass, got: %v", err)
	}
	if !dec.Allowed || dec.Stale {
		t.Errorf("checkpoint-reset decision wrong: %+v", dec)
	}
}

// A checkpoint vouching for an OLDER epoch than the synced list cannot advance
// the clock (it does not prove the current set is fresh) — but it is not an
// attack, so it is silently ignored (anchor unchanged), not an error.
func TestCheckpoint_OlderEpochDoesNotAdvance(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := revocationRoot(t, pub)
	listIssued := "2026-06-20T00:00:00Z"
	cp, _ := NewSignedFreshnessCheckpoint(root.RegistryURL, 4, "2026-06-21T23:00:00Z", priv)
	anchor, applied, err := ApplyCheckpoint(listIssued, 5, cp, root, 0) // synced epoch 5 > cp 4
	if err != nil {
		t.Fatalf("older-epoch checkpoint should not error, got: %v", err)
	}
	if applied || anchor != listIssued {
		t.Errorf("older-epoch checkpoint must not advance anchor; got applied=%v anchor=%q", applied, anchor)
	}
}

// A present-but-bad checkpoint (forged) is fail-closed in ApplyCheckpoint: it
// must ERROR, never silently fall back to the (older) list anchor — otherwise an
// attacker who plants a bad checkpoint goes undetected.
func TestCheckpoint_ApplyForgedFailsClosed(t *testing.T) {
	_, attacker, _ := ed25519.GenerateKey(rand.Reader)
	pinned, _, _ := ed25519.GenerateKey(rand.Reader)
	root := revocationRoot(t, pinned)
	cp, _ := NewSignedFreshnessCheckpoint(root.RegistryURL, 9, "2026-06-22T12:00:00Z", attacker)
	if _, _, err := ApplyCheckpoint("2026-06-20T00:00:00Z", 5, cp, root, 0); !errors.Is(err, ErrRegistryNotTrusted) {
		t.Fatalf("forged checkpoint in ApplyCheckpoint must fail closed, got: %v", err)
	}
}

// A checkpoint cannot move the anchor BACKWARD (it can only ever prove the set is
// at-least-as-fresh-as the list's own time).
func TestCheckpoint_NeverMovesAnchorBackward(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	root := revocationRoot(t, pub)
	listIssued := "2026-06-22T00:00:00Z"
	// Checkpoint issued EARLIER than the list, same epoch.
	cp, _ := NewSignedFreshnessCheckpoint(root.RegistryURL, 5, "2026-06-21T00:00:00Z", priv)
	anchor, applied, err := ApplyCheckpoint(listIssued, 5, cp, root, 0)
	if err != nil {
		t.Fatal(err)
	}
	if applied || anchor != listIssued {
		t.Errorf("earlier checkpoint must not move anchor backward; got applied=%v anchor=%q", applied, anchor)
	}
}

// Domain separation: a checkpoint signature does not verify as a revocation list
// (different canonical type / first bytes) and vice-versa.
func TestCheckpoint_DomainSeparatedFromRevocationList(t *testing.T) {
	cpBytes, err := CanonicalFreshnessCheckpointBytes("https://reg.example/api/skills", 1, "2026-06-22T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	revBytes, err := CanonicalRevocationBytes("https://reg.example/api/skills", "2026-06-22T00:00:00Z", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(cpBytes) == string(revBytes) {
		t.Fatal("checkpoint and revocation canonical bytes must differ (domain separation)")
	}
}
