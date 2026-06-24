package translog

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

// staticPinnedKey implements PinnedLogKey for one (or two) logs.
type staticPinnedKey struct {
	keys map[string]ed25519.PublicKey
}

func (s staticPinnedKey) PublicKeyFor(logID string) ([]byte, error) {
	k, ok := s.keys[logID]
	if !ok {
		return nil, errors.New("no pinned key for log " + logID)
	}
	return k, nil
}

func sthAt(t *testing.T, priv ed25519.PrivateKey, logID string, size int, ts time.Time, leaves [][HashSize]byte) STH {
	t.Helper()
	root, err := MerkleTreeHash(leaves[:size])
	if err != nil {
		t.Fatal(err)
	}
	s := STH{TreeSize: size, RootHash: hexOf(root), Timestamp: FormatSTHTimestamp(ts), LogID: logID}
	signed, err := SignSTH(priv, s)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// TestSplitView_Detected is the headline: two honestly-SIGNED STHs from the
// same log at the SAME tree_size but with DIFFERENT roots is an
// equivocation, and must be DETECTED.
func TestSplitView_Detected(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)

	// History 1: leaves[0:5]. History 2: a forked set of 5 leaves where
	// leaf 2 differs. Both are size 5 → same tree_size, different root.
	histA := leafHashes(5)
	histB := leafHashes(5)
	histB[2] = HashLeaf([]byte("FORKED-leaf-2"))

	ts := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	sthA := sthAt(t, priv, "log-1", 5, ts, histA)
	sthB := sthAt(t, priv, "log-1", 5, ts.Add(time.Minute), histB)

	conflict, err := VerifyWitnessConsistency([]STH{sthA, sthB})
	if !errors.Is(err, ErrSplitView) {
		t.Fatalf("split view: want ErrSplitView, got %v", err)
	}
	if conflict == nil || conflict.TreeSize != 5 || conflict.LogID != "log-1" {
		t.Fatalf("conflict not populated correctly: %+v", conflict)
	}
	if conflict.RootA == conflict.RootB {
		t.Fatal("conflict roots should differ")
	}
}

// TestSplitView_NoConflict_DifferentSizes: same log, different sizes is NOT
// a split view (it's normal growth).
func TestSplitView_NoConflict_DifferentSizes(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	leaves := leafHashes(8)
	ts := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	s5 := sthAt(t, priv, "log-1", 5, ts, leaves)
	s8 := sthAt(t, priv, "log-1", 8, ts, leaves)
	conflict, err := VerifyWitnessConsistency([]STH{s5, s8})
	if err != nil || conflict != nil {
		t.Fatalf("different sizes must not conflict, got conflict=%v err=%v", conflict, err)
	}
}

// TestSplitView_NoConflict_SameHead: two witnesses reporting the SAME head
// (same size, same root, different timestamp) is consistent, not a split.
func TestSplitView_NoConflict_SameHead(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	leaves := leafHashes(5)
	a := sthAt(t, priv, "log-1", 5, time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC), leaves)
	b := sthAt(t, priv, "log-1", 5, time.Date(2026, 6, 24, 13, 0, 0, 0, time.UTC), leaves)
	conflict, err := VerifyWitnessConsistency([]STH{a, b})
	if err != nil || conflict != nil {
		t.Fatalf("identical heads must not conflict, got conflict=%v err=%v", conflict, err)
	}
}

// TestSplitView_DifferentLogsNotCompared: same size collision across two
// DIFFERENT logs is not a conflict.
func TestSplitView_DifferentLogsNotCompared(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	a := sthAt(t, priv, "log-1", 5, time.Now(), leafHashes(5))
	bLeaves := leafHashes(5)
	bLeaves[0] = HashLeaf([]byte("x"))
	b := sthAt(t, priv, "log-2", 5, time.Now(), bLeaves)
	conflict, err := VerifyWitnessConsistency([]STH{a, b})
	if err != nil || conflict != nil {
		t.Fatalf("different logs must not conflict, got conflict=%v err=%v", conflict, err)
	}
}

// TestDetectSplitView_VerifiesSignaturesFirst: an UNPINNED-key STH in the
// witness set is rejected before the comparison — an attacker can't smuggle
// an unsigned "head" to hide (or fabricate) an equivocation.
func TestDetectSplitView_RejectsUnpinned(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	_, attacker, _ := ed25519.GenerateKey(nil)

	pinned := staticPinnedKey{keys: map[string]ed25519.PublicKey{"log-1": pub}}

	good := sthAt(t, priv, "log-1", 5, time.Now(), leafHashes(5))
	forged := sthAt(t, attacker, "log-1", 5, time.Now(), leafHashes(5)) // wrong signer

	if _, err := DetectSplitView(pinned, []STH{good, forged}); !errors.Is(err, ErrSTHSignatureInvalid) {
		t.Fatalf("unpinned witness STH must be rejected, got %v", err)
	}
}

// TestDetectSplitView_RealConflictWithValidSignatures: BOTH heads are
// validly signed by the pinned key (the operator itself equivocated), and
// the split view is detected.
func TestDetectSplitView_RealConflict(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	pinned := staticPinnedKey{keys: map[string]ed25519.PublicKey{"log-1": pub}}

	histA := leafHashes(6)
	histB := leafHashes(6)
	histB[4] = HashLeaf([]byte("forked"))
	a := sthAt(t, priv, "log-1", 6, time.Now(), histA)
	b := sthAt(t, priv, "log-1", 6, time.Now().Add(time.Second), histB)

	conflict, err := DetectSplitView(pinned, []STH{a, b})
	if !errors.Is(err, ErrSplitView) {
		t.Fatalf("want ErrSplitView, got %v", err)
	}
	if conflict == nil {
		t.Fatal("expected a populated conflict")
	}
}

// TestCheckAppendConsistency_DetectsRewrite: a log that rewrote history
// between two witnessed heads fails the consistency check (anti-rewrite).
func TestCheckAppendConsistency_DetectsRewrite(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)

	honest := leafHashes(8)
	s4 := sthAt(t, priv, "log-1", 4, time.Now(), honest)

	// Operator rewrote leaf 1 by size 8 — its size-8 STH commits a root
	// that is NOT a pure append of the size-4 root.
	rewritten := leafHashes(8)
	rewritten[1] = HashLeaf([]byte("rewritten"))
	s8 := sthAt(t, priv, "log-1", 8, time.Now(), rewritten)

	// The proof is computed over the HONEST size-8 tree (the only one the
	// operator could have published consistently); against the rewritten
	// size-8 root it must fail.
	proof, _ := ConsistencyProof(4, 8, honest)
	proofs := map[int]map[int][][HashSize]byte{4: {8: proof}}

	err := CheckAppendConsistency([]STH{s4, s8}, proofs)
	if !errors.Is(err, ErrWitnessInconsistent) {
		t.Fatalf("rewrite between witnessed heads: want ErrWitnessInconsistent, got %v", err)
	}
}

// TestCheckAppendConsistency_HonestPasses: honest growth passes.
func TestCheckAppendConsistency_HonestPasses(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	leaves := leafHashes(8)
	s4 := sthAt(t, priv, "log-1", 4, time.Now(), leaves)
	s8 := sthAt(t, priv, "log-1", 8, time.Now(), leaves)
	proof, _ := ConsistencyProof(4, 8, leaves)
	proofs := map[int]map[int][][HashSize]byte{4: {8: proof}}
	if err := CheckAppendConsistency([]STH{s4, s8}, proofs); err != nil {
		t.Fatalf("honest growth should pass: %v", err)
	}
}
