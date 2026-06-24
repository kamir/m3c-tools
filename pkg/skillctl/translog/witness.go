package translog

import (
	"errors"
	"fmt"
	"sort"
)

// Split-view / equivocation detection.
//
// A transparency log operator equivocates when it shows DIFFERENT histories
// to different observers — e.g. "this skill is revoked for company A but
// still valid for company B." With L1 we cannot PREVENT that (only the
// deferred L2 BFT consortium ledger could), but we CAN make it DETECTABLE by
// cross-witnessing Signed Tree Heads: if two witnesses report STHs for the
// same log at the SAME tree_size with DIFFERENT root_hash, the operator
// signed two incompatible histories — a split view.
//
// This is exactly the cross-company STH freshness / split-view check that
// SPEC-0279 AC4 (the P4 freshness checkpoint) deferred: an STH cross-checked
// here IS the SPEC-0279 R4 freshness checkpoint, composed where the verifier
// reaches for it (see verify integration).
//
// NOTE on scope: this is the OFFLINE comparison LOGIC. The wire transport
// that gossips STHs between org nodes (SPEC-0190 / Kafka) is DEFERRED — a
// caller hands us the witnessed STH set however it obtained them.

// ErrSplitView is returned when two STHs for the same log equivocate: same
// tree_size, different root_hash. This is the detectable equivocation
// signal. It is sentinel-wrapped so callers can branch on it.
var ErrSplitView = errors.New("translog: split view detected (log equivocated)")

// ErrWitnessInconsistent is returned when two STHs for the same log are not
// a same-size conflict but still cannot be a pure append of one another —
// i.e. a supplied consistency proof between them FAILS. A log that rewrote
// history between two sizes trips this.
var ErrWitnessInconsistent = errors.New("translog: witnessed STHs are not append-consistent")

// SplitViewConflict describes a detected equivocation between two witnessed
// STHs. It carries both heads so an operator can attach them to an incident
// report (they are each independently signed and therefore non-repudiable
// evidence that the LOG produced both).
type SplitViewConflict struct {
	// LogID is the log that equivocated.
	LogID string
	// TreeSize is the size at which the two heads disagree.
	TreeSize int
	// RootA and RootB are the two conflicting root hashes (hex).
	RootA string
	RootB string
	// A and B are the full conflicting STHs (signed evidence).
	A STH
	B STH
}

// Error implements error so a conflict can be returned directly.
func (c *SplitViewConflict) Error() string {
	return fmt.Sprintf(
		"%v: log %q reports tree_size %d with two different roots (%s vs %s)",
		ErrSplitView, c.LogID, c.TreeSize, c.RootA, c.RootB)
}

// Unwrap lets errors.Is(conflict, ErrSplitView) succeed.
func (c *SplitViewConflict) Unwrap() error { return ErrSplitView }

// VerifyWitnessConsistency scans a set of STHs (typically gathered from
// different witnesses) for the SAME log and returns the first detectable
// equivocation: two heads at the same tree_size with different root_hash.
//
// It returns:
//   - (nil, nil) when no same-size conflict exists among the inputs;
//   - (*SplitViewConflict, error) where the error wraps ErrSplitView when a
//     split view is found.
//
// STHs carrying DIFFERENT LogIDs are never compared against each other
// (they are different logs; a size collision is not a conflict). Only the
// (size, root) pair is compared — timestamp and signature differences are
// expected and benign.
//
// This function does NOT verify signatures; callers MUST VerifySTH each
// input against the pinned log key first (an unsigned or unpinned STH is
// not admissible evidence). The dedicated DetectSplitView helper below does
// the verify-then-compare in one call for callers that have the key.
func VerifyWitnessConsistency(sths []STH) (*SplitViewConflict, error) {
	// Group by (logID, treeSize) and look for a root disagreement. We keep
	// the first head seen per (logID,size) and compare every subsequent
	// head against it.
	type key struct {
		logID string
		size  int
	}
	seen := make(map[key]STH, len(sths))

	// Iterate in a deterministic order so the SAME input set always yields
	// the SAME first-reported conflict (stable diagnostics).
	idx := make([]int, len(sths))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool {
		x, y := sths[idx[a]], sths[idx[b]]
		if x.LogID != y.LogID {
			return x.LogID < y.LogID
		}
		if x.TreeSize != y.TreeSize {
			return x.TreeSize < y.TreeSize
		}
		return x.RootHash < y.RootHash
	})

	for _, i := range idx {
		s := sths[i]
		k := key{logID: s.LogID, size: s.TreeSize}
		prev, ok := seen[k]
		if !ok {
			seen[k] = s
			continue
		}
		if !prev.Equal(s) {
			// Same log, same size, different root → equivocation.
			c := &SplitViewConflict{
				LogID:    s.LogID,
				TreeSize: s.TreeSize,
				RootA:    prev.RootHash,
				RootB:    s.RootHash,
				A:        prev,
				B:        s,
			}
			return c, c
		}
	}
	return nil, nil
}

// DetectSplitView is the verify-then-compare convenience: it first verifies
// every STH against the pinned log public key (rejecting any unsigned /
// unpinned / forged head), then runs VerifyWitnessConsistency. Use this at
// the verifier boundary where the pinned key is available.
func DetectSplitView(logPub PinnedLogKey, sths []STH) (*SplitViewConflict, error) {
	for i, s := range sths {
		pub, err := logPub.PublicKeyFor(s.LogID)
		if err != nil {
			return nil, fmt.Errorf("witness[%d] (log %q): %w", i, s.LogID, err)
		}
		if err := VerifySTH(pub, s); err != nil {
			return nil, fmt.Errorf("witness[%d] (log %q): %w", i, s.LogID, err)
		}
	}
	return VerifyWitnessConsistency(sths)
}

// CheckAppendConsistency verifies that a SET of witnessed STHs for the same
// log are mutually append-consistent: for each pair (smaller, larger) the
// caller supplies the consistency proof and we confirm the larger is a pure
// append of the smaller. A failure means the log rewrote history between the
// two heads → ErrWitnessInconsistent (a detected anti-rewrite violation).
//
// proofs is keyed by [smallerSize][largerSize]. Pairs with no proof are
// skipped (the caller controls coverage); same-size pairs are checked for
// root equality via the split-view path, not here.
func CheckAppendConsistency(sths []STH, proofs map[int]map[int][][HashSize]byte) error {
	// Sort by size ascending so we always pass (first <= second).
	ordered := make([]STH, len(sths))
	copy(ordered, sths)
	sort.SliceStable(ordered, func(a, b int) bool { return ordered[a].TreeSize < ordered[b].TreeSize })

	for i := 0; i < len(ordered); i++ {
		for j := i + 1; j < len(ordered); j++ {
			small, large := ordered[i], ordered[j]
			if small.LogID != large.LogID {
				continue
			}
			if small.TreeSize == large.TreeSize {
				continue // handled by split-view detection
			}
			byLarge, ok := proofs[small.TreeSize]
			if !ok {
				continue
			}
			proof, ok := byLarge[large.TreeSize]
			if !ok {
				continue
			}
			sRoot, err := small.RootBytes()
			if err != nil {
				return fmt.Errorf("smaller STH (size %d): %w", small.TreeSize, err)
			}
			lRoot, err := large.RootBytes()
			if err != nil {
				return fmt.Errorf("larger STH (size %d): %w", large.TreeSize, err)
			}
			if err := VerifyConsistency(small.TreeSize, large.TreeSize, sRoot, lRoot, proof); err != nil {
				return fmt.Errorf("%w: log %q between sizes %d and %d: %v",
					ErrWitnessInconsistent, small.LogID, small.TreeSize, large.TreeSize, err)
			}
		}
	}
	return nil
}

// PinnedLogKey resolves a log_id to its pinned ed25519 public key. The
// verify-layer trust-roots loader implements this so split-view detection
// can verify each witnessed STH against the RIGHT pinned key.
type PinnedLogKey interface {
	PublicKeyFor(logID string) (ed25519PublicKey, error)
}

// ed25519PublicKey is a thin alias kept local so witness.go does not pull a
// crypto import into a file that is otherwise pure comparison logic. It is
// the same underlying type as crypto/ed25519.PublicKey.
type ed25519PublicKey = []byte
