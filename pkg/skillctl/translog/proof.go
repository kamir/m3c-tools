package translog

import (
	"crypto/subtle"
	"errors"
	"fmt"
)

// Proof errors. All proof-shape problems are sentinel-wrapped so callers
// (and the adversarial gate) can branch on the failure class without
// parsing strings.
var (
	// ErrIndexOutOfRange — a leaf index is not in [0, size).
	ErrIndexOutOfRange = errors.New("translog: leaf index out of range")
	// ErrBadProofSize — a proof has the wrong number of hashes for the
	// (index, size) it claims to prove. A forged or truncated proof trips
	// this before any hashing happens.
	ErrBadProofSize = errors.New("translog: proof has wrong length for tree size")
	// ErrInclusionMismatch — the root recomputed from the leaf + proof
	// does not equal the expected root. This is the catch-all rejection
	// for a tampered leaf, a wrong index, or a forged proof path.
	ErrInclusionMismatch = errors.New("translog: inclusion proof does not reconstruct the root")
	// ErrConsistencyMismatch — a consistency proof failed to reconstruct
	// BOTH the old and the new root. A log that dropped or rewrote an
	// entry between the two sizes trips this — the append-only property
	// is violated and the rewrite is DETECTED.
	ErrConsistencyMismatch = errors.New("translog: consistency proof failed (log is not a pure append)")
	// ErrBadConsistencyArgs — nonsensical sizes (e.g. first > second, or
	// a zero first size with a non-empty proof).
	ErrBadConsistencyArgs = errors.New("translog: invalid consistency proof arguments")
)

// InclusionProof returns the RFC-6962 audit path proving that the leaf at
// index `index` is included in a tree of `size` leaves. The returned slice
// is ordered from the leaf's sibling upward to (but excluding) the root.
//
// `leaves` MUST be the full ordered set of leaf hashes for the tree of the
// given size (len(leaves) must equal size). Production callers hold these
// in the local log file; the proof is computed once and can be checked
// later by VerifyInclusion WITHOUT the leaf set — only the single leaf
// hash, the proof, and the trusted root are needed.
func InclusionProof(index, size int, leaves [][HashSize]byte) ([][HashSize]byte, error) {
	if size <= 0 {
		return nil, fmt.Errorf("%w: size=%d", ErrEmptyTree, size)
	}
	if index < 0 || index >= size {
		return nil, fmt.Errorf("%w: index=%d size=%d", ErrIndexOutOfRange, index, size)
	}
	if len(leaves) != size {
		return nil, fmt.Errorf("%w: have %d leaves, size says %d", ErrBadProofSize, len(leaves), size)
	}
	return inclusionPath(index, leaves), nil
}

// inclusionPath is RFC-6962 §2.1.1 PATH(m, D[0:n]). Precondition: n>=1 and
// 0<=m<n. The proof for a single-leaf tree is empty.
func inclusionPath(m int, leaves [][HashSize]byte) [][HashSize]byte {
	n := len(leaves)
	if n == 1 {
		return nil
	}
	k := largestPowerOfTwoLessThan(n)
	if m < k {
		// Leaf is in the left subtree; sibling is the right subtree root.
		sub := inclusionPath(m, leaves[:k])
		return append(sub, merkleTreeHash(leaves[k:]))
	}
	// Leaf is in the right subtree; sibling is the left subtree root.
	sub := inclusionPath(m-k, leaves[k:])
	return append(sub, merkleTreeHash(leaves[:k]))
}

// VerifyInclusion checks an RFC-6962 inclusion (audit) proof OFFLINE: it
// reconstructs the tree root from the single leaf hash, its index/size,
// and the audit path, then compares (constant-time) against the expected
// root.
//
// No network, no leaf set, no log operator is consulted — this is the
// property that lets a verifier confirm "this event is committed under the
// STH I already trust" without trusting any server. A tampered leaf, a
// wrong index, a wrong size, or a forged path all reduce to a
// reconstructed root that differs from `root`, returning
// ErrInclusionMismatch.
func VerifyInclusion(leafHash [HashSize]byte, index, size int, proof [][HashSize]byte, root [HashSize]byte) error {
	if size <= 0 {
		return fmt.Errorf("%w: size=%d", ErrEmptyTree, size)
	}
	if index < 0 || index >= size {
		return fmt.Errorf("%w: index=%d size=%d", ErrIndexOutOfRange, index, size)
	}
	// The audit path length is exactly ceil(log2) of the position of the
	// leaf within its subtree decomposition. We compute the expected
	// length and reject a mismatched proof BEFORE hashing so a forged
	// proof of the wrong shape can never be massaged into a valid root.
	want := inclusionProofLen(index, size)
	if len(proof) != want {
		return fmt.Errorf("%w: have %d hashes, want %d for index=%d size=%d",
			ErrBadProofSize, len(proof), want, index, size)
	}

	computed := rebuildRootFromInclusion(leafHash, index, size, proof)
	if subtle.ConstantTimeCompare(computed[:], root[:]) != 1 {
		return ErrInclusionMismatch
	}
	return nil
}

// rebuildRootFromInclusion folds the audit path into a root hash.
//
// inclusionPath emits siblings DEEPEST-FIRST (the recursion appends the
// current level's sibling AFTER recursing into the subtree containing the
// leaf). So proof[0] is the leaf's immediate sibling and proof[len-1] is
// the root's-child sibling. To consume them in that order we must first
// record each level's left/right decision walking TOP-DOWN, then apply the
// proof BOTTOM-UP. Precondition: len(proof)==inclusionProofLen(index,size),
// 0<=index<size.
func rebuildRootFromInclusion(leafHash [HashSize]byte, index, size int, proof [][HashSize]byte) [HashSize]byte {
	// onLeft[d] is true when, at decomposition depth d (0 = whole tree),
	// the leaf sits in the LEFT subtree (so its sibling is on the right).
	onLeft := make([]bool, 0, len(proof))
	fn := index
	sn := size
	for sn > 1 {
		k := largestPowerOfTwoLessThan(sn)
		if fn < k {
			onLeft = append(onLeft, true)
			sn = k
		} else {
			onLeft = append(onLeft, false)
			fn -= k
			sn -= k
		}
	}
	// Apply proof bottom-up: the deepest decision is the LAST recorded, and
	// it pairs with proof[0].
	hash := leafHash
	for i := 0; i < len(proof); i++ {
		// Deepest decision first.
		d := len(onLeft) - 1 - i
		if onLeft[d] {
			// Leaf subtree is on the LEFT; sibling on the RIGHT.
			hash = hashChildren(hash, proof[i])
		} else {
			// Leaf subtree is on the RIGHT; sibling on the LEFT.
			hash = hashChildren(proof[i], hash)
		}
	}
	return hash
}

// inclusionProofLen returns the exact number of hashes an inclusion proof
// for (index, size) must contain. Computed by the same decomposition the
// proof-builder uses, so the length check in VerifyInclusion is tight.
func inclusionProofLen(index, size int) int {
	n := 0
	fn := index
	sn := size
	for sn > 1 {
		k := largestPowerOfTwoLessThan(sn)
		if fn < k {
			sn = k
		} else {
			fn -= k
			sn -= k
		}
		n++
	}
	return n
}

// ConsistencyProof returns the RFC-6962 §2.1.2 consistency proof that a
// tree of `second` leaves is a pure APPEND of a tree of `first` leaves —
// i.e. the first `first` leaves are unchanged and nothing was rewritten.
//
// `leaves` must be the full ordered leaf-hash set of the LARGER (second)
// tree. A verifier later checks the proof with VerifyConsistency against
// the two roots it independently trusts (the old root from an old STH, the
// new root from a new STH) WITHOUT the leaf set.
//
// first == second yields an empty proof (trivially consistent). first == 0
// also yields an empty proof (everything is "new"); VerifyConsistency
// treats both as a no-op success.
func ConsistencyProof(first, second int, leaves [][HashSize]byte) ([][HashSize]byte, error) {
	if first < 0 || second < 0 || first > second {
		return nil, fmt.Errorf("%w: first=%d second=%d", ErrBadConsistencyArgs, first, second)
	}
	if second == 0 {
		return nil, fmt.Errorf("%w: second=0", ErrEmptyTree)
	}
	if len(leaves) != second {
		return nil, fmt.Errorf("%w: have %d leaves, second says %d", ErrBadProofSize, len(leaves), second)
	}
	if first == 0 || first == second {
		return [][HashSize]byte{}, nil
	}
	return consistencySubproof(first, leaves, true), nil
}

// consistencySubproof is RFC-6962 §2.1.2 SUBPROOF(m, D[0:n], b). `m` is the
// first (smaller) size; `leaves` is D[0:n] for the current subtree; `b`
// indicates whether the current subtree's root is "known" to the verifier
// from the old tree (true at the top, where m may equal n on the left
// spine).
func consistencySubproof(m int, leaves [][HashSize]byte, b bool) [][HashSize]byte {
	n := len(leaves)
	if m == n {
		if b {
			// The whole subtree is the old tree; nothing to prove here.
			return [][HashSize]byte{}
		}
		// The old tree root is an interior node the verifier must be
		// given so it can reconstruct the old root.
		return [][HashSize]byte{merkleTreeHash(leaves)}
	}
	k := largestPowerOfTwoLessThan(n)
	if m <= k {
		// Old tree lives entirely in the left subtree; append the right
		// subtree root (the part that is purely new at this level).
		sub := consistencySubproof(m, leaves[:k], b)
		return append(sub, merkleTreeHash(leaves[k:]))
	}
	// Old tree spans into the right subtree; the left subtree is fully
	// shared (carry b=false so its root is surfaced), recurse right.
	sub := consistencySubproof(m-k, leaves[k:], false)
	return append(sub, merkleTreeHash(leaves[:k]))
}

// VerifyConsistency checks an RFC-6962 consistency proof OFFLINE: that
// `secondRoot` (size `second`) is a pure append of `firstRoot` (size
// `first`). It reconstructs BOTH roots from the proof and compares each
// (constant-time) against the trusted values.
//
// A log that dropped, reordered, or rewrote any of the first `first`
// entries cannot produce a proof that reconstructs the original
// `firstRoot` AND the advertised `secondRoot` — so the rewrite is DETECTED
// as ErrConsistencyMismatch. This is the anti-rewrite property.
func VerifyConsistency(first, second int, firstRoot, secondRoot [HashSize]byte, proof [][HashSize]byte) error {
	if first < 0 || second < 0 || first > second {
		return fmt.Errorf("%w: first=%d second=%d", ErrBadConsistencyArgs, first, second)
	}
	if first == 0 {
		// Old tree was empty: nothing to be consistent WITH. By RFC-6962
		// convention an empty old tree is trivially consistent; we still
		// reject a non-empty proof so a forged path can't sneak in.
		if len(proof) != 0 {
			return fmt.Errorf("%w: first=0 expects empty proof, got %d hashes", ErrBadProofSize, len(proof))
		}
		return nil
	}
	if first == second {
		// Same tree: roots must be identical and the proof empty.
		if len(proof) != 0 {
			return fmt.Errorf("%w: first==second expects empty proof, got %d hashes", ErrBadProofSize, len(proof))
		}
		if subtle.ConstantTimeCompare(firstRoot[:], secondRoot[:]) != 1 {
			return ErrConsistencyMismatch
		}
		return nil
	}

	// firstIsPowerOfTwo: when the old size is an exact power of two, its
	// root is a clean subtree of the new tree and is NOT carried in the
	// proof — the verifier seeds it from firstRoot. Otherwise the first
	// proof element is the old tree's left-spine node.
	firstIsPow2 := isPowerOfTwo(first)

	want := consistencyProofLen(first, second)
	if len(proof) != want {
		return fmt.Errorf("%w: have %d hashes, want %d for first=%d second=%d",
			ErrBadProofSize, len(proof), want, first, second)
	}

	gotFirst, gotSecond, ok := rebuildConsistencyRoots(first, second, firstRoot, proof, firstIsPow2)
	if !ok {
		return ErrConsistencyMismatch
	}
	if subtle.ConstantTimeCompare(gotFirst[:], firstRoot[:]) != 1 {
		return ErrConsistencyMismatch
	}
	if subtle.ConstantTimeCompare(gotSecond[:], secondRoot[:]) != 1 {
		return ErrConsistencyMismatch
	}
	return nil
}

// rebuildConsistencyRoots folds a consistency proof into the old and new
// roots. This is the verification counterpart to consistencySubproof,
// following the standard RFC-6962 reference algorithm (the same shape used
// by Trillian's merkle/proof verifier). Returns (oldRoot, newRoot, ok).
func rebuildConsistencyRoots(first, second int, firstRoot [HashSize]byte, proof [][HashSize]byte, firstIsPow2 bool) ([HashSize]byte, [HashSize]byte, bool) {
	// Seed the proof working set. When first is a power of two, firstRoot
	// is the implicit first node; otherwise proof[0] is.
	var seed [][HashSize]byte
	if firstIsPow2 {
		seed = append([][HashSize]byte{firstRoot}, proof...)
	} else {
		seed = proof
	}
	if len(seed) == 0 {
		return [HashSize]byte{}, [HashSize]byte{}, false
	}

	fn := first - 1
	sn := second - 1
	// Shift fn,sn right until fn is odd (or zero) — aligns to the rightmost
	// node of the old tree on the shared left spine.
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}

	hash1 := seed[0]
	hash2 := seed[0]
	for _, c := range seed[1:] {
		if sn == 0 {
			// Ran out of tree to climb but still have proof nodes →
			// malformed proof.
			return [HashSize]byte{}, [HashSize]byte{}, false
		}
		if fn&1 == 1 || fn == sn {
			// Right child (or both indices coincide): the proof node is
			// the LEFT sibling for both running hashes that still track
			// the old tree.
			hash1 = hashChildren(c, hash1)
			hash2 = hashChildren(c, hash2)
			for fn != 0 && fn&1 == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			// Left child: only the new-tree hash extends to the right.
			hash2 = hashChildren(hash2, c)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		// Did not consume the full new tree → malformed proof.
		return [HashSize]byte{}, [HashSize]byte{}, false
	}
	return hash1, hash2, true
}

// consistencyProofLen returns the expected hash count for a consistency
// proof between first and second (1 <= first < second). Derived from the
// same decomposition consistencySubproof uses so the length check is
// tight.
func consistencyProofLen(first, second int) int {
	return len(consistencyShape(first, second))
}

// consistencyShape replays the SUBPROOF recursion counting only how many
// hashes it would emit, given the sizes alone (no leaf data). Keeping this
// independent of the actual hashes lets VerifyConsistency reject a
// wrong-length proof up front.
func consistencyShape(m, n int) []struct{} {
	if m == n {
		// b=true at the entry point: empty.
		return nil
	}
	return shapeSub(m, n, true)
}

func shapeSub(m, n int, b bool) []struct{} {
	if m == n {
		if b {
			return nil
		}
		return []struct{}{{}}
	}
	k := largestPowerOfTwoLessThan(n)
	if m <= k {
		return append(shapeSub(m, k, b), struct{}{})
	}
	return append(shapeSub(m-k, n-k, false), struct{}{})
}

// isPowerOfTwo reports whether x is a positive power of two.
func isPowerOfTwo(x int) bool {
	return x > 0 && x&(x-1) == 0
}
