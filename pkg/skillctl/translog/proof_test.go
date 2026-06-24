package translog

import (
	"errors"
	"testing"
)

// TestInclusion_RoundTripAllSizes proves every leaf in every tree up to a
// decent size. This exercises the k-split decomposition on both balanced
// and unbalanced trees.
func TestInclusion_RoundTripAllSizes(t *testing.T) {
	for size := 1; size <= 33; size++ {
		leaves := leafHashes(size)
		root, err := MerkleTreeHash(leaves)
		if err != nil {
			t.Fatalf("size=%d: %v", size, err)
		}
		for idx := 0; idx < size; idx++ {
			proof, err := InclusionProof(idx, size, leaves)
			if err != nil {
				t.Fatalf("size=%d idx=%d: build proof: %v", size, idx, err)
			}
			if err := VerifyInclusion(leaves[idx], idx, size, proof, root); err != nil {
				t.Fatalf("size=%d idx=%d: verify: %v", size, idx, err)
			}
		}
	}
}

func TestInclusion_TamperedLeafRejected(t *testing.T) {
	size := 7
	leaves := leafHashes(size)
	root, _ := MerkleTreeHash(leaves)
	idx := 3
	proof, _ := InclusionProof(idx, size, leaves)

	// Flip the leaf hash → reconstruction diverges from root.
	bad := leaves[idx]
	bad[0] ^= 0xFF
	if err := VerifyInclusion(bad, idx, size, proof, root); !errors.Is(err, ErrInclusionMismatch) {
		t.Fatalf("tampered leaf: want ErrInclusionMismatch, got %v", err)
	}
}

func TestInclusion_WrongIndexRejected(t *testing.T) {
	size := 8
	leaves := leafHashes(size)
	root, _ := MerkleTreeHash(leaves)
	// Proof for index 2, but verify claims index 5.
	proof, _ := InclusionProof(2, size, leaves)
	if err := VerifyInclusion(leaves[2], 5, size, proof, root); err == nil {
		t.Fatal("wrong index: expected rejection, got nil")
	}
}

func TestInclusion_TamperedProofPathRejected(t *testing.T) {
	size := 9
	leaves := leafHashes(size)
	root, _ := MerkleTreeHash(leaves)
	idx := 4
	proof, _ := InclusionProof(idx, size, leaves)
	if len(proof) == 0 {
		t.Fatal("expected a non-empty proof")
	}
	// Corrupt one sibling hash.
	proof[0][0] ^= 0x01
	if err := VerifyInclusion(leaves[idx], idx, size, proof, root); !errors.Is(err, ErrInclusionMismatch) {
		t.Fatalf("tampered path: want ErrInclusionMismatch, got %v", err)
	}
}

func TestInclusion_WrongSizeProofRejected(t *testing.T) {
	size := 8
	leaves := leafHashes(size)
	root, _ := MerkleTreeHash(leaves)
	idx := 1
	proof, _ := InclusionProof(idx, size, leaves)
	// Claim a different size than the proof was built for: the length
	// check must catch it before any hashing.
	if err := VerifyInclusion(leaves[idx], idx, 16, proof, root); !errors.Is(err, ErrBadProofSize) {
		t.Fatalf("wrong size: want ErrBadProofSize, got %v", err)
	}
}

func TestInclusion_ForgedProofForNonLoggedLeaf(t *testing.T) {
	// Adversarial: an event that was NEVER logged. Its leaf hash is not in
	// the tree. No proof of the correct length can reconstruct the trusted
	// root, so VerifyInclusion must reject for every index.
	size := 8
	leaves := leafHashes(size)
	root, _ := MerkleTreeHash(leaves)

	forged := HashLeaf([]byte("event-that-was-never-logged"))
	for idx := 0; idx < size; idx++ {
		// Reuse a genuine-shape proof (length is right) but the leaf is
		// alien → must fail.
		proof, _ := InclusionProof(idx, size, leaves)
		if err := VerifyInclusion(forged, idx, size, proof, root); err == nil {
			t.Fatalf("idx=%d: forged inclusion for non-logged leaf accepted", idx)
		}
	}
}

func TestInclusion_IndexOutOfRange(t *testing.T) {
	size := 4
	leaves := leafHashes(size)
	if _, err := InclusionProof(4, size, leaves); !errors.Is(err, ErrIndexOutOfRange) {
		t.Fatalf("want ErrIndexOutOfRange, got %v", err)
	}
	if _, err := InclusionProof(-1, size, leaves); !errors.Is(err, ErrIndexOutOfRange) {
		t.Fatalf("want ErrIndexOutOfRange for negative, got %v", err)
	}
}

// TestConsistency_RoundTripAllPairs is the anti-rewrite workhorse: for
// every (first <= second) up to a decent size, the proof must reconstruct
// BOTH the old and new roots.
func TestConsistency_RoundTripAllPairs(t *testing.T) {
	const max = 24
	full := leafHashes(max)
	roots := make([][HashSize]byte, max+1)
	for n := 1; n <= max; n++ {
		r, err := MerkleTreeHash(full[:n])
		if err != nil {
			t.Fatal(err)
		}
		roots[n] = r
	}

	for second := 1; second <= max; second++ {
		for first := 0; first <= second; first++ {
			proof, err := ConsistencyProof(first, second, full[:second])
			if err != nil {
				t.Fatalf("first=%d second=%d: build: %v", first, second, err)
			}
			var fRoot [HashSize]byte
			if first > 0 {
				fRoot = roots[first]
			}
			if err := VerifyConsistency(first, second, fRoot, roots[second], proof); err != nil {
				t.Fatalf("first=%d second=%d: verify: %v (prooflen=%d)", first, second, err, len(proof))
			}
		}
	}
}

// TestConsistency_RewriteDetected is the headline property: a log that
// REWROTE an early entry produces a different old-root; the consistency
// proof from the honest log cannot reconcile the rewritten new tree with
// the genuine old root → DETECTED.
func TestConsistency_RewriteDetected(t *testing.T) {
	first, second := 4, 8
	honest := leafHashes(second)
	oldRoot, _ := MerkleTreeHash(honest[:first])
	newRootHonest, _ := MerkleTreeHash(honest)

	// Attacker rewrites leaf 1 in the new tree (history tampering) but
	// still wants verifiers pinned to oldRoot to accept it.
	tampered := leafHashes(second)
	tampered[1] = HashLeaf([]byte("REWRITTEN"))
	newRootTampered, _ := MerkleTreeHash(tampered)

	// Honest proof for the honest new tree verifies fine.
	goodProof, _ := ConsistencyProof(first, second, honest)
	if err := VerifyConsistency(first, second, oldRoot, newRootHonest, goodProof); err != nil {
		t.Fatalf("honest consistency should pass: %v", err)
	}

	// The tampered new tree, presented with the genuine old root, must NOT
	// verify — regardless of which proof the attacker supplies.
	tamperedProof, _ := ConsistencyProof(first, second, tampered)
	if err := VerifyConsistency(first, second, oldRoot, newRootTampered, tamperedProof); !errors.Is(err, ErrConsistencyMismatch) {
		t.Fatalf("rewrite via tampered proof: want ErrConsistencyMismatch, got %v", err)
	}
	// Attacker tries the HONEST proof against the tampered new root.
	if err := VerifyConsistency(first, second, oldRoot, newRootTampered, goodProof); !errors.Is(err, ErrConsistencyMismatch) {
		t.Fatalf("rewrite via honest proof: want ErrConsistencyMismatch, got %v", err)
	}
}

func TestConsistency_TamperedProofRejected(t *testing.T) {
	first, second := 3, 9
	leaves := leafHashes(second)
	oldRoot, _ := MerkleTreeHash(leaves[:first])
	newRoot, _ := MerkleTreeHash(leaves)
	proof, _ := ConsistencyProof(first, second, leaves)
	if len(proof) == 0 {
		t.Fatal("expected non-empty consistency proof")
	}
	proof[0][0] ^= 0x80
	if err := VerifyConsistency(first, second, oldRoot, newRoot, proof); !errors.Is(err, ErrConsistencyMismatch) {
		t.Fatalf("tampered consistency proof: want ErrConsistencyMismatch, got %v", err)
	}
}

func TestConsistency_WrongLengthRejected(t *testing.T) {
	first, second := 3, 9
	leaves := leafHashes(second)
	oldRoot, _ := MerkleTreeHash(leaves[:first])
	newRoot, _ := MerkleTreeHash(leaves)
	proof, _ := ConsistencyProof(first, second, leaves)
	// Drop a hash → wrong length must be rejected up front.
	short := proof[:len(proof)-1]
	if err := VerifyConsistency(first, second, oldRoot, newRoot, short); !errors.Is(err, ErrBadProofSize) {
		t.Fatalf("short proof: want ErrBadProofSize, got %v", err)
	}
}

func TestConsistency_BadArgs(t *testing.T) {
	leaves := leafHashes(4)
	if _, err := ConsistencyProof(5, 4, leaves); !errors.Is(err, ErrBadConsistencyArgs) {
		t.Fatalf("first>second: want ErrBadConsistencyArgs, got %v", err)
	}
}

// TestConsistency_FirstEqualsSecond_RootMustMatch ensures the same-size
// path still checks root equality (a verifier shouldn't accept two
// different roots claimed at the same size — that's the split-view shape,
// caught here at the proof layer too).
func TestConsistency_FirstEqualsSecond_RootMustMatch(t *testing.T) {
	leaves := leafHashes(5)
	root, _ := MerkleTreeHash(leaves)
	var other [HashSize]byte
	copy(other[:], root[:])
	other[0] ^= 0xFF
	if err := VerifyConsistency(5, 5, root, other, nil); !errors.Is(err, ErrConsistencyMismatch) {
		t.Fatalf("same size, different roots: want ErrConsistencyMismatch, got %v", err)
	}
	if err := VerifyConsistency(5, 5, root, root, nil); err != nil {
		t.Fatalf("same size, same root: want pass, got %v", err)
	}
}
