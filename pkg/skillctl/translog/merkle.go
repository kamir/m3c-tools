package translog

import (
	"crypto/sha256"
	"errors"
)

// RFC-6962 domain-separation prefixes. These single bytes are hashed in
// FRONT of the data so a leaf hash and an internal-node hash live in
// disjoint pre-image spaces. Removing them would reopen the classic
// Merkle second-preimage / leaf-vs-node confusion (see doc.go).
const (
	// LeafPrefix (0x00) tags a leaf hash: SHA-256(0x00 || leaf_bytes).
	LeafPrefix byte = 0x00
	// NodePrefix (0x01) tags an internal-node hash:
	// SHA-256(0x01 || left_hash || right_hash).
	NodePrefix byte = 0x01
)

// HashSize is the width of every node and leaf hash in the tree (SHA-256).
const HashSize = sha256.Size // 32

// ErrEmptyTree is returned when a root hash is requested for zero leaves.
// RFC-6962 defines MTH({}) = SHA-256() (the hash of the empty string), but
// our log never commits an empty tree to an STH, so we treat zero leaves
// as a caller error to surface bugs loudly rather than sign over a
// degenerate root.
var ErrEmptyTree = errors.New("translog: cannot hash an empty tree")

// HashLeaf returns the RFC-6962 leaf hash of leafBytes:
//
//	SHA-256( 0x00 || leafBytes )
//
// leafBytes is the canonical event encoding (see LogEntry.Canonical). The
// 0x00 prefix is what stops a leaf value from ever colliding with an
// internal node hash.
func HashLeaf(leafBytes []byte) [HashSize]byte {
	h := sha256.New()
	h.Write([]byte{LeafPrefix})
	h.Write(leafBytes)
	var out [HashSize]byte
	copy(out[:], h.Sum(nil))
	return out
}

// hashChildren returns the RFC-6962 internal-node hash of two child
// hashes:
//
//	SHA-256( 0x01 || left || right )
//
// The 0x01 prefix is the counterpart to HashLeaf's 0x00: it guarantees an
// internal node and a leaf can never share a pre-image.
func hashChildren(left, right [HashSize]byte) [HashSize]byte {
	h := sha256.New()
	h.Write([]byte{NodePrefix})
	h.Write(left[:])
	h.Write(right[:])
	var out [HashSize]byte
	copy(out[:], h.Sum(nil))
	return out
}

// MerkleTreeHash computes the RFC-6962 Merkle Tree Hash (MTH) over the
// ordered slice of already-hashed leaves.
//
// The recurrence (RFC-6962 §2.1) for n > 1 leaves D[0:n] is:
//
//	MTH(D[0:n]) = HASH( 0x01 || MTH(D[0:k]) || MTH(D[k:n]) )
//
// where k is the LARGEST power of two strictly less than n. This split —
// not a simple round-up — is the load-bearing detail that makes inclusion
// and consistency proofs interoperate with every other RFC-6962
// implementation.
//
// Callers pass leaf HASHES (the output of HashLeaf), not raw event bytes;
// keeping leaf hashing separate lets the inclusion-proof verifier work
// from a single leaf hash without re-encoding the event.
//
// Returns ErrEmptyTree for an empty slice.
func MerkleTreeHash(leaves [][HashSize]byte) ([HashSize]byte, error) {
	var zero [HashSize]byte
	n := len(leaves)
	if n == 0 {
		return zero, ErrEmptyTree
	}
	return merkleTreeHash(leaves), nil
}

// merkleTreeHash is the unchecked recursive core. Precondition: len > 0.
func merkleTreeHash(leaves [][HashSize]byte) [HashSize]byte {
	n := len(leaves)
	if n == 1 {
		// A single leaf's tree hash is the leaf hash itself — NOT a
		// re-hash. RFC-6962 §2.1: MTH(D[0:1]) = the leaf's hash.
		return leaves[0]
	}
	k := largestPowerOfTwoLessThan(n)
	left := merkleTreeHash(leaves[:k])
	right := merkleTreeHash(leaves[k:])
	return hashChildren(left, right)
}

// largestPowerOfTwoLessThan returns the largest power of two STRICTLY less
// than n, for n >= 2. This is RFC-6962's "k" split point. For n a power of
// two it returns n/2; otherwise it returns the highest power of two below
// n (e.g. n=5 → 4, n=7 → 4, n=8 → 4).
//
// Implemented without bit-twiddling cleverness so the property is obvious:
// double a candidate until the NEXT double would meet or exceed n.
func largestPowerOfTwoLessThan(n int) int {
	if n < 2 {
		// Caller invariant violation; the recursion never asks for this.
		panic("translog: largestPowerOfTwoLessThan requires n >= 2")
	}
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}
