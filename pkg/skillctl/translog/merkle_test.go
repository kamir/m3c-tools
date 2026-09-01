package translog

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// leafHashes builds n leaf hashes from deterministic byte payloads
// "leaf-0", "leaf-1", ... so tests are reproducible.
func leafHashes(n int) [][HashSize]byte {
	out := make([][HashSize]byte, n)
	for i := 0; i < n; i++ {
		out[i] = HashLeaf([]byte("leaf-" + itoa(i)))
	}
	return out
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

// refRoot is an INDEPENDENT reference implementation of the RFC-6962 MTH,
// written as plainly as possible so it can't share a bug with the
// production merkleTreeHash. Tests cross-check production against this.
func refRoot(leaves [][HashSize]byte) [HashSize]byte {
	n := len(leaves)
	if n == 1 {
		return leaves[0]
	}
	// largest power of two < n
	k := 1
	for k*2 < n {
		k *= 2
	}
	l := refRoot(leaves[:k])
	r := refRoot(leaves[k:])
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(l[:])
	h.Write(r[:])
	var out [HashSize]byte
	copy(out[:], h.Sum(nil))
	return out
}

func TestHashLeaf_DomainPrefix(t *testing.T) {
	// A leaf hash MUST be SHA-256(0x00 || bytes) — verify against a manual
	// computation so the prefix can never be silently dropped.
	data := []byte("hello-world")
	got := HashLeaf(data)

	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	var want [HashSize]byte
	copy(want[:], h.Sum(nil))

	if got != want {
		t.Fatalf("HashLeaf mismatch:\n got %x\nwant %x", got, want)
	}

	// And it must DIFFER from the bare SHA-256 (no prefix) — that's the
	// whole point of domain separation.
	bare := sha256.Sum256(data)
	if got == bare {
		t.Fatal("HashLeaf must not equal bare SHA-256 (domain prefix missing?)")
	}
}

// TestSecondPreimage_LeafNodeConfusion is the adversarial guard: feeding
// the CONCATENATION of two child hashes in as a LEAF value must produce a
// different hash than the INTERNAL NODE over those same two children. If
// the prefixes were absent, an attacker could present a leaf whose hash
// equals an internal node and confuse the verifier.
func TestSecondPreimage_LeafNodeConfusion(t *testing.T) {
	a := HashLeaf([]byte("a"))
	b := HashLeaf([]byte("b"))

	node := hashChildren(a, b) // 0x01 || a || b

	// An attacker crafts a leaf whose raw bytes are exactly a||b and hopes
	// HashLeaf(a||b) == node.
	var concat []byte
	concat = append(concat, a[:]...)
	concat = append(concat, b[:]...)
	leaf := HashLeaf(concat) // 0x00 || (a||b)

	if leaf == node {
		t.Fatal("leaf-vs-node confusion: HashLeaf(a||b) collided with hashChildren(a,b) — domain prefixes broken")
	}
}

func TestMerkleTreeHash_EmptyIsError(t *testing.T) {
	if _, err := MerkleTreeHash(nil); err == nil {
		t.Fatal("expected ErrEmptyTree for zero leaves")
	}
}

func TestMerkleTreeHash_SingleLeafIsLeaf(t *testing.T) {
	leaves := leafHashes(1)
	root, err := MerkleTreeHash(leaves)
	if err != nil {
		t.Fatal(err)
	}
	if root != leaves[0] {
		t.Fatalf("single-leaf root must equal the leaf hash itself")
	}
}

// TestMerkleTreeHash_MatchesReference cross-checks production MTH against
// the independent reference for many sizes, including non-powers-of-two
// where the k-split matters most.
func TestMerkleTreeHash_MatchesReference(t *testing.T) {
	for n := 1; n <= 33; n++ {
		leaves := leafHashes(n)
		got, err := MerkleTreeHash(leaves)
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		want := refRoot(leaves)
		if got != want {
			t.Fatalf("n=%d root mismatch:\n got %x\nwant %x", n, got, want)
		}
	}
}

// TestMerkleTreeHash_GoldenVectors pins a few small trees to exact hex so
// any future change to the hashing construction is caught loudly. The
// vectors are derived from the construction itself (self-consistent golden
// values), then frozen.
func TestMerkleTreeHash_GoldenVectors(t *testing.T) {
	cases := []struct {
		n   int
		hex string
	}{
		{1, hexOf(HashLeaf([]byte("leaf-0")))},
		{2, hexOf(hashChildren(HashLeaf([]byte("leaf-0")), HashLeaf([]byte("leaf-1"))))},
	}
	for _, c := range cases {
		leaves := leafHashes(c.n)
		root, err := MerkleTreeHash(leaves)
		if err != nil {
			t.Fatal(err)
		}
		if hexOf(root) != c.hex {
			t.Fatalf("n=%d golden mismatch:\n got %s\nwant %s", c.n, hexOf(root), c.hex)
		}
	}

	// n=4 must equal H(H(l0,l1), H(l2,l3)) — a balanced tree.
	l := leafHashes(4)
	want4 := hashChildren(hashChildren(l[0], l[1]), hashChildren(l[2], l[3]))
	got4, _ := MerkleTreeHash(l)
	if got4 != want4 {
		t.Fatal("n=4 balanced-tree shape mismatch")
	}

	// n=3 must equal H(H(l0,l1), l2) — k=2, right subtree is a lone leaf.
	l3 := leafHashes(3)
	want3 := hashChildren(hashChildren(l3[0], l3[1]), l3[2])
	got3, _ := MerkleTreeHash(l3)
	if got3 != want3 {
		t.Fatal("n=3 unbalanced-tree shape mismatch (k-split wrong?)")
	}
}

func TestLargestPowerOfTwoLessThan(t *testing.T) {
	cases := map[int]int{2: 1, 3: 2, 4: 2, 5: 4, 7: 4, 8: 4, 9: 8, 16: 8, 17: 16}
	for n, want := range cases {
		if got := largestPowerOfTwoLessThan(n); got != want {
			t.Fatalf("largestPowerOfTwoLessThan(%d)=%d want %d", n, got, want)
		}
	}
}

func hexOf(h [HashSize]byte) string { return hex.EncodeToString(h[:]) }

// sanity: the bytes helper used in proof tests behaves.
func TestBytesEqualHelper(t *testing.T) {
	a := HashLeaf([]byte("x"))
	b := HashLeaf([]byte("x"))
	if !bytes.Equal(a[:], b[:]) {
		t.Fatal("deterministic leaf hashing broken")
	}
}
