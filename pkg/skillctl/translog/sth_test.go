package translog

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/signing"
)

// makeSTH builds and signs an STH over the tree of the given leaf payloads.
func makeSTH(t *testing.T, logKey ed25519.PrivateKey, logID string, leaves [][HashSize]byte) STH {
	t.Helper()
	root, err := MerkleTreeHash(leaves)
	if err != nil {
		t.Fatal(err)
	}
	s := STH{
		TreeSize:  len(leaves),
		RootHash:  hexOf(root),
		Timestamp: FormatSTHTimestamp(time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)),
		LogID:     logID,
	}
	signed, err := SignSTH(logKey, s)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestSTH_SignVerifyRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	leaves := leafHashes(5)
	s := makeSTH(t, priv, "skillctl-log-A", leaves)
	if err := VerifySTH(pub, s); err != nil {
		t.Fatalf("round-trip verify failed: %v", err)
	}
}

// TestSTH_UnpinnedKeyRefused: an STH signed by a key the verifier did NOT
// pin must be refused. This is the headline trust check.
func TestSTH_UnpinnedKeyRefused(t *testing.T) {
	_, attackerPriv, _ := ed25519.GenerateKey(nil)
	pinnedPub, _, _ := ed25519.GenerateKey(nil) // the key we trust

	leaves := leafHashes(4)
	forged := makeSTH(t, attackerPriv, "skillctl-log-A", leaves)

	if err := VerifySTH(pinnedPub, forged); !errors.Is(err, ErrSTHSignatureInvalid) {
		t.Fatalf("STH by unpinned key: want ErrSTHSignatureInvalid, got %v", err)
	}
}

// TestSTH_ForgedRootRefused: an attacker keeps a valid signature but swaps
// the root_hash → the signed bytes no longer match → rejected.
func TestSTH_ForgedRootRefused(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	leaves := leafHashes(6)
	s := makeSTH(t, priv, "skillctl-log-A", leaves)

	// Swap the root to a different tree's root, keep the old signature.
	other, _ := MerkleTreeHash(leafHashes(7))
	s.RootHash = hexOf(other)
	if err := VerifySTH(pub, s); !errors.Is(err, ErrSTHSignatureInvalid) {
		t.Fatalf("forged root: want ErrSTHSignatureInvalid, got %v", err)
	}
}

func TestSTH_TamperedTreeSizeRefused(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	s := makeSTH(t, priv, "skillctl-log-A", leafHashes(5))
	s.TreeSize = 9 // lie about the size, keep signature
	if err := VerifySTH(pub, s); !errors.Is(err, ErrSTHSignatureInvalid) {
		t.Fatalf("tampered tree_size: want ErrSTHSignatureInvalid, got %v", err)
	}
}

func TestSTH_MalformedRejectedBeforeCrypto(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	good := makeSTH(t, priv, "log", leafHashes(3))

	cases := []struct {
		name string
		mut  func(STH) STH
	}{
		{"zero size", func(s STH) STH { s.TreeSize = 0; return s }},
		{"short root", func(s STH) STH { s.RootHash = "abcd"; return s }},
		{"bad timestamp", func(s STH) STH { s.Timestamp = "2026-06-24 12:00:00"; return s }},
		{"bad logid newline", func(s STH) STH { s.LogID = "log\nevil"; return s }},
		{"empty logid", func(s STH) STH { s.LogID = ""; return s }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bad := c.mut(good)
			if err := VerifySTH(pub, bad); !errors.Is(err, ErrSTHMalformed) {
				t.Fatalf("%s: want ErrSTHMalformed, got %v", c.name, err)
			}
		})
	}
}

// TestSTH_CrossDomain_SignatureReuseRefused is the adversarial cross-domain
// test: a signature minted over an ATTESTATION message (signing.Attestation
// domain) by a key must NOT verify as an STH, and an STH signature must NOT
// verify as an attestation. The distinct leading domain separators
// guarantee the signed-byte spaces are disjoint.
func TestSTH_CrossDomain_SignatureReuseRefused(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)

	// 1) Take a real STH and try to pass its signed bytes off as an
	//    attestation: the attestation canonical message starts with
	//    "attestation\n", the STH with "skillctl-sth-v1\n" — they can
	//    never be equal, so an STH signature can't satisfy an attestation
	//    verify and vice versa. We assert the messages are byte-distinct
	//    AND that signatures don't cross-verify.
	leaves := leafHashes(4)
	root, _ := MerkleTreeHash(leaves)
	sth := STH{
		TreeSize:  len(leaves),
		RootHash:  hexOf(root),
		Timestamp: "2026-06-24T12:00:00Z",
		LogID:     "log",
	}
	sthMsg, err := sth.CanonicalSTHMessage()
	if err != nil {
		t.Fatal(err)
	}

	// Build an attestation message that happens to reference the SAME
	// digest material, to make the reuse attempt maximally realistic.
	attMsg, err := signing.CanonicalizeAttestationMessage(
		"sha256:"+hexOf(root), "green", "2026-06-24T12:00:00Z", "reviewer-1")
	if err != nil {
		t.Fatal(err)
	}

	// The signed-byte spaces must be disjoint (different domain prefix).
	if string(sthMsg) == string(attMsg) {
		t.Fatal("STH and attestation canonical messages collided — domain separation broken")
	}

	// Sign the ATTESTATION with this key, then try to use that signature
	// as the STH signature → must fail.
	attSig := ed25519.Sign(priv, attMsg)
	sth.Signature = hex.EncodeToString(attSig)
	if err := VerifySTH(pub, sth); !errors.Is(err, ErrSTHSignatureInvalid) {
		t.Fatalf("attestation signature reused as STH: want ErrSTHSignatureInvalid, got %v", err)
	}

	// Conversely: sign the STH, then try to verify that signature as an
	// attestation → ed25519.Verify over attMsg must fail.
	sthSig := ed25519.Sign(priv, sthMsg)
	if ed25519.Verify(pub, attMsg, sthSig) {
		t.Fatal("STH signature verified as an attestation — cross-domain reuse possible")
	}
}

func TestSTH_Equal(t *testing.T) {
	leaves := leafHashes(5)
	root, _ := MerkleTreeHash(leaves)
	a := STH{TreeSize: 5, RootHash: hexOf(root), Timestamp: "2026-06-24T12:00:00Z", LogID: "L"}
	b := STH{TreeSize: 5, RootHash: hexOf(root), Timestamp: "2026-06-24T13:00:00Z", LogID: "L"} // diff ts
	if !a.Equal(b) {
		t.Fatal("same (size,root,logid) STHs should be Equal regardless of timestamp")
	}
	c := a
	c.RootHash = hexOf(leafHashes(1)[0]) // different root, same size
	if a.Equal(c) {
		t.Fatal("same size + different root must NOT be Equal (that's a split view)")
	}
}
