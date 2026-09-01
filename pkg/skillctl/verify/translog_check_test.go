package verify

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/pkg/skillctl/translog"
)

// buildPinnedLog creates a small log, signs a head, and returns a
// *TrustRoots pinning that log + STH, plus the inclusion input for a chosen
// entry. requireInclusion controls the policy field.
func buildPinnedLog(t *testing.T, requireInclusion bool) (*TrustRoots, LogInclusionInput, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)

	// Build a log of 5 entries.
	logID := "skillctl-log-1"
	entries := make([]translog.LogEntry, 5)
	leaves := make([][translog.HashSize]byte, 5)
	for i := 0; i < 5; i++ {
		e := translog.LogEntry{
			Type:      translog.EventAttest,
			Digest:    "sha256:" + strings.Repeat("0", 63) + itoaLocal(i),
			Timestamp: "2026-06-24T12:00:0" + itoaLocal(i) + "Z",
			Subject:   "skill-" + itoaLocal(i),
		}
		entries[i] = e
		h, err := e.LeafHash()
		if err != nil {
			t.Fatal(err)
		}
		leaves[i] = h
	}
	root, err := translog.MerkleTreeHash(leaves)
	if err != nil {
		t.Fatal(err)
	}
	sth := translog.STH{
		TreeSize:  5,
		RootHash:  hexLocal(root),
		Timestamp: translog.FormatSTHTimestamp(time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)),
		LogID:     logID,
	}
	signed, err := translog.SignSTH(priv, sth)
	if err != nil {
		t.Fatal(err)
	}

	tr := &TrustRoots{
		RequireLogInclusion: requireInclusion,
		Logs: []LogTrust{{
			LogID:     logID,
			LogKeyB64: base64.StdEncoding.EncodeToString(pub),
			LogKey:    pub,
			PinnedSTHs: []PinnedSTH{{
				TreeSize:  signed.TreeSize,
				RootHash:  signed.RootHash,
				Timestamp: signed.Timestamp,
				LogID:     signed.LogID,
				Signature: signed.Signature,
			}},
		}},
	}

	// Inclusion input for entry index 2.
	proof, err := translog.InclusionProof(2, 5, leaves)
	if err != nil {
		t.Fatal(err)
	}
	in := LogInclusionInput{
		Entry:    entries[2],
		Index:    2,
		TreeSize: 5,
		Proof:    proof,
		LogID:    logID,
	}
	return tr, in, priv
}

func TestCheckLogInclusion_Success(t *testing.T) {
	tr, in, _ := buildPinnedLog(t, true)
	res, err := CheckLogInclusion(tr, in, true)
	if err != nil {
		t.Fatalf("inclusion should pass: %v", err)
	}
	if !res.Included || res.STHTreeSize != 5 {
		t.Fatalf("unexpected result: %+v", res)
	}
}

// TestCheckLogInclusion_RequireFailsClosed: with require_log_inclusion the
// absence of a valid proof is a HARD refusal (ErrLogInclusionMissing).
func TestCheckLogInclusion_RequireFailsClosed_NoProof(t *testing.T) {
	tr, in, _ := buildPinnedLog(t, true)
	in.Proof = nil // drop the proof
	_, err := CheckLogInclusion(tr, in, true)
	if !errors.Is(err, ErrLogInclusionMissing) {
		t.Fatalf("require + no proof: want ErrLogInclusionMissing, got %v", err)
	}
	if ExitCodeForLog(err) != ExitLogInclusionMissing {
		t.Fatalf("exit code = %d, want %d", ExitCodeForLog(err), ExitLogInclusionMissing)
	}
}

// TestCheckLogInclusion_RequireFailsClosed_ForgedEvent: an event that was
// never logged (its leaf isn't in the tree) cannot be shown included →
// fail-closed.
func TestCheckLogInclusion_ForgedEvent(t *testing.T) {
	tr, in, _ := buildPinnedLog(t, true)
	// Swap in an event that was never logged but reuse a valid-shape proof.
	in.Entry = translog.LogEntry{
		Type:      translog.EventAttest,
		Digest:    "sha256:" + strings.Repeat("a", 64),
		Timestamp: "2026-06-24T12:00:00Z",
		Subject:   "never-logged",
	}
	_, err := CheckLogInclusion(tr, in, true)
	if !errors.Is(err, ErrLogInclusionMissing) {
		t.Fatalf("forged event: want ErrLogInclusionMissing, got %v", err)
	}
}

// TestCheckLogInclusion_AdvisoryDefault: without the policy, a missing proof
// is advisory — returns Included=false, no error.
func TestCheckLogInclusion_AdvisoryDefault(t *testing.T) {
	tr, in, _ := buildPinnedLog(t, false)
	in.Proof = nil
	res, err := CheckLogInclusion(tr, in, false)
	if err != nil {
		t.Fatalf("advisory mode should not error: %v", err)
	}
	if res.Included {
		t.Fatal("advisory: expected Included=false")
	}
	if res.Advisory == "" {
		t.Fatal("advisory: expected a human-readable note")
	}
}

// TestCheckLogInclusion_UnpinnedSTHKeyRefused: if the pinned STH is signed
// by a key OTHER than the pinned log key, it is not a valid head and the
// inclusion check cannot pass (fail-closed under require).
func TestCheckLogInclusion_UnpinnedSTHKeyRefused(t *testing.T) {
	tr, in, _ := buildPinnedLog(t, true)
	// Re-sign the pinned STH with an ATTACKER key but keep the pinned
	// (honest) public key in the trust-roots → VerifySTH fails → no valid
	// head at this size.
	_, attacker, _ := ed25519.GenerateKey(nil)
	root, _ := translog.MerkleTreeHash(rebuildLeaves(t, in))
	bad := translog.STH{TreeSize: 5, RootHash: hexLocal(root), Timestamp: tr.Logs[0].PinnedSTHs[0].Timestamp, LogID: in.LogID}
	signedBad, _ := translog.SignSTH(attacker, bad)
	tr.Logs[0].PinnedSTHs[0].Signature = signedBad.Signature

	_, err := CheckLogInclusion(tr, in, true)
	if !errors.Is(err, ErrLogInclusionMissing) {
		t.Fatalf("unpinned STH key: want ErrLogInclusionMissing, got %v", err)
	}
}

// TestCheckLogInclusion_NoPinnedLog: an event referencing an unpinned log
// fails-closed under require.
func TestCheckLogInclusion_NoPinnedLog(t *testing.T) {
	tr, in, _ := buildPinnedLog(t, true)
	in.LogID = "some-other-log"
	if _, err := CheckLogInclusion(tr, in, true); !errors.Is(err, ErrLogInclusionMissing) {
		t.Fatalf("unpinned log: want ErrLogInclusionMissing, got %v", err)
	}
}

// rebuildLeaves reconstructs the 5 leaves used by buildPinnedLog so a test
// can recompute the honest root. It mirrors the entry construction.
func rebuildLeaves(t *testing.T, _ LogInclusionInput) [][translog.HashSize]byte {
	t.Helper()
	leaves := make([][translog.HashSize]byte, 5)
	for i := 0; i < 5; i++ {
		e := translog.LogEntry{
			Type:      translog.EventAttest,
			Digest:    "sha256:" + strings.Repeat("0", 63) + itoaLocal(i),
			Timestamp: "2026-06-24T12:00:0" + itoaLocal(i) + "Z",
			Subject:   "skill-" + itoaLocal(i),
		}
		h, _ := e.LeafHash()
		leaves[i] = h
	}
	return leaves
}

func itoaLocal(i int) string {
	return string(rune('0' + i))
}

func hexLocal(h [translog.HashSize]byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, len(h)*2)
	for _, b := range h {
		out = append(out, hexdigits[b>>4], hexdigits[b&0x0f])
	}
	return string(out)
}
