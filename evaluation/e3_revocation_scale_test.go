package evaluation

// E3 — Revocation-list verify vs SIZE (SPEC-0280 §2; SPEC-0276 R4.4).
//
// Method: build a signed revocation list of N digests (N = 10 … 10^6), signed by
// the population registry key, then measure the SHIPPED offline verification:
//
//   verify.VerifyRevocationList(list, root, minEpoch)
//
// which canonicalizes (validate + lowercase + dedup + SORT) the N digests, runs
// one ed25519 verify against the pinned registry key, enforces the epoch floor,
// and returns the revoked-digest set. We report wall-clock vs N (a CSV curve):
// the cost is dominated by the O(N log N) canonicalization, with a single
// constant-time signature check, so the curve is the artifact.

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/evaluation/internal/synth"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

const e3Seed = 0x52760E3

// e3Sizes is the list-size sweep (10 → 10^6).
var e3Sizes = []int{10, 100, 1000, 10000, 100000, 1000000}

// TestE3RevocationScale measures offline revocation-list verify time vs list
// size and records one CSV row per size.
func TestE3RevocationScale(t *testing.T) {
	requireEval(t)
	regPriv := synth.RegistryPriv(e3Seed)
	root := func() *verify.TrustRoot {
		r := e10Root() // reuse the registry-pinned root shape
		// e10Root pins synth.RegistryPriv(e10Seed); re-pin to e3Seed's key.
		return rePinRegistry(r, e3Seed)
	}()

	for _, n := range e3Sizes {
		digests := synth.SyntheticDigests(n, e3Seed)
		list, err := verify.NewSignedRevocationList(synth.RegistryURL, "2026-06-24T00:00:00Z", 5, digests, regPriv)
		if err != nil {
			t.Fatalf("sign list n=%d: %v", n, err)
		}

		// Warm once (also asserts it verifies).
		if _, err := verify.VerifyRevocationList(list, root, 5); err != nil {
			t.Fatalf("warm verify n=%d: %v", n, err)
		}

		// Repeat enough to get a stable median; fewer reps for the huge lists.
		reps := repsForSize(n)
		durs := make([]time.Duration, 0, reps)
		for r := 0; r < reps; r++ {
			start := time.Now()
			if _, err := verify.VerifyRevocationList(list, root, 5); err != nil {
				t.Fatalf("verify n=%d: %v", n, err)
			}
			durs = append(durs, time.Since(start))
		}
		med, _ := medianP99(durs)
		t.Logf("E3 n=%d revocation-verify median=%.4fms", n, ms(med))
		record(t, "E3", "revocation-verify", "median_ms", round4(ms(med)),
			"offline VerifyRevocationList (canon+sort+1 ed25519 verify), list_size=%d, reps=%d", n, reps)
	}
}

// repsForSize chooses an iteration count: many for small lists, few for 10^6.
func repsForSize(n int) int {
	switch {
	case n <= 1000:
		return 2000
	case n <= 100000:
		return 200
	default:
		return 20
	}
}

// rePinRegistry returns a copy of root whose single registry key is re-derived
// from seed (so a list signed with synth.RegistryPriv(seed) verifies).
func rePinRegistry(root *verify.TrustRoot, seed uint64) *verify.TrustRoot {
	priv := synth.RegistryPriv(seed)
	pub := priv.Public().(ed25519.PublicKey)
	cp := *root
	cp.RegistryKeys = []verify.RegistryKey{{
		ID:     "eval-registry-2026",
		Pubkey: []byte(pub),
		Issued: "2026-06-22",
	}}
	return &cp
}
