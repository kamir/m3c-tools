package evaluation

// E8 — Trust-root SCALE (SPEC-0280 §2).
//
// Method: verify ONE bundle while the trust root pins N authors (N = 1 … 10^3),
// measuring how offline verify.Verify() scales with the size of the pinned-author
// set. The bundle's author sits at the END of the pinned list, so FindAuthor must
// scan the whole set — the worst case for the lookup. This is the "how many
// independent authors can a single relying party pin before verification slows"
// question (the trust-root scale the SPEC asks for).
//
// We report wall-clock vs N (a CSV curve). Verification cost is dominated by the
// fixed-size crypto (one SHA-256 over the blob + two ed25519 verifies), so the
// curve shows the author-lookup overhead is negligible against the crypto floor —
// itself a finding worth stating.

import (
	"context"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/evaluation/internal/synth"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

const e8Seed = 0x52800E8

// e8Sizes is the pinned-author-count sweep (1 → 10^3).
var e8Sizes = []int{1, 10, 100, 1000}

// TestE8TrustRootScale measures offline verify time as the pinned-author set
// grows, with the verified bundle's author at the worst-case (last) position.
func TestE8TrustRootScale(t *testing.T) {
	requireEval(t)

	for _, n := range e8Sizes {
		dir := t.TempDir()
		// Mint n bundles → n distinct pinned authors in one root.
		pop, err := synth.MintPopulation(dir, n, e8Seed)
		if err != nil {
			t.Fatalf("mint n=%d: %v", n, err)
		}
		root := pop.Root
		// Verify the LAST bundle (its author is last in the pinned list → worst
		// case for FindAuthor's scan).
		target := pop.Bundles[n-1]

		// Warm once (also asserts it verifies under the n-author root).
		if err := verifyOne(target, root); err != nil {
			t.Fatalf("warm verify n=%d: %v", n, err)
		}

		const reps = 3000
		durs := make([]time.Duration, 0, reps)
		for r := 0; r < reps; r++ {
			start := time.Now()
			if _, err := verify.Verify(verify.VerifyOpts{
				BundlePath:      target.Path,
				BundleMeta:      target.Meta,
				TrustRoot:       root,
				IdentityFetcher: nil,
				Ctx:             context.Background(),
			}); err != nil {
				t.Fatalf("verify n=%d: %v", n, err)
			}
			durs = append(durs, time.Since(start))
		}
		med, p99 := medianP99(durs)
		t.Logf("E8 pinned_authors=%d verify median=%.4fms p99=%.4fms", n, ms(med), ms(p99))
		record(t, "E8", "trustroot-scale", "median_ms", round4(ms(med)),
			"offline verify with %d pinned authors (target author last → worst-case lookup), reps=%d", n, reps)
	}
}
