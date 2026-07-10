package evaluation

// E1 — Offline `verify` latency (SPEC-0280 §2).
//
// Method: synthesize N=10^4 signed bundles (synth.MintPopulation, deterministic
// seed), then measure the SHIPPED verify.Verify() over them in pinned-author
// (fully offline) mode. We report:
//
//   - cold:  each iteration verifies a bundle whose .skb has NOT been read this
//            run (the OS page cache is the only warmth); we sweep distinct
//            bundles so the per-call digest recompute reads fresh bytes.
//   - warm:  each iteration re-verifies the SAME bundle, so the blob bytes are
//            hot in cache and we isolate the crypto + chain-walk cost.
//
// verify.Verify reads the .skb once (SHA-256 over the bytes), checks the author
// signature against the pinned key, the registry signature against the pinned
// registry key, the governance gate, and surfaces the signed-manifest data-scope
// — the full SPEC-0188 §7 algorithm, no network.
//
// Single core: run with `-cpu 1`. The harness records median + p99 via a
// dedicated latency driver (TestE1Latency) that the runner invokes; the
// Benchmark form gives ns/op for cross-checking.

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/kamir/m3c-tools/evaluation/internal/synth"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// e1Seed is the fixed seed for the E1 population (reproducibility).
const e1Seed = 0x5180280E1

// e1PopulationSize is N for the latency sweep (SPEC-0280: N=10^4). The latency
// test mints this many; the Go Benchmark forms use a smaller working set so the
// -benchtime loop has many bundles to sweep without exhausting the population.
const e1PopulationSize = 10000

// verifyOne runs the shipped offline verify over a single synthesized bundle.
func verifyOne(b *synth.Bundle, root *verify.TrustRoot) error {
	_, err := verify.Verify(verify.VerifyOpts{
		BundlePath:      b.Path,
		BundleMeta:      b.Meta,
		TrustRoot:       root,
		IdentityFetcher: nil, // pinned mode → fully offline
		Ctx:             context.Background(),
	})
	return err
}

// BenchmarkE1VerifyWarm re-verifies the SAME bundle so the blob is hot in cache;
// isolates crypto + chain-walk cost. Run: go test -run x -bench E1VerifyWarm -cpu 1.
func BenchmarkE1VerifyWarm(b *testing.B) {
	dir := b.TempDir()
	pop, err := synth.MintPopulation(dir, 1, e1Seed)
	if err != nil {
		b.Fatalf("mint: %v", err)
	}
	bundle := pop.Bundles[0]
	if err := verifyOne(bundle, pop.Root); err != nil {
		b.Fatalf("warm-up verify failed: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := verifyOne(bundle, pop.Root); err != nil {
			b.Fatalf("verify: %v", err)
		}
	}
}

// BenchmarkE1VerifyCold sweeps DISTINCT bundles each iteration so the digest
// recompute reads bytes that were not touched by the previous call. Run:
// go test -run x -bench E1VerifyCold -cpu 1.
func BenchmarkE1VerifyCold(b *testing.B) {
	dir := b.TempDir()
	const n = 1024
	pop, err := synth.MintPopulation(dir, n, e1Seed)
	if err != nil {
		b.Fatalf("mint: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bundle := pop.Bundles[i%n]
		if err := verifyOne(bundle, pop.Root); err != nil {
			b.Fatalf("verify: %v", err)
		}
	}
}

// TestE1Latency mints the full N=10^4 population and measures the per-call
// wall-clock distribution for cold (first-touch sweep) and warm (repeat) verify,
// reporting median and p99 in milliseconds. This is the SPEC-0280 §2 E1 row.
// It writes its numbers to the run log via t.Log; the runner harvests them into
// the CSV. Guarded behind -short skipping so `go test` stays fast by default
// unless RUN_EVAL is set.
func TestE1Latency(t *testing.T) {
	requireEval(t)
	dir := t.TempDir()
	pop, err := synth.MintPopulation(dir, e1PopulationSize, e1Seed)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	root := pop.Root

	// Cold: one verify per distinct bundle (first touch this run).
	cold := make([]time.Duration, len(pop.Bundles))
	for i, bundle := range pop.Bundles {
		start := time.Now()
		if err := verifyOne(bundle, root); err != nil {
			t.Fatalf("cold verify[%d]: %v", i, err)
		}
		cold[i] = time.Since(start)
	}

	// Warm: re-verify a single bundle N times (hot cache).
	warm := make([]time.Duration, e1PopulationSize)
	hot := pop.Bundles[0]
	for i := 0; i < e1PopulationSize; i++ {
		start := time.Now()
		if err := verifyOne(hot, root); err != nil {
			t.Fatalf("warm verify[%d]: %v", i, err)
		}
		warm[i] = time.Since(start)
	}

	cMed, cP99 := medianP99(cold)
	wMed, wP99 := medianP99(warm)

	t.Logf("E1 N=%d cold: median=%.4fms p99=%.4fms", len(cold), ms(cMed), ms(cP99))
	t.Logf("E1 N=%d warm: median=%.4fms p99=%.4fms", len(warm), ms(wMed), ms(wP99))

	record(t, "E1", "verify-latency-cold", "median_ms", round4(ms(cMed)),
		"N=%d single-core offline pinned-author verify, first-touch sweep", len(cold))
	record(t, "E1", "verify-latency-cold", "p99_ms", round4(ms(cP99)),
		"N=%d single-core offline pinned-author verify, first-touch sweep", len(cold))
	record(t, "E1", "verify-latency-warm", "median_ms", round4(ms(wMed)),
		"N=%d single-core offline pinned-author verify, hot cache", len(warm))
	record(t, "E1", "verify-latency-warm", "p99_ms", round4(ms(wP99)),
		"N=%d single-core offline pinned-author verify, hot cache", len(warm))
}

// medianP99 returns the median and the 99th-percentile of a duration sample.
func medianP99(d []time.Duration) (median, p99 time.Duration) {
	if len(d) == 0 {
		return 0, 0
	}
	s := make([]time.Duration, len(d))
	copy(s, d)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	median = s[len(s)/2]
	idx := (len(s)*99 + 99) / 100 // ceil(0.99*n)
	if idx >= len(s) {
		idx = len(s) - 1
	}
	p99 = s[idx]
	return median, p99
}

func ms(d time.Duration) float64 { return float64(d.Nanoseconds()) / 1e6 }
