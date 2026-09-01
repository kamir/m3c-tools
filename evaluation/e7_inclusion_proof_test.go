package evaluation

// E7 — Transparency-log INCLUSION-PROOF verify (SPEC-0280 §2; SPEC-0278).
//
// Method: build a transparency log of N entries, sign a tree head (STH) with a
// deterministic log key, produce a per-event inclusion proof, then measure the
// SHIPPED offline verification of that proof against the witnessed STH:
//
//   translog.VerifyInclusion(leafHash, index, size, proof, root)
//
// This is the RFC-6962 audit-path check a relying party runs to confirm an event
// (admit / revoke / attest) is committed in the log it pinned — no log server
// contacted. We report time/event in microseconds across a range of tree sizes
// (the proof length is O(log N), so the curve is the interesting artifact).

import (
	"testing"
	"time"

	"github.com/kamir/m3c-tools/evaluation/internal/synth"
	"github.com/kamir/m3c-tools/pkg/skillctl/translog"
)

const e7Seed = 0x52780278

// e7Sizes are the tree sizes the inclusion-proof curve is measured at.
var e7Sizes = []int{16, 256, 4096, 65536}

// buildLog appends n deterministic entries to a fresh log and returns it.
func buildLog(t testing.TB, dir string, n int) *translog.Log {
	t.Helper()
	l, err := translog.OpenLog(dir+"/e7-log.jsonl", "eval-log")
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	for i := 0; i < n; i++ {
		e := translog.LogEntry{
			Type:      translog.EventAdmit,
			Digest:    synth.SyntheticDigests(1, uint64(e7Seed+i))[0],
			Timestamp: "2026-06-24T12:00:00Z",
			Subject:   "eval-subject",
		}
		if _, err := l.Append(e); err != nil {
			t.Fatalf("append[%d]: %v", i, err)
		}
	}
	return l
}

// BenchmarkE7VerifyInclusion measures offline inclusion-proof verification at a
// representative tree size (65536). Run: go test -run x -bench E7 -cpu 1.
func BenchmarkE7VerifyInclusion(b *testing.B) {
	dir := b.TempDir()
	const n = 65536
	l := buildLog(b, dir, n)
	_, logPriv := synth.LogKeypair(e7Seed)
	sth, err := l.SignHead(logPriv, time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC))
	if err != nil {
		b.Fatalf("sign head: %v", err)
	}
	root, err := sth.RootBytes()
	if err != nil {
		b.Fatalf("root bytes: %v", err)
	}
	// Pick a fixed middle index; build its proof + leaf once.
	idx := n / 2
	proof, size, leaf, err := l.ProveInclusion(idx)
	if err != nil {
		b.Fatalf("prove inclusion: %v", err)
	}
	if err := translog.VerifyInclusion(leaf, idx, size, proof, root); err != nil {
		b.Fatalf("warm-up verify: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := translog.VerifyInclusion(leaf, idx, size, proof, root); err != nil {
			b.Fatalf("verify: %v", err)
		}
	}
}

// TestE7InclusionProof measures time/event for offline inclusion-proof
// verification across e7Sizes, recording the curve. Each size is measured by
// verifying a fixed set of sampled indices many times and taking the median.
func TestE7InclusionProof(t *testing.T) {
	requireEval(t)
	_, logPriv := synth.LogKeypair(e7Seed)

	for _, n := range e7Sizes {
		dir := t.TempDir()
		l := buildLog(t, dir, n)
		sth, err := l.SignHead(logPriv, time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC))
		if err != nil {
			t.Fatalf("sign head n=%d: %v", n, err)
		}
		root, err := sth.RootBytes()
		if err != nil {
			t.Fatalf("root bytes n=%d: %v", n, err)
		}

		// Sample 64 indices spread across the tree; pre-build their proofs so
		// the timed loop measures ONLY verification (the relying-party cost).
		const samples = 64
		type pv struct {
			idx   int
			size  int
			leaf  [translog.HashSize]byte
			proof [][translog.HashSize]byte
		}
		pvs := make([]pv, 0, samples)
		for s := 0; s < samples; s++ {
			idx := (s * n) / samples
			proof, size, leaf, err := l.ProveInclusion(idx)
			if err != nil {
				t.Fatalf("prove n=%d idx=%d: %v", n, idx, err)
			}
			pvs = append(pvs, pv{idx: idx, size: size, leaf: leaf, proof: proof})
		}

		const reps = 2000
		durs := make([]time.Duration, 0, samples*reps)
		for r := 0; r < reps; r++ {
			for _, p := range pvs {
				start := time.Now()
				if err := translog.VerifyInclusion(p.leaf, p.idx, p.size, p.proof, root); err != nil {
					t.Fatalf("verify n=%d idx=%d: %v", n, p.idx, err)
				}
				durs = append(durs, time.Since(start))
			}
		}
		med, p99 := medianP99(durs)
		usMed := float64(med.Nanoseconds()) / 1e3
		usP99 := float64(p99.Nanoseconds()) / 1e3
		t.Logf("E7 n=%d inclusion-proof verify: median=%.3fµs p99=%.3fµs (proof_len=%d)", n, usMed, usP99, len(pvs[0].proof))
		record(t, "E7", "inclusion-proof", "median_us", round4(usMed),
			"offline VerifyInclusion against witnessed STH, tree_size=%d, proof_len=%d", n, len(pvs[0].proof))
		record(t, "E7", "inclusion-proof", "p99_us", round4(usP99),
			"offline VerifyInclusion against witnessed STH, tree_size=%d", n)
	}
}
