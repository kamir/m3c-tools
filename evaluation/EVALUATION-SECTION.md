# Evaluation (SPEC-0280 §4, filled)

This is the paper-ready Evaluation section: the SPEC-0280 §4 template with the
**real measured numbers** from this machine slotted in. The numbers are produced
by the committed harness (`evaluation/`, run `RUN_EVAL=1 go test ./evaluation/...`)
and are reproduced verbatim from `evaluation/results/RESULTS.csv` /
`RESULTS.md`. Every metric exercises a **shipped** package; the population is
**synthetic** except **E4**, which uses the **real committed corpus**.

**Hardware / build.** Apple M3 Max, 16 logical cores, darwin/arm64, Go 1.26.4.
Single-core figures (E1) are measured single-goroutine; the wall-clock figures
are medians (and p99) over the sample sizes noted per metric.

---

## Evaluation (paper text)

> **Evaluation.** We evaluate the shipped trust layer on a **synthetic** scale
> population (deterministically minted signed bundles, identities, revocation
> lists, and transparency-log heads) plus the **real** committed behaviour-scan
> corpus (40 adversarial + 32 benign `SKILL.md` bodies), on an Apple M3 Max
> (16 cores, darwin/arm64, Go 1.26.4).
>
> **Verification** (E1) of a signed bundle in fully-offline pinned-author mode
> costs a median of **0.117 ms** (p99 **0.294 ms**) warm and **0.259 ms**
> (p99 **0.495 ms**) cold over **N = 10⁴** bundles on a single core. Kit
> verification on an air-gapped host (E2) completes in **8.76 ms** wall-clock
> with **zero** outbound network calls (every proxy environment variable is
> routed at a localhost sentinel that counts any connection attempt; the count is
> 0). **Revocation** verification (E3) scales from **0.044 ms** at 10 entries to
> **1.58 s** at 10⁶ entries — dominated by canonical sort, with a single
> constant-time signature check — and the freshness model (E10) passes **all
> 7/7** rollback / stale / split-view / consistency / future-dated cases.
> **Behaviour scanning** (E4) achieves **100.0 %** true-positive at **0.0 %**
> false-positive on the SPEC-0246 corpus (thresholds TP ≥ 95 %, FP ≤ 5 %).
> **Agent authorization** (E5) adds **0.000023 ms** per invocation for the
> cached-mandate gate and **0.037 ms** per invocation when the signed mandate is
> re-verified on every call. **OIDC offline** verification (E6) is **N/A —
> deferred (gated P3-P2)**: the OIDC/JWKS owner/sign-off binding (SPEC-0277 P2)
> is not built, so there is no path to measure and we report no number rather
> than fabricate one. **Transparency-log** inclusion proofs (E7) verify in
> **0.38–1.25 µs** per event across tree sizes 16 → 65 536 (proof length
> 4 → 16). The stack scales flat to **10³ pinned authors/roots** (E8): verify
> stays at **≈ 0.12–0.14 ms** as the pinned set grows three orders of magnitude,
> because the cost floor is the fixed-size crypto, not the author lookup. The
> verification kit (E9) is **3123 bytes** (5 files) and is **byte-reproducible**
> (two exports from the same signed inputs are file-by-file identical). All
> artifacts and the harness are released for reproducibility (Appendix /
> `evaluation/`).
>
> *Threats to validity.* Our scale population is **synthetic**: it is minted by
> the same signing primitives the product ships (so the cryptography and the
> verification path are real), but the *distribution* of skills, authors, and
> revocations is generated, not drawn from a deployed cohort — absolute latencies
> would shift with real bundle sizes and registry policy, though the asymptotic
> shapes (E3 sort-bound, E7 O(log N), E8 crypto-floor) are structural and
> distribution-independent. Results are **single-platform** (one Apple M3 Max);
> they fix relative costs but not portability — the air-gap proof (E2) and the
> reproducibility result (E9) are platform-independent properties, while the
> latency numbers (E1/E3/E7/E8) are machine-specific and the harness records the
> hardware so a re-run elsewhere is directly comparable. The behaviour-scan
> result (E4) is bounded by **corpus representativeness**: 40 adversarial + 32
> benign hand-curated samples exercise the SPEC-0246 rule families but cannot
> stand in for the full adversarial space; the 100 %/0 % figure is the score on
> *this* corpus and should be read as "meets the committed acceptance bar," not
> as a guarantee against unseen attacks. Finally, **E6 is honestly deferred**
> rather than estimated: when the SPEC-0277 P2 OIDC/JWKS binding ships, the
> harness slot (`e6_oidc_deferred_test.go`) is where the real number lands.

---

## The matrix (E1–E10), with the real numbers

| #   | Metric                                  | Result (this machine)                                              | Population | Threshold / note |
|-----|-----------------------------------------|-------------------------------------------------------------------|------------|------------------|
| E1  | Offline `verify` latency                | warm median **0.117 ms** / p99 **0.294 ms**; cold median **0.259 ms** / p99 **0.495 ms** (N=10⁴, 1 core) | synthetic | — |
| E2  | Kit verify on air-gapped host           | **8.76 ms** wall-clock; **0** net calls                            | synthetic  | net calls must be 0 ✓ |
| E3  | Revocation-list verify vs size          | **0.044 ms** (10) → **0.086 ms** (10²) → **0.80 ms** (10³) → **10.0 ms** (10⁴) → **111.7 ms** (10⁵) → **1583 ms** (10⁶) | synthetic | sort-bound curve |
| E4  | Behaviour-scan TP/FP (**real corpus**)  | **100.0 %** TP (40/40), **0.0 %** FP (0/32)                        | **real**   | TP ≥ 95 % ✓, FP ≤ 5 % ✓ |
| E5  | Agent-grant authorization overhead      | cached **+0.000023 ms**/invocation; full re-verify **+0.037 ms**/invocation | synthetic | delta over no-gate baseline |
| E6  | OIDC/JWKS offline verify                | **N/A — deferred (gated P3-P2)**                                   | n/a        | not built; not faked |
| E7  | Transparency-log inclusion-proof verify | **0.375 µs** (16) → **0.75 µs** (256) → **1.08 µs** (4096) → **1.25 µs** (65536) | synthetic | O(log N), proof_len 4→16 |
| E8  | Trust-root scale (pinned authors)       | **0.125 ms** (1) → **0.120 ms** (10) → **0.125 ms** (100) → **0.145 ms** (10³) | synthetic | flat — crypto-floor dominated |
| E9  | Kit size + reproducibility              | **3123 bytes**; byte-identical **yes**                            | synthetic  | reproducible ✓ |
| E10 | Revocation freshness correctness        | **7/7** cases pass (rollback, stale-high, stale-low-open, fresh, future-dated, split-view, consistency) | synthetic | pass/fail matrix ✓ |

### How each number was obtained (driver → measured quantity)

- **E1** `evaluation/e1_verify_latency_test.go` → `verify.Verify` over a minted
  10⁴-bundle population, pinned-author offline mode, cold (distinct-bundle sweep)
  and warm (hot single bundle).
- **E2** `evaluation/e2_e9_kit_test.go` (`TestE2KitAirGap`) → real
  `skillctl export-verification-kit` then `skillctl verify`, all proxy env routed
  at a localhost sentinel; net-call count asserted 0.
- **E3** `evaluation/e3_revocation_scale_test.go` → `verify.VerifyRevocationList`
  over signed lists of 10 … 10⁶ digests.
- **E4** `evaluation/e4_bodyscan_corpus_test.go` → `bodyscan.Scan` over the
  committed `pkg/skillctl/bodyscan/testdata/corpus` (real data), TP/FP at the
  SPEC-0246 §4.6 correctness bar.
- **E5** `evaluation/e5_agent_authz_test.go` → `agentid.Verify` +
  `Grant.AuthorizeSkill` delta over a no-gate baseline.
- **E6** `evaluation/e6_oidc_deferred_test.go` → records the honest N/A marker.
- **E7** `evaluation/e7_inclusion_proof_test.go` → `translog.VerifyInclusion`
  against a witnessed STH across tree sizes 16 → 65 536.
- **E8** `evaluation/e8_trustroot_scale_test.go` → `verify.Verify` with 1 … 10³
  pinned authors, target author last (worst-case lookup).
- **E9** `evaluation/e2_e9_kit_test.go` (`TestE9KitSizeReproducibility`) → kit
  byte size + two-export byte-identity check.
- **E10** `evaluation/e10_freshness_test.go` → the shipped `EvaluateFreshness` /
  `VerifyRevocationList` / `VerifyConsistency` / `DetectSplitView` across the
  adversarial matrix.

### Reproduce

```bash
RUN_EVAL=1 go test ./evaluation/ -run 'TestE|TestZZZ' -v -timeout 30m
EVAL_CPU="Apple M3 Max" go run ./evaluation/cmd/results-md evaluation/results
```

Seeds are fixed (`e1Seed … e10Seed` in each driver); the synthesizer derives all
keys deterministically, so the population — and therefore the numbers' shape — is
reproducible on any host (absolute latencies are hardware-specific and recorded).
