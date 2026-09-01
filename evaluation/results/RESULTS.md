# SPEC-0280 Evaluation Results (E1–E10)

> Generated from `RESULTS.csv` by `evaluation/cmd/results-md`. Do not hand-edit;
> re-run the harness (`RUN_EVAL=1 go test ./evaluation/...`) then regenerate.

## Run environment

- CPU: Apple M3 Max
- OS/arch: darwin/arm64
- Logical CPUs: 16
- Go: go1.26.4
- Population: **synthetic** for all metrics except **E4** (the real committed SPEC-0246 corpus).

## Results

| Metric | Driver | Measured | Value | Population | Note |
|--------|--------|----------|-------|------------|------|
| E1 | verify-latency-cold | median_ms | 0.2592 | synthetic | N=10000 single-core offline pinned-author verify, first-touch sweep |
| E1 | verify-latency-cold | p99_ms | 0.4950 | synthetic | N=10000 single-core offline pinned-author verify, first-touch sweep |
| E1 | verify-latency-warm | median_ms | 0.1170 | synthetic | N=10000 single-core offline pinned-author verify, hot cache |
| E1 | verify-latency-warm | p99_ms | 0.2942 | synthetic | N=10000 single-core offline pinned-author verify, hot cache |
| E10 | freshness-consistency | verdict | PASS | synthetic | SPEC-0279/0278 adversarial case driven through the shipped logic |
| E10 | freshness-fresh | verdict | PASS | synthetic | SPEC-0279/0278 adversarial case driven through the shipped logic |
| E10 | freshness-future-dated | verdict | PASS | synthetic | SPEC-0279/0278 adversarial case driven through the shipped logic |
| E10 | freshness-matrix | pass_rate | 100 | synthetic | 7/7 adversarial cases produced the safe verdict (rollback/stale/split-view/consistency) |
| E10 | freshness-rollback | verdict | PASS | synthetic | SPEC-0279/0278 adversarial case driven through the shipped logic |
| E10 | freshness-split-view | verdict | PASS | synthetic | SPEC-0279/0278 adversarial case driven through the shipped logic |
| E10 | freshness-stale-high-risk | verdict | PASS | synthetic | SPEC-0279/0278 adversarial case driven through the shipped logic |
| E10 | freshness-stale-low-fail-open | verdict | PASS | synthetic | SPEC-0279/0278 adversarial case driven through the shipped logic |
| E2 | kit-air-gap | net_calls | 0 | synthetic | outbound HTTP(S) attempts counted by the localhost sentinel; MUST be 0 |
| E2 | kit-air-gap | wall_clock_ms | 8.7632 | synthetic | `skillctl verify` over an exported kit, all proxy env routed at a sentinel |
| E3 | revocation-verify | median_ms | 0.0440 | synthetic | offline VerifyRevocationList (canon+sort+1 ed25519 verify), list_size=10, reps=2000 |
| E3 | revocation-verify | median_ms | 0.0864 | synthetic | offline VerifyRevocationList (canon+sort+1 ed25519 verify), list_size=100, reps=2000 |
| E3 | revocation-verify | median_ms | 0.8027 | synthetic | offline VerifyRevocationList (canon+sort+1 ed25519 verify), list_size=1000, reps=2000 |
| E3 | revocation-verify | median_ms | 10.0462 | synthetic | offline VerifyRevocationList (canon+sort+1 ed25519 verify), list_size=10000, reps=200 |
| E3 | revocation-verify | median_ms | 111.6693 | synthetic | offline VerifyRevocationList (canon+sort+1 ed25519 verify), list_size=100000, reps=200 |
| E3 | revocation-verify | median_ms | 1583.4911 | synthetic | offline VerifyRevocationList (canon+sort+1 ed25519 verify), list_size=1000000, reps=20 |
| E4 | bodyscan-corpus | false_positive_pct | 0.0000 | real | shipped bodyscan.Scan over the committed SPEC-0246 corpus, 32 benign samples, threshold<=5% |
| E4 | bodyscan-corpus | true_positive_pct | 100.0000 | real | shipped bodyscan.Scan over the committed SPEC-0246 corpus, 40 adversarial samples, threshold>=95% |
| E5 | authorize-only | added_ms_per_invocation | 0.000023 | synthetic | cached-mandate gate (Grant.AuthorizeSkill), 200000 iters, delta over no-gate baseline |
| E5 | full-gate | added_ms_per_invocation | 0.036675 | synthetic | re-verify-each-call gate (agentid.Verify + AuthorizeSkill), 200000 iters, delta over no-gate baseline |
| E6 | oidc-jwks-offline | status | N/A — deferred (gated P3-P2) | n/a | the OIDC/Keycloak owner/sign-off binding is SPEC-0277 P2, not built; no JWKS verify path exists to measure (no number fabricated) |
| E7 | inclusion-proof | median_us | 0.3750 | synthetic | offline VerifyInclusion against witnessed STH, tree_size=16, proof_len=4 |
| E7 | inclusion-proof | median_us | 0.7500 | synthetic | offline VerifyInclusion against witnessed STH, tree_size=256, proof_len=8 |
| E7 | inclusion-proof | median_us | 1.0830 | synthetic | offline VerifyInclusion against witnessed STH, tree_size=4096, proof_len=12 |
| E7 | inclusion-proof | median_us | 1.2500 | synthetic | offline VerifyInclusion against witnessed STH, tree_size=65536, proof_len=16 |
| E7 | inclusion-proof | p99_us | 0.5420 | synthetic | offline VerifyInclusion against witnessed STH, tree_size=16 |
| E7 | inclusion-proof | p99_us | 1.2500 | synthetic | offline VerifyInclusion against witnessed STH, tree_size=256 |
| E7 | inclusion-proof | p99_us | 1.6250 | synthetic | offline VerifyInclusion against witnessed STH, tree_size=4096 |
| E7 | inclusion-proof | p99_us | 2.0000 | synthetic | offline VerifyInclusion against witnessed STH, tree_size=65536 |
| E8 | trustroot-scale | median_ms | 0.1252 | synthetic | offline verify with 1 pinned authors (target author last → worst-case lookup), reps=3000 |
| E8 | trustroot-scale | median_ms | 0.1201 | synthetic | offline verify with 10 pinned authors (target author last → worst-case lookup), reps=3000 |
| E8 | trustroot-scale | median_ms | 0.1253 | synthetic | offline verify with 100 pinned authors (target author last → worst-case lookup), reps=3000 |
| E8 | trustroot-scale | median_ms | 0.1448 | synthetic | offline verify with 1000 pinned authors (target author last → worst-case lookup), reps=3000 |
| E9 | kit-reproducibility | byte_identical | yes | synthetic | two exports from the same deterministic signed fixture compared file-by-file |
| E9 | kit-size | bytes | 3123 | synthetic | exported verification-kit total size (5 files) |

E6 is recorded as `N/A — deferred (gated P3-P2)`: the OIDC/JWKS binding (SPEC-0277 P2) is not built, so there is no path to measure — no number is fabricated.
