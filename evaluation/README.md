# SPEC-0280 — Trust-Layer Evaluation Harness (E1–E10)

A reproducible, committed harness that measures the **shipped** m3c-tools trust
layer (`pkg/skillctl/{verify,signing,translog,agentid,bodyscan,datascope}` + the
`export-verification-kit` CLI). Each metric is a Go driver that exercises a real
shipped package over a **deterministic** population and emits a **real number**
into `results/RESULTS.csv` + `results/RESULTS.md`.

**Honesty contract (the project standard):** no claim without a number; every row
is labelled `synthetic` (generated population) or `real` (the committed corpus);
**E6 is `N/A — deferred`**, never fabricated.

## What is measured

| #   | Metric                                   | Driver file                        | Reports |
|-----|------------------------------------------|------------------------------------|---------|
| E1  | Offline `verify` latency                 | `e1_verify_latency_test.go`        | median, p99 (ms), cold + warm |
| E2  | Kit verify on an air-gapped host         | `e2_e9_kit_test.go`                | wall-clock (ms); **0** net calls |
| E3  | Revocation-list verify vs size           | `e3_revocation_scale_test.go`      | time-vs-size curve (10 → 10⁶) |
| E4  | Behaviour-scan TP/FP (**real corpus**)   | `e4_bodyscan_corpus_test.go`       | TP%, FP% |
| E5  | Agent-grant authorization overhead       | `e5_agent_authz_test.go`           | added ms/invocation |
| E6  | OIDC/JWKS offline verify                  | `e6_oidc_deferred_test.go`         | **N/A — deferred (gated P3-P2)** |
| E7  | Transparency-log inclusion-proof verify  | `e7_inclusion_proof_test.go`       | time/event (µs) curve |
| E8  | Trust-root scale (N pinned authors)      | `e8_trustroot_scale_test.go`       | time-vs-N curve (1 → 10³) |
| E9  | Kit size + reproducibility               | `e2_e9_kit_test.go`                | bytes; byte-identical? |
| E10 | Revocation freshness correctness         | `e10_freshness_test.go`            | pass/fail matrix |

Shared pieces:

- `internal/synth/synth.go` — deterministic issuer (the white-paper
  `mint-evidence.go` pattern, made reproducible via seeded ed25519 keys). Mints N
  signed `.skb` bundles + `BundleMeta` + a pinned `TrustRoot` that verifies fully
  offline.
- `harness_test.go` — the result sink → `results/RESULTS.csv`.
- `scripts/mint_kit_fixture.go` — `go:build ignore` issuer used by E2/E9 to feed
  the real `skillctl export-verification-kit` a deterministic fixture.

## Running

```bash
# Fast correctness pass (no RUN_EVAL): E4 (real corpus) + E10 (safety matrix).
# These run in plain CI and fail the build on a regression.
go test ./evaluation/

# Full measured harness — produces results/RESULTS.csv (overwrite is gated on
# RUN_EVAL so a plain `go test ./...` never clobbers committed numbers).
RUN_EVAL=1 go test ./evaluation/ -run 'TestE|TestZZZ' -v -timeout 30m

# Then regenerate the Markdown table from the CSV:
go run ./evaluation/cmd/results-md
```

### Determinism / seeds

Every driver uses a fixed seed (constants `e1Seed … e10Seed`). The synthesizer
derives all keys from the seed via a counter-mode SHA-256 KDF, so the same seed
yields a **byte-identical** population (and identical digests) on every run and
host. Seeds are listed at the top of each driver file.

> The workflow-script `Date.now()` ban does **not** apply to Go: the drivers use
> `time.Now()` only to *measure* elapsed wall-clock (never to seed data), and
> `testing.B` for the benchmark forms.

### Benchmark forms (cross-check)

Several metrics also ship a `testing.B` benchmark for an independent `ns/op`
reading on a single core:

```bash
go test ./evaluation/ -run x -bench 'E1|E5|E7' -benchmem -cpu 1
```

## Methodology notes

- **E1 cold vs warm.** *Cold* sweeps distinct bundles so each `verify` recomputes
  a SHA-256 over bytes not touched by the previous call; *warm* re-verifies one
  hot bundle to isolate the crypto + chain-walk. Single core: pass `-cpu 1` to the
  benchmark forms; the latency test is single-goroutine by construction.
- **E2 air-gap proof.** A localhost **sentinel** TCP listener counts any inbound
  connection; every proxy env var (`HTTP(S)_PROXY`, `ALL_PROXY`, lowercase) is
  routed at it. Because the kit-verify path is pinned-mode (it reads no
  registry/ER1 endpoint), any HTTP egress would land on the sentinel and be
  counted. The assertion is `net_calls == 0`. For an even stronger, syscall-level
  guarantee, run the verify under a tracer:
  - Linux: `strace -f -e trace=network skillctl verify --bundle … --trust-roots …`
  - macOS: `sudo dtruss -t connect skillctl verify …`
  (both should show zero `connect()` to a non-loopback address).
- **E4 uses the REAL committed corpus** at
  `../pkg/skillctl/bodyscan/testdata/corpus` (40 adversarial + 32 benign). TP/FP
  use the same correctness bar as the shipped SPEC-0246 §4.6 gate, so E4 is an
  honest re-measurement of the production acceptance criterion.
- **E5** reports *two* honest figures: the cached-mandate gate (`AuthorizeSkill`
  only) and the re-verify-each-call gate (`agentid.Verify` + `AuthorizeSkill`),
  each as a delta over a no-gate baseline.
- **E9** exports the kit twice from the same deterministic fixture and compares
  file-by-file; "reproducible" = every file byte-identical.
- **E10** is correctness, not latency: each adversarial case
  (rollback / stale-high / stale-low-open / fresh / future-dated / split-view /
  consistency) drives the shipped `EvaluateFreshness` / `VerifyRevocationList` /
  `VerifyConsistency` / `DetectSplitView` and asserts the **safe** verdict.

## Threats to validity

Recorded in `EVALUATION-SECTION.md`: the population is **synthetic** (except E4,
which is the real corpus); results are **single-platform** (the hardware recorded
in `RESULTS.md`); corpus **representativeness** bounds E4. E6 is honestly deferred.

## Constraint

The harness is **additive**: it lives entirely under `evaluation/` and modifies
**no** shipped package. It calls only the existing exported API surface.
