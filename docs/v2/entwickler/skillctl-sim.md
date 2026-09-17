# Runbook: skillctl-sim, the trust-plane simulation

How to run `cmd/skillctl-sim` and, more importantly, how to read what it
prints. Everything below was read from `cmd/skillctl-sim/main.go`,
`pkg/skillctl/sim/` and the `Makefile` (`sim`, `sim-deep`, `sim-theory`) on
2026-09-16.

Audience: a developer who changed anything on the trust plane and wants the
theory-against-measurement verdict, or who sees `make sim` red and has to
decide what that means. The one-line index entry is in the
[Program-Index](../../program-index.md).

Rolle: Entwickler · Sprache: EN · Stand: 2026-09-16

## What it is, in one sentence

A generated corpus of multi-principal scenarios, each carrying a SPEC-derived
prediction, executed against the **real** `skillctl` binary and a real git
registry, hermetically (a throwaway HOME per scenario); the run compares the
predicted outcome histogram with the measured one, bin by bin.

## The four subcommands

Dispatch read from `main()` in `cmd/skillctl-sim/main.go`:

| Subcommand | What it does | Exit |
|---|---|---|
| `theory` | Checks the SPECIFICATION alone, no binary, no registry, no network; reasons over the state space. | `0` sound · `1` the model failed its own check · `2` usage |
| `list` | Prints the generated corpus and what each scenario predicts, `[OUT OF MODEL]` marks the unclaimed steps. | `0` · `2` usage |
| `run` | Executes the corpus against the binary under test and compares theory with reality. | `0` pass · `1` fail · `2` usage |
| `freeze` | Prints the freeze manifest for a planned measurement (`-t`, `-plan`, `-scope`). | `0` · `1` error · `2` usage |

Flags for `run`: `-t` (covering-array strength: `2` = the gate, `3` = the
weekly run, `0` = no design, then `-n` counts), `-n`, `-skillctl <path>`
(default `./build/skillctl`, then PATH), `-jobs`, `-md <file>` (also write the
report as Markdown).

## Run it

```bash
make sim          # strength 2: the blocking gate, about four seconds
make sim-deep     # strength 3: where three-way interactions show up; weekly
make sim-theory   # the specification alone, no binary in the loop
```

The corpus at strength 2 is a COVERING ARRAY, not a sample: every admissible
pair of factor levels appears in at least one scenario, so breadth is an
arithmetic property rather than a judgement call (Makefile, `sim` comment).

## How to read a run

The pass condition, quoted from the exit logic in `runRun`
(`cmd/skillctl-sim/main.go`):

1. **Harness failures outrank everything.** One harness failure means the
   corpus did not run, the run "measured nothing and is not a result", exit
   `1` regardless of the conflict count. This exists because a run in which
   nothing executed once exited `0`.
2. **No unwaived conflict.** A waived conflict is counted and printed with
   its finding; it is not removed from the comparison.
3. **No invariant violation.**
4. **Residual zero.** The residual is the total disagreement between the
   closed-form prediction and the measured histogram. It is part of the pass
   condition: the earlier exemption ("out-of-model attacks make some residual
   permanent") is superseded, because the analytic model now predicts those
   outcomes (a withheld revoke, a stolen key) instead of being surprised by
   them; the reasoning is recorded at the `sim` target in the Makefile.

Every report carries provenance: the harness commit, the model hash, the
binary hash and the binary's own `--version` answer. When that answer is
`dev`, that is itself a finding: the measured artifact is not a released one
(`sutVersion`, `cmd/skillctl-sim/main.go`).

## Two traps, both measured

- **The binary path is made absolute before the workers start.** Every
  scenario runs in its own working directory, so a relative `-skillctl` path
  once made every exec fail while the run still ended `0`; `resolveBinary`
  now resolves and stat-checks the path up front and fails once, with the
  path in hand.
- **`run` needs a binary, `theory` does not.** A missing binary is a refusal
  before the first scenario ("no skillctl found; build one with
  `make build-skillctl` or pass `-skillctl <path>`"), not a sea of
  per-scenario errors.
