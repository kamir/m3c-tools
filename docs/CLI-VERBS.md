# skillctl CLI verb register

This file is the allocation table for the top-level `skillctl` verbs, analogous
to the SPEC slot table that FR-0104 introduced for SPEC numbers. Its purpose is
to turn verb allocation from a **read** into a **write**: before FR-0113 the only
way to find out whether a verb name was taken was to read `cmd/skillctl/main.go`
and see what looked free, so two people reading at different times got the same
answer and two collisions landed in two days (`audit` vs `auditlog`, and
`capability` vs the SPEC-0401 reference bindings). Recording the allocation here
makes the second reader see that the name is already spoken for.

Source: SPEC-0404 §7-K3 (REQ-7.8 .. REQ-7.10), decided 2026-09-04.

## Columns

- **Verb** the canonical dispatched verb. Aliases that route to the same handler
  are listed in parentheses after it, e.g. `version` (`--version`, `-v`).
- **Owning SPEC** the specification (and section, where the code names one) that
  owns the verb's semantics. `built-in` marks a verb with no owning SPEC (usage
  and version printing). A trailing `(?)` marks a value the code does not pin
  precisely; it is a best-supported guess, not an invented fact.
- **Exit-Code space** the set of process exit codes the verb's handler can
  produce. This column is **mandatory** (REQ-7.9): both known collisions turned
  on it. `skillctl audit` owns `0/2/3` (SPEC-0189 §14 posture verdicts), so a
  script that branches on exit `2` must never be handed a `2` that means
  something else. The trust chain owns `0` plus `10..17` (SPEC-0188 §11). A
  register that carried only names would have caught the ambiguity at
  `audit status` but not the real risk, that a script branching on `2` today
  gets a wrong answer tomorrow.

Notation: `0/1/2` is the shared base space (`exitOK`=0, `exitGeneric`=1,
`exitUsage`=2 from `cmd/skillctl/signing_cmds.go`). `10..17` is an inclusive
numeric range from the `pkg/skillctl/exitcode` registry. A code shown as
`(NN in refusal_code)` rides the signed decision JSON while the PROCESS still
exits `2` to block the PreToolUse call (verify-hook / enforce / guard-path
convention); it is not a distinct process exit.

## How to add a verb

1. **Register first.** Add a row to the main table below with the canonical
   name, its owning SPEC, and its exit-code space. Pick a name not already in
   this table. If the verb is agreed but not yet implemented, add it to the
   **Reserved** section instead.
2. **Then implement.** Add the `case "<verb>":` to the top-level dispatch switch
   in `cmd/skillctl/main.go` and the handler.

A dispatched verb with **no** register row turns CI **red** (REQ-7.10): this is
enforcement, not convention. The checker is `cmd/verbaudit`; it AST-parses the
`switch os.Args[1]` dispatch, parses this file, and fails on any dispatched verb
that is not registered, plus any main-table row with an empty Exit-Code cell. It
is wired blocking into `scripts/check-docs.sh` and the `docs-gate` CI job, the
same way `cmd/docaudit` gates the flag surface.

## Verb register

| Verb | Owning SPEC | Exit-Code space |
| --- | --- | --- |
| `login` | FR-0043 | 0/1/2 |
| `version` (`--version`, `-v`) | built-in | 0 |
| `doctor` | SPEC-0406 D1 | 0/1/2 |
| `pack` | SPEC-0188 (Phase 1 PoC) | 0/1/2, 18 |
| `keygen` | SPEC-0188 §11 | 0/1/2 |
| `sign` | SPEC-0188 §11 | 0/1/2 |
| `verify-sig` | SPEC-0188 §11 | 0/1/2, 10, 11 |
| `trust` | SPEC-0188 (S7) | 0/1/2 |
| `peer` | SPEC-0359 (D2) | 0/1/2 |
| `cross-sign` | SPEC-0359 (D3) | 0/1/2 |
| `attest` | SPEC-0188 (S9) | 0/1/2 |
| `revoke` | SPEC-0188 §4.5 | 0/1/2 |
| `audit` | SPEC-0189 §14 | 0/2/3 |
| `propose` | SPEC-0194 | 0/1/2 |
| `install` | SPEC-0188 §11 (S8) | 0/1/2, 10..16 |
| `verify` | SPEC-0188 §11 (S8) | 0/1/2, 10..17 |
| `export-verification-kit` | SPEC-0276 R4.3 | 0/1/2, 10..19 |
| `compliance` | SPEC-0276 R5 | 0/1/2 |
| `verify-hook` | SPEC-0247 P0.1 | 0/2 (25/26/28 in refusal_code) |
| `enforce` | SPEC-0317 P0 | 0/2 (26 in refusal_code) |
| `guard-path` | SPEC-0317 R-6 | 0/2 (27 in refusal_code) |
| `agentid` | SPEC-0277 P0+P1 | 0/1/2, 11/12/17/20/21 |
| `gate-stats` | SPEC-0255 | 0/1/2 |
| `auditlog` | SPEC-0403 §8 | 0/1 |
| `pin` | SPEC-0247 §7.3 | 0/1/2 |
| `session-baseline` | SPEC-0317 R-7 | 0/1/2 |
| `scan` | SPEC-0189 (S0a) | 0/1 |
| `report` | SPEC-0189 (S0a) | 0/1 |
| `diff` | SPEC-0189 (S0a) | 0/1 |
| `seal` | SPEC-0189 (S0a) | 0/1 |
| `import` | SPEC-0189 (S0a) | 0/1 |
| `menubar` | SPEC-0189 (S0a) | 0/1 |
| `review` | SPEC-0189 (S0a) (?) | 0/1 |
| `browse` | SPEC-0189 (S0a) (?) | 0/1 |
| `consolidate` | SPEC-0189 (S0a) (?) | 0/1 |
| `sync-usage` | SPEC-0189 (S0a) | 0/1 |
| `sync` | SPEC-0317 R-5 | 0/1/2, 29 |
| `awareness` | SPEC-0195 (S2 M1) | 0/1/2, 18/19 |
| `intent` | SPEC-0195 (S2 M2) | 0/1/2, 18/19 |
| `translog` | SPEC-0278 P5 | 0/1/2 |
| `project` | SPEC-0214 | 0/1/2 |
| `session` | SPEC-0213 | 0/1/2 |
| `publish` | SPEC-0225 P1 | 0/1/2 |
| `pull` | SPEC-0225 P2 | 0/1/2 |
| `registry` | SPEC-0225 P2 | 0/1/2 |
| `runbook` | SPEC-0272 | 0/1/2 |
| `room` | SPEC-0246 §7 | 0/1/2 |
| `help` (`--help`, `-h`) | built-in | 0 |

Notes on sourcing:

- `review`, `browse`, `consolidate` predate SPEC-0189 and were baselined into
  its S0a scanner family when the branch merged (`cmd/skillctl/scanner_cmds.go`
  header: "pre-SPEC-0189 behaviour preserved"), so their owning SPEC is marked
  `(?)`: S0a is where they are dispatched and documented, not necessarily where
  they were born.
- `revoke` (the author-side verb) exits `0/1/2`. The verifier's
  `identity_revoked` exit `17` (`pkg/skillctl/exitcode` Tier 4) is surfaced by
  `verify` / `install`, not by `revoke` itself.
- `import` here is the SPEC-0189 S0a scanner import, exit `0/1`. It is distinct
  from the `import-public` surface (exit `4/5/17/18/19`), which is not a
  top-level verb in the current dispatch.

## Reserved (registered before implemented)

These names are allocated but not yet dispatched in `main.go`. The checker does
NOT fail on a reserved entry that has no dispatch (that is the whole point of
reserving). Move a row up to the main table when the `case` lands.

| Verb | Owning SPEC | Exit-Code space |
| --- | --- | --- |
| `capability` | SPEC-0378 | 0/1 |

`capability` is the second known collision. SPEC-0378 owns capability binding
(normative P0); SPEC-0401 §3 describes reference bindings under the same word.
Reserving the stem here settles the ownership before either lands a `case`.
