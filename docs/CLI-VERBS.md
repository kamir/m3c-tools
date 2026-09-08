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
  gets a wrong answer tomorrow. Since AUDIT-0001 the cell is also **checked**:
  `cmd/exitaudit` compares it against the same verb's `Exit:` statement in
  [the manual](manual-skillctl.md#exit-codes) and against
  `pkg/skillctl/exitcode`, so the two documents can no longer disagree in
  silence (twelve of fourteen verbs did).

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
3. **Then state the exit space in both places.** The cell here and the `Exit:`
   line in the manual's command section must name the same numbers, and any
   number outside `0/1/2` must be a registered code in `pkg/skillctl/exitcode`
   (or a documented exception in the manual's "Codes outside the register"
   table). `go run ./cmd/exitaudit` says which of those is missing.

A dispatched verb with **no** register row turns CI **red** (REQ-7.10): this is
enforcement, not convention. The checker is `cmd/verbaudit`; it AST-parses the
`switch os.Args[1]` dispatch, parses this file, and fails on any dispatched verb
that is not registered, plus any main-table row with an empty Exit-Code cell. It
is wired blocking into `scripts/check-docs.sh` and the `docs-gate` CI job, the
same way `cmd/docaudit` gates the flag surface. Its sibling `cmd/exitaudit`
gates the CONTENT of the Exit-Code column against the register and the manual.

## Verb register

| Verb | Owning SPEC | Exit-Code space |
| --- | --- | --- |
| `login` | FR-0043 | 0/1/2 |
| `version` (`--version`, `-v`) | built-in | 0 |
| `doctor` | SPEC-0406 D1 | 0/1/2 |
| `token` (`set`, `list`, `rm`) | FR-0117 | 0/1/2 |
| `pack` | SPEC-0188 (Phase 1 PoC) | 0/1/2, 18 |
| `keygen` | SPEC-0188 §11 | 0/1/2 |
| `sign` | SPEC-0188 §11 | 0/1/2 |
| `verify-sig` | SPEC-0188 §11 | 0/1/2, 10, 11 |
| `trust` (`list`, `add`, `add-author`, `fingerprint`, `remove`) | SPEC-0188 (S7), `add-author`/`fingerprint` SPEC-0406 §3.2 | 0/1/2 |
| `peer` | SPEC-0359 (D2) | 0/1/2 |
| `cross-sign` | SPEC-0359 (D3) | 0/1/2 |
| `attest` | SPEC-0188 (S9) | 0/1/2 |
| `revoke` | SPEC-0188 §4.5 | 0/1/2, 15, 22 |
| `audit` | SPEC-0189 §14 | 0/1/2/3 |
| `propose` | SPEC-0194 | 0/1/2 |
| `install` | SPEC-0188 §11 (S8) | 0/1/2, 10..17, 20, 22 |
| `verify` | SPEC-0188 §11 (S8) | 0/1/2, 10..17, 20, 22 |
| `export-bundle` | SPEC-0406 Phase 2 | 0/1/2, 10..17, 20 |
| `export-verification-kit` | SPEC-0276 R4.3 | 0/1/2, 10..17, 20 |
| `compliance` | SPEC-0276 R5 | 0/1/2 |
| `verify-hook` | SPEC-0247 P0.1 | 0/2 (17/22/25/28 in refusal_code) |
| `enforce` | SPEC-0317 P0 | 0/2 (26 in refusal_code) |
| `guard-path` | SPEC-0317 R-6 | 0/2 (27 in refusal_code) |
| `agentid` | SPEC-0277 P0+P1 | 0/1/2, 11/12/17/20/21/22 |
| `gate-stats` | SPEC-0255 | 0/1/2 |
| `auditlog` | SPEC-0403 §8 | 0/1/2 |
| `pin` | SPEC-0247 §7.3 | 0/1/2, 3 |
| `session-baseline` | SPEC-0317 R-7 | 0/1 |
| `scan` | SPEC-0189 (S0a) | 0/1/2 |
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
| `awareness` | SPEC-0195 (S2 M1) | 0/1/2, 19 |
| `intent` | SPEC-0195 (S2 M2) | 0/1/2, 18 |
| `translog` | SPEC-0278 P5 | 0/1/2, 23/24/25 |
| `project` | SPEC-0214 | 0/1/2 |
| `session` | SPEC-0213 | 0/1/2 |
| `publish` | SPEC-0225 P1 | 0/1/2 |
| `pull` | SPEC-0225 P2 | 0/1/2, 6, 10..13 |
| `registry` | SPEC-0225 P2 | 0/1/2 |
| `runbook` | SPEC-0272 | 0/1/2, 13 |
| `room` | SPEC-0246 §7 | 0/1/2 |
| `help` (`--help`, `-h`) | built-in | 0 |

Notes on sourcing:

- `review`, `browse`, `consolidate` predate SPEC-0189 and were baselined into
  its S0a scanner family when the branch merged (`cmd/skillctl/scanner_cmds.go`
  header: "pre-SPEC-0189 behaviour preserved"), so their owning SPEC is marked
  `(?)`: S0a is where they are dispatched and documented, not necessarily where
  they were born.
- `revoke` (the author-side verb) exits `0/1/2` plus `15` when the registry
  answers `404` (not admitted) or `409` (already revoked), measured at the
  binary against a local registry stub and against `cmd/skillctl/revoke_cmds.go`
  lines 267 and 270. It also exits `22`: `revoke feed --refresh` on a MANAGED
  host whose revocation fetch is unavailable fails closed with the same
  `revocation_stale` number the hook and the sweep use
  (`cmd/skillctl/revoke_feed_cmds.go:79`), measured at the binary with a present
  but unloadable `~/.claude/trust-roots.yaml`. The number is shared, the theme is not: the register holds
  `15` under `verify`/`blob_missing`, so a script reads `15` per verb and never
  as a chain failure. The verifier's `identity_revoked` exit `17`
  (`pkg/skillctl/exitcode` Tier 4) is surfaced by `verify` / `install`, not by
  `revoke` itself.
- `pin` exits `3` (`pin install` as a non-privileged user staged the file and
  printed the sudo runbook: `pinExitNeedPrivMsg`, `cmd/skillctl/pin_cmds.go`).
  `3` is a registered code (`pin`/`need_priv_msg`) and is NOT `audit`'s `3`.
- `audit` exits `1` as well as `0/2/3`. The `0/2/3` scale is the POSTURE verdict
  (`exitCodeFor`, `pkg/skillctl/audit/audit.go`); `1` is the ordinary internal
  error, reachable at three sites: a failed inventory scan
  (`cmd/skillctl/audit_cmds.go:138`), a cleanup token that cannot be built
  (`:236`), and a `--confirm-delete` whose deletions partly failed (`:304`).
  Measured at the binary: a confirm-delete into a read-only skills directory
  exits `1`.
- `install` and `verify` do NOT reach `23`. The number is registered
  (`log_inclusion_missing`) and `verify.ExitCode` maps it, but the only function
  that raises `ErrLogInclusionMissing`, `verify.CheckLogInclusion`, has no caller
  outside its own test file, so no chain run can produce it. `23` is reachable
  today through `translog verify` alone (`exitTranslogNotIncluded`).
- `runbook publish` exits `13` with no device token, and on a `401`/`403` from
  the catalog (`cmd/skillctl/runbook_cmds.go` lines 96 and 123). Same shared
  number, different theme again: the register holds `13` under
  `verify`/`governance_below_min`.
- `session-baseline` exits `0/1` only. It is a pure read that gates nothing, and
  its flag-parse failure returns `1`, not `2`
  (`cmd/skillctl/session_baseline_cmds.go`).
- `auditlog` has a `0/1` HEALTH verdict, and `2` on a usage or flag error
  (`auditlogExitUsage`, `cmd/skillctl/auditlog_cmds.go`). The health space is
  what must not be confused with `audit`'s posture space; the usage code is the
  ordinary one.
- `export-bundle` and `export-verification-kit` both hand the error of
  `verify.Verify` to `verify.ExitCode`, so their space is the codomain of that
  composition: `0/1/2` plus `10`..`17` and `20`. They reach neither `18`/`19`
  (intent and awareness raise those, not the chain) nor `22`/`23` (the freshness
  and log-inclusion checks that `install` and `verify` run around the chain, and
  these two verbs do not).
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
