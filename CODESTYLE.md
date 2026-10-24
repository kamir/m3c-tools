# CODESTYLE.md: the m3c-tools code-quality baseline

[Deutsch](CODESTYLE.de.md) · [English](CODESTYLE.md)

The rationale behind the machine-enforced rules. `.golangci.yml` is what CI runs;
this file says **why**, and, just as importantly, states honestly what is
**not** enforced yet, so nobody mistakes an intention for a gate.

Companion tooling: `/code-quality` (run + remediate the baseline),
`/docs-consistency` (the CLI↔manual gate below), `/slop-check` (the
AI-slop / overclaim audit).

---

## The pragmatic baseline

Keep the implementation straightforward and make security decisions explicit.
Fix defects before adding abstractions. A rule becomes blocking after its actual
findings have been reviewed; exceptions belong at the call site with a concrete reason.

| Area | Rule | Enforcement |
|------|------|-------------|
| Format | Deterministic standard Go formatting | `scripts/check-gofmt.sh` locally and in CI |
| Correctness | Vet, static analysis, unused code and checked errors | `govet`, `staticcheck`, `unused`, `errcheck` in golangci-lint |
| Resource handling | Close HTTP response bodies; remove redundant loop copies and conversions | `bodyclose`, `copyloopvar`, `unconvert` in golangci-lint |
| Errors | Preserve relevant causes with `%w`; classify with `errors.Is`/`errors.As`; do not silently turn failures into success | Review, errcheck within its documented scope, regression tests |
| Comments | Explain contracts, invariants and reasons; exported APIs need useful documentation | Review; no claim of universal comment linting |
| Security analysis | Detect new findings relative to the committed baseline | Standalone gosec and its diff gate |
| Dependencies | Check reachable vulnerabilities, leaked secrets and module consistency | govulncheck, gitleaks and the tidy gate in CI |
| Coverage | Protect measured floors for the scoped trust packages | `.testcoverage.yml`, including the aggregate floor of 57 |
| CLI surface | Keep real flags, documented flags and help dispatch consistent | docaudit |
| Inventories and exits | Keep program/package indexes and documented exit codes consistent | check-index, verbaudit and exitaudit |
| Release review | Command failure, missing scanner or incomplete scan blocks the review | code-review.sh and its failing-side contract tests |

### The honesty rule for comments

A comment describes what exists. Name scope limits and intentional fallbacks.
Do not describe a planned protection as present. A skipped check is not a pass;
an unreadable holder is not a verified holder. Evidence must identify its scope.

## Simple implementation, explicit boundaries

- Prefer concrete types and the standard library. Add a dependency only when it
  solves a demonstrated need; explain the reason and maintenance cost in the PR.
- Define small interfaces at the consuming boundary when substitution is needed.
  Do not create an interface, factory or framework for every struct.
- Keep functions cohesive and control flow direct. Use early returns to make the
  normal path clear; avoid hidden side effects and speculative generalization.
- Validate untrusted paths, sizes, origins and formats at the boundary. Make
  authorization, integrity, revocation and incomplete results explicit.
- Pass `context.Context` first for cancellable I/O and propagate it to the actual
  request or subprocess. Pure calculations do not need artificial contexts.
- Own goroutine lifetimes: define cancellation, termination and who waits.
  Prefer synchronous code when concurrency provides no demonstrated benefit.
- Check writes, flushes, syncs, closes and renames that publish durable or secret
  state. Ignoring a read-side cleanup error requires a local reason. Do not use
  a deferred write as a substitute for a checked publication step.
- Use established cryptographic primitives and `crypto/rand` for security values.
  Keep secret bytes out of errors, process arguments and logs.
- Tests use temporary homes, directories and stores. Set both `HOME` and
  `USERPROFILE` when testing user paths. Live services and credentials require an
  explicit opt-in; ordinary tests must not alter a developer's configuration.
- Add focused failure-path and regression tests for trust decisions and persistence.
  Run the race detector on affected concurrency paths. Do not replace meaningful
  assertions with a blanket coverage target or tests that mirror implementation text.

These conventions follow the [Go review guidance](https://go.dev/wiki/CodeReviewComments)
and the [Go security guidance](https://go.dev/doc/security/).

## What is machine-enforced today

### Test execution evidence

`ci-test-selection.json` declares the managed test lanes. The required simulation
job waits for their producer jobs and validates each expected raw report and its
commit, run, attempt, producer, selection and digest metadata. A missing artifact,
unsuccessful producer or report without successful tests blocks that job.
Declared prose-only exclusions remain visible as a smaller expected lane set.
This is CI consistency evidence, not independent attestation or customer acceptance.

Use **Re-run all jobs** after a failed attempt. Re-running only failed jobs can
leave successful producers' evidence on an older attempt; the consumer rejects
that evidence intentionally. Windows/Linux parity likewise needs both producers
from the same attempt. Archive necessary execution records before their seven-day
CI retention expires. New test packages require an assignment; package inventory
does not establish that every platform-specific or optional test was executed.

The offline E2E lane requires named CLI scenarios to pass and permits only its
declared exact optional skips. Optional macOS app-bundle prerequisites are checked
before building. A dedicated packaging check must set `M3C_REQUIRE_APP_BUNDLE=1`
to fail on missing prerequisites; subsequent build or execution errors always
fail. Packaging and live-service skips do not constitute customer acceptance.

The existing Lint & Vet job runs the configured golangci-lint version on native
macOS and on the Linux and Windows build selections. The portable selections use
`CGO_ENABLED=0`; they are static checks, not native execution on those platforms.
Native tests remain separate. `make lint` uses the local tool; CI pins its version.

Errcheck currently excludes test files, formatted output functions and deferred
calls. Those are real limits: it does not enforce every `_ =` assignment or every
cleanup result. Review must still check durable-state operations. A justified
platform-specific suppression names the affected rule and reason at that line.

Separate CI jobs run govulncheck, gitleaks, tidy, race-enabled tests, documentation
consistency and scoped coverage. `make ci` runs the Makefile's selected local
checks and offline E2E list; it is not the complete CI package/race suite.
The release-review script checks command exit statuses and runs package tests once;
a missing or unsuccessful vulnerability scanner blocks that review.

## Review rules that are not blanket lint gates

`gofumpt`, `gci`, `revive`, `gocritic`, `nilerr`, `errorlint`, `godot` and
`misspell` are not enabled as universal blockers here. Formatting is enforced by
gofmt. Some diagnostic findings are intentional fallbacks or language-sensitive
prose, and mechanically replacing `%v` with `%w` changes the exposed error API.
Review each rule's actual findings before adopting it; never hide them by widening
an exclusion. Gosec remains standalone rather than being run a second time inside
golangci-lint. Do not raise coverage floors above demonstrated results or describe
a baseline as proof that no vulnerabilities exist.

---

## Names in examples: the standard cast

Examples, fixtures, tutorials, demo scripts and test identities use a fixed cast
of invented people. Never the name of an actual colleague, customer or contact.

| Persona | Role, kept stable across the whole tree |
|---|---|
| Bob | the author: packs, signs, publishes |
| Alice | the recipient: pins trust, verifies, installs |
| Charlie | a reviewer or attester |
| Diana | a registry or governance operator |
| Eddy, Freddy, Gustav, Hans | further parties as needed |

Identity ids follow the same rule: `id:bob@example`, `id:alice@example`. Keep a
persona in one role everywhere, because a reader who learns that Bob signs will
carry that across documents.

**Authorship is not a persona.** A commit author, a copyright line and the
`PRODUCT_PUBLISHER` field of a signed installer name a real legal person because
that is their job. Replacing one of those with a persona does not anonymise
anything; it falsifies provenance, which in this repository is the worse
failure. The gate exempts those lines individually, with the reason written next
to each.

An owner-triaged historical scanner fingerprint must retain its original
commit, path, rule and line to resolve the finding. The name gate admits only
the reviewed exact fingerprint in its machine-readable file. Other lines,
files and commits remain checked; six regression cases protect this boundary.

Why mechanical: this tree is public and it is mirrored into a customer's GitLab
every thirty minutes. A name arrives through a hundred small additions, each
harmless alone, and a reviewer who catches the ones in prose still misses the
ones in a test fixture, a file name or a shell variable.

```bash
./scripts/check-no-real-names.sh            # whole tree, exit 1 on any hit
./scripts/check-no-real-names.sh --staged   # only what you are about to commit
```

The gate checks file NAMES as well as contents, and it is wired into the
blocking `prose-gate` CI job. One caution it encodes, learned the hard way:
`git grep -E` does not understand `\b`, so it matches nothing and reports
success. Use `-w`.

## Prose: no em dashes

**Rule.** The character U+2014 EM DASH does not appear anywhere in this
repository. Not in Go code, comments or doc comments; not in Markdown, YAML,
shell, HTML or SVG; not in user-facing strings, CLI output or error messages;
not in commit messages, PR bodies or issue text. This is machine-enforced by
`scripts/check-no-emdash.sh` (see below), not left to review.

**Why.** Two reasons, and the second one matters more than the first.

1. The em dash is the strongest single stylistic fingerprint of machine-written
   text. This repository's entire pitch is evidence and provenance: signed
   releases, verifiable bundles, honest scope. Prose that reads as generated
   undercuts that before anyone gets to the code.
2. The em dash is a **cheap** punctuation mark. It stands in for a colon, a
   period, a semicolon, a pair of commas and a pair of parentheses, all at once,
   which is exactly why it is easy to reach for. Picking the mark the sentence
   actually needs makes the sentence say what it means. The rewrite is almost
   always better technical prose, not merely different prose.

**How to replace it.** Never a blind swap to a hyphen. Read what the two halves
are doing to each other, then pick:

| The dash was doing this | Use | Example |
|---|---|---|
| A label, then its expansion | `:` | A &mdash; YouTube becomes `A: YouTube` |
| Two independent statements | `.` | X works &mdash; Y does not becomes `X works. Y does not.` |
| Two clauses, tightly linked | `;` | no admin rights &mdash; this differs becomes `no admin rights; this differs` |
| An aside inside one sentence | `, ,` or `( )` | X &mdash; and Y &mdash; is Z becomes `X, and Y, is Z` |
| A continuation or afterthought | `,` | signed &mdash; not merely checksummed becomes `signed, not merely checksummed` |
| An empty cell in a table | `n/a` | a cell holding only the dash becomes `n/a` |

Two traps worth naming, because both have already bitten this tree:

- **YAML.** A `:` inserted into an unquoted scalar changes the document
  structure. A step named `Guard`, an em dash, then `all refs are pinned` must become
  `- name: "Guard: all refs are pinned"`, quoted, or take a comma instead.
- **Asserted strings.** A message in `cmd/` that a test matches on has to change
  in both places, and a `.` that starts a new sentence also capitalises the next
  word. Prefer `;` or `,` inside strings that tests pin.

**En dash** (U+2013) is not banned. It is legal between the ends of a range
(`10&ndash;19`, `Mon&ndash;Fri`) and wrong as sentence punctuation. The gate
reports a count and never fails on it.

**Exemption**, about bytes rather than about prose:

| Path | Reason |
|---|---|
| `pkg/skillctl/bodyscan/testdata/` | The corpus IS the input under test, and `.expected.json` pins finding offsets. |

`demo/kup-training/artifacts/` was a second exemption while that tree was checked in.
It is untracked now (it carried three ed25519 private keys, and git does not preserve
mode 0600, so a fresh clone broke the demo at `skillctl sign`), and `.gitignore` keeps
it out of the scanned file list, so the exemption had nothing left to exempt.

Adding a second exemption means writing the reason here first.

### The gate

```bash
./scripts/check-no-emdash.sh            # the gate, exit 1 on any hit
./scripts/check-no-emdash.sh --staged   # only what is staged, for a pre-commit hook
./scripts/check-no-emdash.sh --all      # include the exempt paths and list the en dashes
make check-emdash                       # same gate, wired into `make ci`
```

It runs in CI as the `prose-gate` job (`ci.yml`) and as a step in the release
`docs-gate` (`release.yml`, `skillctl-release.yml`), so a release cannot ship
prose that fails it.

### The rule for agents, applied before the text exists

Agents must apply the rule in this document while writing.
[CLAUDE.md](CLAUDE.md) points to it for repository sessions. The checked-in
[scripts/check-no-emdash.sh](scripts/check-no-emdash.sh) enforces it locally and
in CI; machine-local agent hooks are not distributed with this repository.

---

## CLI ↔ manual ↔ `--help` consistency

`cmd/docaudit` is the release gate that keeps each CLI's **real** flag surface
and its manual in agreement, in **both** directions:

- a flag in the code with no manual entry → **UNDOCUMENTED**
- a manual entry with no flag in the code → **PHANTOM**

and, separately, keeps the binary honest about **itself**:

- a dispatched verb with no line in `printUsage` → **UNLISTED**
- a `printUsage` line for a verb the switch never dispatches → **USAGE-PHANTOM**

Any of the four fails the gate (exit `1`); `2` is a usage/IO error. Run it with:

```bash
go run ./cmd/docaudit -cli all                      # the gate
go run ./cmd/docaudit -cli skillctl -scaffold       # draft the missing entries
./scripts/check-docs.sh                             # section 4 runs the gate, blocking
```

### How the "real" surface is found

Mechanism-independently, by the **union** of three AST strategies, because the
two CLIs use different idioms:

1. **`flag.FlagSet` registration**: the name is the first string literal of
   `fs.String` / `fs.BoolVar` / `fs.Var` / `fs.Func`(…) (skillctl). The usage
   string sits right there, which is why it also seeds `-scaffold`.
2. **`"--flag"` string literals**: a hand-rolled `case "--x":` switch registers
   no FlagSet, so its surface is the double-dash literals it matches (m3c-tools).
3. **Short aliases named alongside their long form**: `case "-f", "--force":`
   or `if a == "--dry-run" || a == "-n"`. A *lone* `-x` literal is **not** a
   flag; it is usually another program's argument (`open -a`, `stty -echo`,
   `security -w`). A single-dash literal therefore counts only when the same
   switch-case list or `if` condition also names a `--long` flag, that sibling
   is the evidence. Only the case list and the `if` condition are scanned, never
   their bodies.

Names are canonicalised to their dashless form, because Go's `flag` package
treats `-x` and `--x` as the same flag and the manuals mix both spellings.

### How the "documented" surface is found

Fenced code blocks are stripped first: a copy-paste example documents nothing.
Then each inline code span contributes the flags it **leads with**:

| Span | Defines |
|------|---------|
| `` `--skill <dir>` `` | `--skill` |
| `` `-o, --output <path>` `` | `-o`, `--output` |
| `` `--author-intent green\|yellow\|red` `` | `--author-intent` |
| `` `skillctl report --input <scan.json>` `` | *nothing*: a command line, not a definition |
| `` `~/.claude/skills` `` | *nothing* |

Leading position is the definition signal. This is what makes the gate enforce
"described", not merely "mentioned". Two consequences worth knowing:

- To name a **foreign** flag without claiming it as ours, put it in a command
  span: `` `claude --dangerously-skip-permissions` ``, not `` `--dangerously-skip-permissions` ``.
- To write a **meta-placeholder**, keep it non-flag-shaped: `` `--<flag> <value>` ``.

### How the "self-described" surface is found

The third question is not about the manual at all. A verb missing from the
manual is a documentation gap; a verb missing from `--help` is invisible to
every user who never opens the manual. When the check was added, 33 of
`skillctl`'s 54 dispatched literals were unlisted, `pack` (step 2 of the
advertised lifecycle) among them.

Both surfaces are read out of the same command package by AST:

- **Dispatched**: the string literals of the `switch os.Args[1]` case clauses,
  aliases included. A verb the switch never names cannot be typed at runtime.
- **Named**: every string literal inside the package's `printUsage` function,
  unquoted and split into lines. That way one raw string (m3c-tools) and a
  hundred `Fprintln` arguments (skillctl) are read identically.

A usage line **names** the verb it leads with when it starts with **exactly two
spaces**, and further aliases follow comma-separated:

```text
  help, --help, -h        Print this command list.     ← names help, --help, -h
  pack                    Build a .skb bundle.          ← names pack
                          ... continued, mentions seal  ← names nothing
Getting started                                         ← names nothing
```

Deeper indentation is a continuation line and column zero is a group header, so
prose can never register a verb by accident. Keep to that shape when you edit a
usage text.

A package with no `os.Args[1]` dispatch is skipped (it does not use the idiom).
A package that **has** a dispatch and no `printUsage` is an error, so the check
cannot be switched off by a rename. There are deliberately **no exemptions**:
a verb a user can type is a verb `--help` must name.

This is a different question from `cmd/verbaudit`, which reconciles the same
dispatch against the allocation table `docs/v2/referenz/CLI-VERBS.md`. Registered is not the
same as visible: every verb was registered while 33 were invisible.

### Exemptions

`docs/docaudit-ignore.txt`, fail-closed: a flag belongs there only **with a
written reason**, and an entry may be scoped to one CLI (`skillctl:--force`).
The current categories are documented-as-absent (the manual states a flag
deliberately does *not* exist) and a hidden advanced flag parsed outside the
standard FlagSet. Exemptions for removed code must be removed with that code.

An exemption is never the right fix for "the extractor cannot see it". If the
gate is blind to a real idiom, teach the extractor and add a test.

---

## Index freshness

`docs/program-index.md` claims to list *every buildable entry point* and
`docs/component-index.md` the library packages, with a count. A prose claim about
a directory can be checked against the directory, so `scripts/check-index.sh`
does, in both directions:

- a buildable `cmd/<name>` absent from the program index → **fail**
- a `cmd/<name>` the program index names that no longer exists → **fail**
- a Go package under `pkg/` or `internal/` absent from the component index → **fail**
- a package the component index names that is not in the tree → **fail**
- a package COUNT in the component index that the directory contradicts → **fail**

The reverse direction is the one that earns its keep: the component index
documented a `skillimport` package that exists nowhere, while twelve real
`pkg/skillctl` packages were missing. The count check is the second half of the
same thought: a list check alone leaves the number free to rot, because a 41st
package that arrives WITH its row satisfies the list and quietly falsifies
"40 subpackages". Each count sentence must match exactly once, so rewording one
out of the file turns the gate red instead of switching it off.

It runs in `scripts/check-docs.sh` (section 7) and, because no workflow calls
that script, as its own step in the `docs-gate` job of `ci.yml`, `release.yml`
and `skillctl-release.yml`. A gate nothing calls is a report.

The check is mechanical on purpose. It checks **presence** and **arithmetic**,
never prose: a new package still needs a human-written responsibility line, and
the failing gate is what makes the author notice that it is owed.
## Exit-code register consistency

`cmd/exitaudit` is the sibling gate that keeps the **numbers** honest, the way
`docaudit` keeps the flags honest. Its subject is `pkg/skillctl/exitcode`, and
it exists because AUDIT-0001 measured what happens without it: `pull` mapped its
five gates onto `12/10/11/13/6` while the manual said "0 ok, 2 usage" and
`docs/v2/referenz/CLI-VERBS.md` said "0/1/2"; `verify-sig` returned `10` for an altered
bundle that no document mentioned; verify-hook's refusal space was `17/22/25/28`
in code, `17/22` in the manual, `25/26/28` in the verb register. Twelve of the
fourteen verbs that state an exit space in both documents stated two different
ones.

Five ways it goes red:

- a `Code` in `exitcode.AllCodes()` with no row in the manual's generated
  register table → **UNDOCUMENTED**
- a row in that table that `AllCodes()` does not carry → **NOT REGISTERED**
- a number written anywhere else in the manual (a per-command `Exit:` line) or
  in a `docs/v2/referenz/CLI-VERBS.md` Exit-Code cell that neither the register nor the
  manual's "Codes outside the register" table accounts for → **UNACCOUNTED**
- the manual's `Exit:` line and the verb register's cell naming different sets
  for the same verb → **PER-VERB DRIFT**
- `gateExit` in `cmd/skillctl/pull_cmds.go`, AST-parsed and resolved through
  `pkg/skillctl/exitcode/registry.go`, returning a number the `pull` cell does
  not list (or the cell claiming one it cannot produce) → **PULL GATE DRIFT**

### What it does NOT check

A gate that hides its edges is worse than no gate, so the boundary is named
here and in the tool's own package comment, and `exitaudit` prints its reach on
every run.

- **Only `pull` is read as code.** Every other verb's cell is compared against
  the MANUAL, never against its handler. A raw `return 13` added to
  `cmd/skillctl/runbook_cmds.go` is invisible to this gate; that one was found
  by hand. Widening the symbolic check to the other verbs means resolving
  cross-file helpers (`verify.ExitCode`), raw literals and `os.Exit` call sites.
  It is worth doing and it is not done.
- **Only `Exit:` statements and Exit-Code cells are scanned for numbers.** A
  number in ordinary prose, and a number in the manual's `verify-hook`
  `refusal_code` table, are not: measured 2026-09-07, an invented `77` in prose
  and an invented `88` in that table both left the gate green.
- **A verb whose manual section states no `Exit:` line falls out of the
  per-verb comparison entirely.** That is now counted and printed rather than
  silent, because a wrong `pin` cell (`0/1/2` for a verb that exits `3`)
  survived this gate's own first release exactly that way.

```bash
go run ./cmd/exitaudit                 # the gate
go run ./cmd/exitaudit -write          # regenerate the manual's register table
go run ./cmd/exitaudit -scaffold       # print it instead of writing it
./scripts/check-docs.sh                # section 6 runs the gate, blocking
```

The four generated columns (Code, Label, Surface, Theme) come from the register;
the Meaning column is prose, and `-write` carries it forward, so regenerating
costs no writing. **Exemptions live in the manual, not in a side file**: a
number that is genuinely not a registered code (`0/1/2`, `audit`'s `3`, the
`skillgate` `30`-`39` band) goes in the "Codes outside the register" table with
the file that owns it, and the gate fails if that file disappears. A number
nobody will name an owner for is a number nobody should document.
