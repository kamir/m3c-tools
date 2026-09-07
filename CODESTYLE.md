# CODESTYLE.md: the m3c-tools code-quality baseline

The rationale behind the machine-enforced rules. `.golangci.yml` is what CI runs;
this file says **why**, and, just as importantly, states honestly what is
**not** enforced yet, so nobody mistakes an intention for a gate.

Companion tooling: `/code-quality` (run + remediate the baseline),
`/docs-consistency` (the CLI↔manual gate below), `/slop-check` (the
AI-slop / overclaim audit).

---

## The pragmatic+ baseline

"Pragmatic+" means: **report first, block only where the rule is unambiguous.**
A finding is closed by changing the code, or by a written, scoped exemption,
never by quietly loosening a rule.

| Area | Rule | Tooling |
|------|------|---------|
| Format | Deterministic gofmt superset, import groups std / external / `github.com/kamir/m3c-tools` | `gofumpt`, `gci` |
| Correctness | `go vet` + `staticcheck` + `unused` + `errcheck` | `golangci-lint` |
| Errors | Wrap with `%w`, sentinels named `ErrXxx`, no silent `_ =` in non-test code | `errorlint`, `errcheck` |
| Doc comments | Exported identifiers documented; comments end with a period | `revive`, `godot` |
| Cleanliness | No redundant conversions, no leaked response bodies, no loop-var aliasing | `gocritic`, `unconvert`, `bodyclose`, `copyloopvar`, `nilerr`, `misspell` |
| Security (SAST) | Crypto, injection, hardcoded credentials | `gosec` |
| Dependencies | Reachable CVEs, secret scan, `go mod tidy` is a no-op | `govulncheck`, `gitleaks`, CI job |
| CLI surface | Every real flag documented, every documented flag real, every dispatched verb named by `--help` | `cmd/docaudit` (see below) |
| Index freshness | Every `cmd/` binary and `pkg/` package indexed, every indexed one real, and both counts right | `scripts/check-index.sh` (CI `docs-gate` + `check-docs.sh` section 7) |

### The honesty rule for comments

A comment describes what **exists**. Scope limits are welcome and should be
loud. `HONEST SCOPE:`, `NOT-YET-WIRED:`, "this is detectable, not impossible".
Aspirational documentation (describing the design you intend, in the present
tense, next to code that does not do it) is a defect, not a placeholder.

---

## What is machine-enforced today

Enabled in `.golangci.yml` and blocking in CI (`lint` job):

- `go vet ./...`
- `staticcheck`, `unused`, `errcheck` (with the curated exclusion list: every
  entry names the fire-and-forget call it excuses)

Blocking in CI as separate jobs: `govulncheck`, `gitleaks`, `go mod tidy`
no-op check, the race-enabled test suites, and **`docaudit`** (the `docs-gate`
job in `ci.yml`, `release.yml` and `skillctl-release.yml`).

## Staged, and deliberately not yet blocking

Measured on this repo (golangci-lint v2.11.3, 2026-09-03): the numbers are here
so the gap is a known quantity rather than a vague aspiration:

| Rule | Current cost to adopt |
|------|----------------------|
| `gofumpt` + `gci` | **186 files** would change (mostly `0700` → `0o700` and import regrouping) |
| `revive` | 50 findings |
| `gocritic` | 31 findings |
| `nilerr` | 22 findings |
| `errorlint` | 9 findings |
| `misspell` | 7 findings |
| `unconvert` / `godot` | 3 each |
| `copyloopvar` | 2 findings |
| `bodyclose` | 1 finding |
| `gosec` | not yet measured (tool not installed in CI) |
| Coverage floor | not yet measured; **never** set a floor above what the suite already meets |

These are not enabled yet because a 186-file format sweep and ~128 lint findings
must land as their own reviewable change. Riding along in an unrelated PR would
bury both the sweep and the PR it hid in. Adopt them one linter at a time,
cheapest first (`bodyclose`, `copyloopvar`, `unconvert`, `godot`, `misspell`),
each with its own commit.

---

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

A gate that fires after the fact is a retry loop. The rule an agent has to hold
*while writing* lives in **[`.claude/rules/prose-style.md`](.claude/rules/prose-style.md)**,
is referenced from `CLAUDE.md` so every session in this repository loads it, and
is backed by the `PreToolUse` hook `.claude/hooks/no-emdash-guard.sh`, which
refuses a `Write` or `Edit` whose payload contains U+2014 before it reaches disk.

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
dispatch against the allocation table `docs/CLI-VERBS.md`. Registered is not the
same as visible: every verb was registered while 33 were invisible.

### Exemptions

`docs/docaudit-ignore.txt`, fail-closed: a flag belongs there only **with a
written reason**, and an entry may be scoped to one CLI (`skillctl:--force`).
The legitimate categories so far are: documented-as-absent (the manual states a
flag deliberately does *not* exist), a hidden advanced flag parsed outside the
standard FlagSet, and the flags of a command that is not dispatched at all
(`invoke-replay`): those retire when the dead code does.

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
