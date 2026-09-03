# CODESTYLE.md — the m3c-tools code-quality baseline

The rationale behind the machine-enforced rules. `.golangci.yml` is what CI runs;
this file says **why**, and — just as importantly — states honestly what is
**not** enforced yet, so nobody mistakes an intention for a gate.

Companion tooling: `/code-quality` (run + remediate the baseline),
`/docs-consistency` (the CLI↔manual gate below), `/slop-check` (the
AI-slop / overclaim audit).

---

## The pragmatic+ baseline

"Pragmatic+" means: **report first, block only where the rule is unambiguous.**
A finding is closed by changing the code, or by a written, scoped exemption —
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
| CLI surface | Every real flag documented, every documented flag real | `cmd/docaudit` (see below) |

### The honesty rule for comments

A comment describes what **exists**. Scope limits are welcome and should be
loud — `HONEST SCOPE:`, `NOT-YET-WIRED:`, "this is detectable, not impossible".
Aspirational documentation (describing the design you intend, in the present
tense, next to code that does not do it) is a defect, not a placeholder.

---

## What is machine-enforced today

Enabled in `.golangci.yml` and blocking in CI (`lint` job):

- `go vet ./...`
- `staticcheck`, `unused`, `errcheck` (with the curated exclusion list — every
  entry names the fire-and-forget call it excuses)

Blocking in CI as separate jobs: `govulncheck`, `gitleaks`, `go mod tidy`
no-op check, the race-enabled test suites, and **`docaudit`** (the `docs-gate`
job in `ci.yml`, `release.yml` and `skillctl-release.yml`).

## Staged, and deliberately not yet blocking

Measured on this repo (golangci-lint v2.11.3, 2026-09-03) — the numbers are here
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
must land as their own reviewable change — riding along in an unrelated PR would
bury both the sweep and the PR it hid in. Adopt them one linter at a time,
cheapest first (`bodyclose`, `copyloopvar`, `unconvert`, `godot`, `misspell`),
each with its own commit.

---

## CLI ↔ manual consistency

`cmd/docaudit` is the release gate that keeps each CLI's **real** flag surface
and its manual in agreement, in **both** directions:

- a flag in the code with no manual entry → **UNDOCUMENTED**
- a manual entry with no flag in the code → **PHANTOM**

Either one fails the gate (exit `1`); `2` is a usage/IO error. Run it with:

```bash
go run ./cmd/docaudit -cli all                      # the gate
go run ./cmd/docaudit -cli skillctl -scaffold       # draft the missing entries
./scripts/check-docs.sh                             # section 4 runs the gate, blocking
```

### How the "real" surface is found

Mechanism-independently, by the **union** of three AST strategies, because the
two CLIs use different idioms:

1. **`flag.FlagSet` registration** — the name is the first string literal of
   `fs.String` / `fs.BoolVar` / `fs.Var` / `fs.Func`(…) (skillctl). The usage
   string sits right there, which is why it also seeds `-scaffold`.
2. **`"--flag"` string literals** — a hand-rolled `case "--x":` switch registers
   no FlagSet, so its surface is the double-dash literals it matches (m3c-tools).
3. **Short aliases named alongside their long form** — `case "-f", "--force":`
   or `if a == "--dry-run" || a == "-n"`. A *lone* `-x` literal is **not** a
   flag; it is usually another program's argument (`open -a`, `stty -echo`,
   `security -w`). A single-dash literal therefore counts only when the same
   switch-case list or `if` condition also names a `--long` flag — that sibling
   is the evidence. Only the case list and the `if` condition are scanned, never
   their bodies.

Names are canonicalised to their dashless form, because Go's `flag` package
treats `-x` and `--x` as the same flag and the manuals mix both spellings.

### How the "documented" surface is found

Fenced code blocks are stripped first — a copy-paste example documents nothing.
Then each inline code span contributes the flags it **leads with**:

| Span | Defines |
|------|---------|
| `` `--skill <dir>` `` | `--skill` |
| `` `-o, --output <path>` `` | `-o`, `--output` |
| `` `--author-intent green\|yellow\|red` `` | `--author-intent` |
| `` `skillctl report --input <scan.json>` `` | *nothing* — a command line, not a definition |
| `` `~/.claude/skills` `` | *nothing* |

Leading position is the definition signal. This is what makes the gate enforce
"described", not merely "mentioned". Two consequences worth knowing:

- To name a **foreign** flag without claiming it as ours, put it in a command
  span: `` `claude --dangerously-skip-permissions` ``, not `` `--dangerously-skip-permissions` ``.
- To write a **meta-placeholder**, keep it non-flag-shaped: `` `--<flag> <value>` ``.

### Exemptions

`docs/docaudit-ignore.txt`, fail-closed: a flag belongs there only **with a
written reason**, and an entry may be scoped to one CLI (`skillctl:--force`).
The legitimate categories so far are: documented-as-absent (the manual states a
flag deliberately does *not* exist), a hidden advanced flag parsed outside the
standard FlagSet, and the flags of a command that is not dispatched at all
(`invoke-replay`) — those retire when the dead code does.

An exemption is never the right fix for "the extractor cannot see it". If the
gate is blind to a real idiom, teach the extractor and add a test.
