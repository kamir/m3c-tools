# Guide: developer setup, build, test and the gates

How to get from a fresh clone to a passing local CI run, and which gates will
judge your change before a human does. Commands below were read from the
`Makefile` and `scripts/check-docs.sh` on 2026-09-16; run them from the
repository root of your own worktree.

Audience: a developer making their first change. The architecture itself is on
the [architecture overview](architecture.md); this page is about the workflow
around a change.

Rolle: Entwickler · Sprache: EN · Stand: 2026-09-17

## The core rule in one sentence

**Work in your own `git worktree`, on a branch named `<prefix>/<name>`, open
the pull request against `master`, and run `make ci` before you push:** the
shared checkout is worked by concurrent sessions, the branch name is enforced
by a required check, and CI runs the same gates you can run locally.

Branch prefixes, the reasoning and the one exception are in
[README, "Branch & worktree workflow"](../../../README.md#branch--worktree-workflow).
Two footnotes to that rule, both bitten in review:

- **The PR target is `master`.** `origin/main` exists but is not where work
  lands: measured on 2026-09-16, the recent pull requests (#307, #309, #311)
  are merge commits on `origin/master`, and `origin/master` is 554 commits
  ahead of `origin/main`'s merge base. Tooling that guesses "main" as the
  default guesses wrong here.
- **The worktree command.** The house target is
  `make worktree SPEC=spec-XXXX STEP=name BRANCH=feat/name [BASE=origin/master]`
  (creates `../wt/<SPEC>/<STEP>`; usage printed when arguments are missing).
  Plain git works too:

  ```bash
  git worktree add ../wt/my-change -b fix/my-change origin/master
  ```

- **A dependency on another PR is a body line, not a comment.** If your PR
  must land after another one, write `Depends-on: #316` into the PR BODY
  (several such lines are fine, so is `Depends-on: #316, #317`; case does not
  matter). The workflow `.github/workflows/pr-deps-gate.yml` runs
  `scripts/check-pr-deps.sh` on every body edit and every branch move: the
  check "PR dependencies (DAG gate)" is red while a named PR is still OPEN,
  red for a reference it cannot resolve (a typo never counts as satisfied),
  and green once every named PR is MERGED or CLOSED. While blocked, the PR
  carries the label `blocked-by-dependency`, so the PR list shows the merge
  order without opening a single PR. A comment saying "merge #316 first" does
  none of this; the body is the contract, a comment is conversation.

## Part A: build

The two CLIs have different build prerequisites, and the lighter one first:

```bash
make build-skillctl     # the trust CLI; plain `go build`, no extra tools needed
make build              # main CLI -> ./build/m3c-tools; gated by check-deps (below)
make build-all          # every command in cmd/, a set the check-make-targets gate pins
make vet                # go vet ./...
```

**`make build` refuses on a machine without capture tooling.** The target
depends on `check-deps` (Makefile), which exits 1 unless `pkg-config`,
`ffmpeg` and `whisper` are all on PATH; `make deps` installs them. This gates
the main CLI even though the flagged tools are capture-runtime concerns; only
`build-skillctl` is free of it. `make build-all` additionally builds
`poc-recorder`, which imports PortAudio via cgo, so it needs
`brew install portaudio` on top. Platform details:
[Prerequisites](../../old/prerequisites.md).

## Part B: test

All tests live in `e2e/`. The suites are split by what they need; none of the
offline path needs a `.env` or any ER1 configuration:

```bash
make test-unit          # offline only: no network, no hardware
make test-network       # needs internet
make test-er1           # needs a running ER1 server
make test-whisper       # needs the whisper binary in PATH
make test-recorder      # needs PortAudio + a microphone
make e2e                # all of the above
```

`make test-unit` is a single long `go test` run, not instant: measured
2026-09-16 on one warm machine, `ok github.com/kamir/m3c-tools/e2e 39.601s`,
exit 0; `make ci` runs the same suite again as its test step.

A single offline test:
`go test -v -count=1 ./e2e/ -run TestRetryQueueInsertAndQuery` (part of the
`test-unit` selection). Careful when picking your own `-run` pattern: some
`e2e/` tests are network tests, and not every one guards itself with
`SkipIfNoYTCalls` (`TestTranscriptFetch` in `e2e/transcript_test.go` calls
YouTube unguarded). And note the trap recorded in
`.claude/rules/claims.md`: a `-run` pattern matching nothing exits 0;
`scripts/require-tests-ran.sh` exists for exactly that.

## Part C: the gates, and which files they bind

`make ci` runs, in this order (read from the Makefile target `ci`):
`vet lint check-emdash check-gofmt check-redirect-guard check-required-checks
check-docpages test-unit build`.

**One tool it does not install for you: `golangci-lint`.** The `lint` step
calls `golangci-lint run` directly (Makefile), so on a machine without it,
`make ci` stops at step two. The stage 2 script
(`scripts/skillctl-enterprise-test.sh`, described in
[Prerequisites](../../old/prerequisites.md)) installs it at the version CI pins;
installing by hand works too, the enforced config is `.golangci.yml`.

The documentation gates live in `./scripts/check-docs.sh` and block a release:

| Gate | Binary | Binds |
|---|---|---|
| CLI ↔ manual ↔ `--help` | `cmd/docaudit` | [manual-m3c-tools](../referenz/manual-m3c-tools.md), [manual-skillctl](../referenz/manual-skillctl.md), exemptions in [docaudit-ignore.txt](../../docaudit-ignore.txt) |
| verb register | `cmd/verbaudit` | [CLI-VERBS](../referenz/CLI-VERBS.md): register the verb BEFORE implementing it |
| exit-code register | `cmd/exitaudit` | the manual's `Exit:` lines, the register column, `pkg/skillctl/exitcode` |
| tutorial chain | `scripts/tutorial-smoke.sh` | `docs/v2/nutzer/tutorial-szenario-0*.de.md`, run against a throwaway registry (a bare `local://` git registry in a temporary HOME, created and deleted per run) |
| index freshness | `scripts/check-index.sh` | [program-index](../../program-index.md), [component-index](../../component-index.md), both directions plus the counts |
| docpage drift | `scripts/check-docpages.sh` | every page registered in its `REGISTER` block, byte-compared against its markdown source |

Two prose rules are binding for every byte you write into this tree, including
commit messages: [prose-style.md](../../../.claude/rules/prose-style.md)
(never U+2014, machine-enforced) and
[claims.md](../../../.claude/rules/claims.md) (the word "measured" is reserved
for what was measured).

Formatting and commit conventions beyond `gofmt` (gofumpt, `gci` import
groups, the `-race` test policy) are in
[CONTRIBUTING.md](../../../CONTRIBUTING.md); `.golangci.yml` is the enforced
config, and [CODESTYLE.md](../../../CODESTYLE.md) carries the reasoning.

## Part D: filing bugs and features

A bug or feature request lives on two planes, kept in step by
`scripts/bugtracker.sh`; the workflow, the refusals and the redaction rules
are in [bug-tracking](bug-tracking.md).

## Part E: releasing

Releases are tag-driven; there is no VERSION file, and the product line
(`vX.Y.Z`) and the skillctl line (`skillctl/vX.Y.Z`) are cut independently.
The operational runbook is [releasing](../betrieb/releasing.md); the human
sign-off and acceptance gates are described there too.
