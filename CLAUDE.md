# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository is three CLIs in one Go module: `m3c-tools` (capture to ER1),
`skillctl` (skill trust plane), and `secretctl` (named secrets, never printed).
Product shape, packages, and programs: [README.md](README.md),
[docs/component-index.md](docs/component-index.md),
[docs/program-index.md](docs/program-index.md).

Capture pipeline (one of several): YouTube or local media → transcript /
whisper / screenshot → `impression` composite → `er1.Upload`. On failure the
payload is saved under a MEMORY folder and queued for retry.

## Build & Test Commands

```bash
make build              # Build CLI → ./build/m3c-tools
make vet                # go vet ./...

make test-unit          # Offline tests (pkg/ and e2e/ lists in the Makefile)
make test-network       # Requires internet (transcript only by default)
make test-network M3C_TEST_FULL_NETWORK=1  # Include thumbnail + translate tests
make test-er1           # Requires running ER1 server
make test-whisper       # Requires whisper binary in PATH
make test-recorder      # Requires PortAudio + microphone
make e2e                # Run all e2e tests

go test -v -count=1 ./e2e/ -run TestTranscriptFetch
make run ARGS="transcript dQw4w9WgXcQ --format srt"
```

## Capture details that still matter

- InnerTube: Android client context, `CONSENT=YES+cb` cookie, strip `&fmt=srv3`
  from caption `baseUrl` to get XML. Caption URLs with `&exp=xpe` are PoToken
  and must error.
- CLI flags: manual `os.Args` parsing (no cobra/flag). Follow `cmdTranscript()`
  when adding commands.
- ER1 multipart requires transcript, audio, and image parts. Missing audio or
  image is filled with a 1s silent WAV or a 1x1 PNG.

## Writing style (binding, machine-enforced)

Before writing ANY text into this repository (code, comments, docs, YAML, commit
messages, PR bodies, CLI strings), read
[`.claude/rules/prose-style.md`](.claude/rules/prose-style.md).

The short version: **never emit U+2014 EM DASH**, and do not substitute a spaced
hyphen or a double hyphen for it. Choose the punctuation the sentence needs, a
colon for a label and its expansion, a period for two statements, a semicolon
for two clauses too close to split, commas or parentheses for an aside. A lone
dash in a table cell is `n/a`.

Enforced three ways: a `PreToolUse` hook (`.claude/hooks/no-emdash-guard.sh`)
that refuses the write, `./scripts/check-no-emdash.sh` locally and in
`make ci`, and the blocking `prose-gate` CI job. Rationale and the two byte-level
exemptions: [CODESTYLE.md](CODESTYLE.md#prose-no-em-dashes).

## Claims (binding)

Before writing any sentence about behaviour (a doc line, a code comment, a
commit message, a job name, a tool's help text), read
[`.claude/rules/claims.md`](.claude/rules/claims.md).

The short version: **the word "measured" is reserved for what was measured.**
A promise in a header covers every line under it. Turning a behaviour off means
hunting for whoever still claims it. And a search that finds nothing proves
nothing until it has been shown to find a planted occurrence.

Unlike the prose rule below, this one has no hook behind it. It was written
after an adversarial re-read of nine changes found the same failure class in
seven of them: a sentence printed beside measurements gets read as a
measurement. Derivation and the five measures: `PLAN/QG-0001-fruehwarnung.md`
in the maintenance repository.

## Branching, and what merges without you

Branch names are enforced by a required check: `<prefix>/<name>`, exactly one
slash, prefix drawn from a fixed list. The list, the reasoning and the single
named exception (pull requests authored by `dependabot[bot]`, owner decision E1
of 2026-09-08) live in README §"Branch & worktree workflow". Work in your own
`git worktree`, never in the shared checkout.

Dependabot pull requests additionally arm GitHub's auto-merge on their own
(`.github/workflows/dependabot-auto-merge.yml`, owner decision E2), so a green
dependency bump lands in `master` with nobody reading it. Postponing one is a
`hold` label for the short term and an `ignore:` entry in
`.github/dependabot.yml` for anything that must outlive the pull request.

## Configuration

Settings load from the active profile, then `~/.m3c-tools/preferences.env`.
A CWD `.env` is read only with `M3C_DOTENV=1`. See `.env.example`.
- `ER1_API_URL`, `ER1_API_KEY`, `ER1_CONTEXT_ID`: server connection
- `ER1_VERIFY_SSL`: `false` is allowed only for loopback

SPECs and ER1 requirements live in the private maintenance plane.

## Context Efficiency

Treat conversation history as **disposable working memory**. Durable project state belongs in the repository, not the conversation. **Retrieve, don't replay.**

**Before reading large files:**
1. Search for the relevant symbol / section / filename first (grep/glob), then open it.
2. Read only the relevant line ranges: not the whole file "to be safe".
3. Do not load generated files, logs, lock files, or large datasets unless the task requires it.
4. **Never inspect the whole repo recursively** unless repository-wide discovery is genuinely needed.

**Multi-stage work:**
1. Carry accepted results (artifacts, decisions, test results) forward.
2. Do not carry rejected reasoning or abandoned approaches.
3. Write a checkpoint and start a **fresh session** before a substantially different task.

**Answers & tools:** ask for / produce exactly what's needed (paragraph, JSON, 5 bullets). Output costs twice: once when written, then in every later turn as input. Load only the tools the task needs (least-context access: `coding` = filesystem + git + shell).

**At task completion**, produce a compact handoff (no transcript): objective · facts established · decisions made · files changed · tests/results · open questions · next action · relevant files (name 3–10, don't load broadly).

Context budget: 🟢 <20k normal · 🟡 20–60k prune + checkpoint · 🔴 >60k or task-switch: finish the atomic operation, write the handoff, start a fresh session. See SPEC-0357 (`context-handoff`) for the sealed, provider-neutral handoff contract.
