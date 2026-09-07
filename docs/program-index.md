---
layout: default
title: Program Index
---

# Program Index

**What you run.** Every buildable/runnable entry point in the `m3c-tools`
repository: Go binaries, Python MCP servers, and the evaluation harness.

> Go module: `github.com/kamir/m3c-tools`. All Go binaries build to `./build/`.
> The bare executables checked out at the repo root (`m3c-tools`, `skillctl`,
> `thinking-engine`, `m3c-tools.exe`) are git-ignored build artifacts, not sources.

See also: [Service Index](service-index) (what stays running) ·
[Component Index](component-index) (the libraries these programs are built from).

## Go binaries (`cmd/`)

| Program | Entry point | Build | What it is |
|---------|-------------|-------|------------|
| **m3c-tools** | `cmd/m3c-tools/` | `make build` | The main Multi-Modal-Memory CLI. Also launches the macOS menu bar app with `--menubar`. |
| **skillctl** | `cmd/skillctl/` | `make build-skillctl` | The skill **trust** CLI: sign, admit, verify, revoke, audit skills (offline-verifiable). |
| **skillctl-demo** | `cmd/skillctl-demo/` | `make build-skillctl-demo` | Self-contained offline demo that shows a CISO the trust plane *containing an attack live* (scenarios S1/S2A/S5, real exit codes). |
| **thinking-engine** | `cmd/thinking-engine/` | `make thinking-build` | Per-user cognitive runtime (SPEC-0167). Runs as a service: see [Service Index](service-index). |
| **poc-menubar** | `cmd/poc-menubar/` | `make build-all` | Reference POC: macOS menu bar via `menuet`. |
| **poc-recorder** | `cmd/poc-recorder/` | `make build-all` | Reference POC: PortAudio microphone recording. |
| **poc-transcript** | `cmd/poc-transcript/` | `make build-all` | Reference POC: YouTube transcript fetch (core library port). |
| **poc-whisper** | `cmd/poc-whisper/` | `make build-all` | Reference POC: Whisper transcription via CLI subprocess. |
| **skillctl-sim** | `cmd/skillctl-sim/` | `make build-skillctl-sim` | Trust-plane simulation: a generated corpus of multi-principal scenarios, each with a SPEC-derived prediction, run against the real `skillctl` binary and a real git registry. `make sim`. |
| **docaudit** | `cmd/docaudit/` | `go run ./cmd/docaudit` | Blocking gate: the CLI flag surface (AST-extracted) against its manual, in both directions, plus every dispatched verb against the binary's own `--help`. |
| **verbaudit** | `cmd/verbaudit/` | `go run ./cmd/verbaudit` | Blocking gate: the dispatched `skillctl` verbs against the allocation table [CLI-VERBS](CLI-VERBS) (FR-0113). |
| **structural** | `cmd/structural/` | `go run ./cmd/structural` | Inventories the decisions in the trust path and states the MC/DC obligation each one carries. Produces the obligation, not a coverage measurement. |
| **release-evidence** | `cmd/release-evidence/` | `go run ./cmd/release-evidence` | Assembles the Release Evidence Bundle (the "Trust Binder"): an index that ties a set of release artifacts to a commit and a mandatory gate-set. |

> The four `poc-*` binaries are **validated reference implementations**, not
> production code (see `CLAUDE.md`). The last four rows are the repository's own
> gates and measurement tools; they ship no user-facing feature. Measured, they
> run in different places: `docaudit` and `verbaudit` BLOCK, from
> `scripts/check-docs.sh` and from the `docs-gate` job of `ci.yml`,
> `release.yml` and `skillctl-release.yml`; `structural` only reports, because its
> step in `ci.yml`'s `freeze-manifest` job pipes into `tail` and the workflow sets
> no `pipefail`, so its exit status cannot fail the run; `release-evidence` runs in
> `skillctl-release.yml`. None of the four runs in `make ci`.

### Subcommand surfaces

Both CLIs parse `os.Args` by hand (no cobra/flag). Neither verb list is
duplicated here: a copy in this file was how five subcommands that do not exist
came to be documented while ten real ones were not. Each binary is its own
source of truth, and both are gated:

- **m3c-tools**: run `m3c-tools help`. Full reference:
  [Manual: m3c-tools](manual-m3c-tools).
- **skillctl**: run `skillctl help`. Full reference:
  [Manual: skillctl](manual-skillctl); the allocation table for the verb names
  is [CLI-VERBS](CLI-VERBS).

`cmd/docaudit` blocks a release when a dispatched verb is missing from the
binary's own `--help`, or when a flag and its manual disagree; `cmd/verbaudit`
blocks when a dispatched verb has no row in the allocation table.

## Python programs (MCP servers)

| Program | Entry point | What it is |
|---------|-------------|------------|
| **mcp-skill-server** | `mcp-skill-server/server.py` | MCP (stdio) server exposing the skill lifecycle as Claude Code tools: wraps the `skillctl` Go CLI + aims-core REST. |
| **rag-mcp-server** | `rag-mcp-server/rag_mcp_server.py` | MCP (stdio) server for local, air-gapped workspace RAG (SPEC-0268). Also ships a CLI (`rag.py`) and pipeline scripts (`indexer.py`, `embedder.py`, `chunker.py`, `distill_backfill.py`). |

Both run as long-lived services: see [Service Index](service-index).

## Evaluation harness

| Program | Location | Build | What it is |
|---------|----------|-------|------------|
| **trust-layer evaluation** | `evaluation/` | `make eval` (`make eval-fast`) | SPEC-0280 measurement harness. Contains no production code; the measurable surface lives entirely in Go test files (`e1`…`e10`: verify latency, revocation scale, body-scan corpus, agent-authz, inclusion proof, freshness, …). |

## Operational scripts (not primary programs, but runnable)

| Area | Location | Purpose |
|------|----------|---------|
| Build & packaging | `scripts/build-all.sh`, `scripts/build-windows.sh`, `scripts/build-portaudio-universal.sh`, `scripts/make-dmg.sh`, `scripts/make-icns.sh` | Cross-platform builds, macOS bundle/DMG, Windows binary. |
| Installers | `installer/` (`m3c-tools.nsi`, `build.sh`), `scripts/installer.nsi`, `tools/skillctl-install.sh`, `tools/skillctl-install.ps1` | NSIS installer, skillctl install one-liners. |
| skillctl release/runbook | `tools/skillctl-release.sh`, `tools/skillctl-runbook.sh`, `tools/skillctl-runbook-publish.sh`, `scripts/publish-skb.sh` | Release + `.skb` publish + runbook automation. |
| Thinking Engine launch | `tools/thinking-engine-start.sh` | Convenience launcher for a per-user engine stack. |
| Capture-source login/checks | `tools/plaud-mcp-login.mjs`, `tools/plaud-e2e-check.sh`, `scripts/e2e-plaud-sync-local.sh` | Plaud OAuth login + E2E sync verification. |
| CI / docs / review | `scripts/code-review.sh`, `scripts/check-docs.sh`, `scripts/check-index.sh`, `scripts/e2e-device-token-proof.sh` | `check-docs.sh` runs the docaudit / verbaudit / tutorial / index gates locally; `check-index.sh` is the index gate itself, and the CI `docs-gate` job calls it directly. |

Discover all build/test/run entry points with `make help`.
