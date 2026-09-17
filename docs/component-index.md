---
layout: default
title: Component Index
---

# Component Index

**The building blocks.** Importable Go library packages (no `main`) that the
[programs](program-index) and [services](service-index) are assembled from.
Public packages live under `pkg/`; internal-only packages under `internal/`.

Grouped by domain:
[A. Capture & media](#a-capture--media-pipeline-pkg) ·
[B. ER1 & session](#b-er1-knowledge-upload--session-pkg) ·
[C. Capture sources](#c-capture-sources-pkg) ·
[D. Config/infra/util](#d-config-infra--util-pkg) ·
[E. Desktop UI](#e-desktop-ui-pkg) ·
[F. skillctl trust subsystem](#f-skillctl-trust-subsystem-pkgskillctl-siblings) ·
[G. Other internal packages](#g-other-internal-packages-internal)

---

## A. Capture & media pipeline (`pkg/`)

| Package | Responsibility |
|---------|----------------|
| `transcript` | Pure-Go port of youtube-transcript-api (InnerTube, no API key). Video page → API key → caption XML → snippets; 4 output formats (Text/SRT/JSON/WebVTT); proxy configs; thumbnail fetch with size fallback. |
| `impression` | Observation capture + composite-document builder + tag system. Combines video transcript + user commentary into a structured ER1 document; auto-tags by observation type. |
| `whisper` | Speech-to-text via the `whisper` CLI subprocess (not C bindings); finds the binary, runs `--output_format json`, parses segments. |
| `recorder` | PortAudio microphone recording via cgo. 16 kHz/16-bit PCM mono WAV (whisper-compatible). |
| `screenshot` | Screen capture on macOS via the `screencapture` CLI. |
| `draft` | Save/load capture drafts (in-progress observations). |
| `importer` | Batch audio import: scan a folder, deduplicate, copy, and track. |
| `bulkprogress` | Platform-neutral progress vocabulary for the audio pipeline. |

## B. ER1, knowledge upload & session (`pkg/`)

| Package | Responsibility |
|---------|----------------|
| `er1` | ER1 server config + multipart HTTP upload (`transcript_file_ext`/`audio_data_ext`/`image_data`, placeholder audio/image when absent) + JSON-backed retry queue with mutex sync. |
| `er1login` | Runs the aims-core browser **device-pairing** flow and returns credentials. |
| `session` | SPEC-0213 "session-state in ER1": persist a working session as a machine-tagged memory item + checkpoint chain. |
| `tracking` | SQLite-backed export tracking for ER1 uploads. |
| `timetracking` | Local time tracking scoped to PLM project contexts. |
| `m3cproject` | Resolves the PLM project context for the current working directory (`.m3c/project.yaml`). |
| `auth` | Device-token storage and retrieval. |

## C. Capture sources (`pkg/`)

| Package | Responsibility |
|---------|----------------|
| `plaud` | API client for the **Plaud.ai** voice-recorder cloud. |
| `pocket` | **Pocket** cloud API client (SPEC-0173). |

## D. Config, infra & util (`pkg/`)

| Package | Responsibility |
|---------|----------------|
| `config` | Init/config bootstrap (`.env` / `~/.m3c-tools.env`). |
| `setup` | Foundation of the SPEC-0175 onboarding flow. |
| `httpsafe` | Small, dependency-free HTTP hardening helpers shared across clients. |
| `diag` | Diagnostic check types + rendering for the doctor/check surface. |
| `testutil` | Shared test helpers. |

## E. Desktop UI (`pkg/`)

| Package | Responsibility |
|---------|----------------|
| `menubar` | Types, configuration, and callback interfaces for the menu bar app. |
| `tray` | Cross-platform notifications via pure-Go `beeep`. |

## F. skillctl trust subsystem (`pkg/skillctl/*` + siblings)

The offline-verifiable skill **trust plane**: the library behind the
[`skillctl`](program-index) CLI. 42 subpackages under `pkg/skillctl/`, plus the
sibling top-level packages at the end of this section, grouped by role. The list
and the number are both gated by `scripts/check-index.sh`: it diffs `pkg/**` and
`internal/**` against this file in both directions AND re-counts the directories,
so a new package cannot arrive with a row of its own and leave the count behind.
It runs in `scripts/check-docs.sh` and in the `docs-gate` job of `ci.yml`,
`release.yml` and `skillctl-release.yml`.

**Inventory & parsing**

| Package | Responsibility |
|---------|----------------|
| `skillctl/model` | Data types for the skill inventory system. |
| `skillctl/parser` | Extracts YAML frontmatter from markdown skill files. |
| `skillctl/scanner` | Walks directories to discover Claude Code skill sources. |
| `skillctl/hasher` | Content hashing + duplicate detection. |

**Cryptography & identity**

| Package | Responsibility |
|---------|----------------|
| `skillctl/signing` | Phase-2 cryptographic primitives (SPEC-0188). |
| `skillctl/verify` | Client-side verifier algorithm (SPEC-0188). |
| `skillctl/device` | Per-machine DEVICE KEY that signs SPEC-0202 invocations. |
| `skillctl/agentid` | Pure, stdlib-only core of SPEC-0277 agent-instance identity. |
| `skillctl/translog` | L1 transparency log (SPEC-0278). |
| `skillctl/trustcore` | The signed-envelope trust primitives every backend and the pull/gossip/gauntlet paths share (FR-0090): a trust decision reads an event's kind and digest from INSIDE the signed envelope, never from an unsigned carrier projection. |

**Lifecycle, admission & install**

| Package | Responsibility |
|---------|----------------|
| `skillctl/install` | SPEC-0188 §7 client install pipeline. |
| `skillctl/importer` | Talks to the aims-core skill-profile API. |
| `skillctl/registry` | HTTP client for the aims-core skill registry. |
| `skillctl/awareness` | SPEC-0195 admission bridge. |
| `skillctl/propose` | SPEC-0194 §6 ready-to-promote gate. |
| `skillctl/pin` | SPEC-0247 §7.3 managed-settings pinning. |
| `skillctl/semver` | The one loose-semver comparator: picks the highest non-revoked version across every backend and gates version monotonicity at propose time. Replaced four copies that disagreed on a leading `v`. |
| `skillctl/homeroot` | The one place that decides how skillctl resolves the per-user root. On a shipping Windows build `$HOME` is never honoured for security paths; `%USERPROFILE%` is the only root. |

**Artifact backends (SPEC-0356)**

| Package | Responsibility |
|---------|----------------|
| `skillctl/artifact` | The pluggable artifact-repository abstraction: ER1, git forges and OCI registries are peers behind one `Backend`. The invariant across all of them is the content digest; everything else is a backend-native projection of the same SPEC-0190 event envelope. |
| `skillctl/artifact/conformance` | The backend-agnostic lifecycle suite every `artifact.Backend` must pass (D8), run against the git backend, the ER1 backend and the in-memory fake, so backend parity is a test rather than a claim. |
| `skillctl/backend/git` | Git registry backend (`github://` / `gitlab://` / `local://`), including the frozen Git Wire Format v1 on-disk contract. |
| `skillctl/backend/oci` | OCI-registry backend (D7): the `.skb` is a layer whose digest is its identity, lifecycle events ride as referrers. |
| `skillctl/artifactauth` | Read-only per-backend credential resolution (D5): env override, then the OS keychain. It never writes or deletes a credential store. |
| `skillctl/netguard` | The one audited "is this host provably local?" egress predicate that gates credentials and TLS-verification bypasses across the backends and the ER1 client. |

**Governance & evidence**

| Package | Responsibility |
|---------|----------------|
| `skillctl/outbox` | SPEC-0317 (P0) transactional audit outbox. |
| `skillctl/statemachine` | SPEC-0317 R-7 named offline state machine. |
| `skillctl/govlevel` | The one canonical governance-level vocabulary. |
| `skillctl/datascope` | Typed client-side contract for SPEC-0196. |
| `skillctl/bodyscan` | SPEC-0246 §4 semantic danger-prose detector. |
| `skillctl/exitcode` | Canonical registry of `skillctl` process exit codes. |
| `skillctl/auditevent` | SPEC-0403 audit-event foundation: the shared envelope, the sinks, and the dispatcher that decides what a failed write means (silent loss is not the default). |
| `skillctl/auditexport` | SPEC-0455 seam between the audit drain and a selectable sink: contract types plus the backend conformance suite (T-00; implementations arrive with T-01). |
| `skillctl/secfile` | Hardens the on-disk permissions of security-sensitive files. A no-op on Unix (0600 is enforced by the kernel); real DACL work on Windows, which does not honour the Unix perm bits. |

**Analysis, reporting & UI**

| Package | Responsibility |
|---------|----------------|
| `skillctl/audit` | Per-skill verdicts for `skillctl audit`. |
| `skillctl/consolidate` | Duplicate/orphan analysis over an inventory. |
| `skillctl/delta` | Diffs two inventories. |
| `skillctl/envreport` | SPEC-0428 skill-env reports: the ENV address (hashed host), the immutable per-environment report, and its collection from an `audit` run. Retention is the point, not collection. |
| `skillctl/report` | HTML + Markdown reports from inventories. |
| `skillctl/review` | Local HTTP server for reviewing delta reports. |
| `skillctl/browse` | Interactive D3.js skill-graph browser. |
| `skillctl/menubar` | macOS menu bar app for monitoring skillctl state. |
| `skillctl/sim` | The trust-plane simulation library behind [`skillctl-sim`](program-index): the transition system, the generated scenario corpus, and the oracle that compares each SPEC-derived prediction with the observed run. |

**Sibling top-level packages**

| Package | Responsibility |
|---------|----------------|
| `skillgate` | SPEC-0202 cooperative invocation gateway. |
| `skillbundle` | Deterministic packing of `.skb` skill bundles. |
## G. Other internal packages (`internal/*`)

The Thinking Engine internals that used to fill this section left the tree on
2026-09-17: the engine was an experiment and now lives in its own repository
(BUILD-AUDIT-0001, owner decision E-2a). What remains under `internal/` is the
one package the rest of the tree depends on.

| Package | Responsibility |
|---------|----------------|
| `internal/dbdriver` | Shared database-driver support. Used by `cmd/skillctl`, `pkg/skillctl/browse`, `pkg/skillctl/outbox`, `pkg/timetracking` and `pkg/tracking`, which is why it stayed when the engine went. |
