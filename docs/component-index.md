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
[G. Thinking Engine internals](#g-thinking-engine-internals-internalthinking)

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
| `session` | SPEC-0213 "session-state in ER1" — persist a working session as a machine-tagged memory item + checkpoint chain. |
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

The offline-verifiable skill **trust plane** — the library behind the
[`skillctl`](program-index) CLI. 30 focused subpackages, grouped by role:

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

**Lifecycle, admission & install**

| Package | Responsibility |
|---------|----------------|
| `skillctl/install` | SPEC-0188 §7 client install pipeline. |
| `skillctl/importer` | Talks to the aims-core skill-profile API. |
| `skillctl/registry` | HTTP client for the aims-core skill registry. |
| `skillctl/awareness` | SPEC-0195 admission bridge. |
| `skillctl/propose` | SPEC-0194 §6 ready-to-promote gate. |
| `skillctl/pin` | SPEC-0247 §7.3 managed-settings pinning. |

**Governance & evidence**

| Package | Responsibility |
|---------|----------------|
| `skillctl/outbox` | SPEC-0317 (P0) transactional audit outbox. |
| `skillctl/statemachine` | SPEC-0317 R-7 named offline state machine. |
| `skillctl/govlevel` | The one canonical governance-level vocabulary. |
| `skillctl/datascope` | Typed client-side contract for SPEC-0196. |
| `skillctl/bodyscan` | SPEC-0246 §4 semantic danger-prose detector. |
| `skillctl/exitcode` | Canonical registry of `skillctl` process exit codes. |

**Analysis, reporting & UI**

| Package | Responsibility |
|---------|----------------|
| `skillctl/audit` | Per-skill verdicts for `skillctl audit`. |
| `skillctl/consolidate` | Duplicate/orphan analysis over an inventory. |
| `skillctl/delta` | Diffs two inventories. |
| `skillctl/report` | HTML + Markdown reports from inventories. |
| `skillctl/review` | Local HTTP server for reviewing delta reports. |
| `skillctl/browse` | Interactive D3.js skill-graph browser. |
| `skillctl/menubar` | macOS menu bar app for monitoring skillctl state. |

**Sibling top-level packages**

| Package | Responsibility |
|---------|----------------|
| `skillgate` | SPEC-0202 cooperative invocation gateway. |
| `skillbundle` | Deterministic packing of `.skb` skill bundles. |
| `skillimport` | SPEC-0201 import-from-internet: `parser` (reference syntax), `policy` (source-policy files), `scanner` (pre-flight static scanner). |

## G. Thinking Engine internals (`internal/thinking/*`)

The 18 internal packages that make up the [Thinking Engine service](service-index).
Grouped by role in the T→R→I→A→C pipeline:

**Substrate**

| Package | Responsibility |
|---------|----------------|
| `thinking/schema` | Go types for every message on every topic. |
| `thinking/ctx` | Compile-time-safe wrapper around the user context / ctx hash. |
| `thinking/store` | Local SQLite engine state. |
| `thinking/kafka` | Kafka producer/consumer (in-memory bus, or franz-go under the `thinking_kafka` tag). |

**Cognitive pipeline (R/I/A/C)**

| Package | Responsibility |
|---------|----------------|
| `thinking/orchestrator` | Accepts a ProcessSpec; publishes lifecycle events. |
| `thinking/processors` | The R/I/A/C cognitive-layer processors. |
| `thinking/autoreflect` | Opt-in consumer that watches and triggers reflection. |
| `thinking/feedback` | Closes the cognitive loop from the I-processor. |

**LLM**

| Package | Responsibility |
|---------|----------------|
| `thinking/llm` | LLM adapter surface (OpenAI / Ollama). |
| `thinking/prompts` | Resolves prompt IDs to prompt bodies. |

**Persistence to ER1**

| Package | Responsibility |
|---------|----------------|
| `thinking/er1` | Thinking Engine's ER1 REST client. |
| `thinking/sink` | D2 async ER1 sinker. |

**Cost control**

| Package | Responsibility |
|---------|----------------|
| `thinking/budget` | D4 two-layer spend cap. |
| `thinking/ratelimit` | Keyed hourly limiter backed by the store. |

**Control, ops & recovery**

| Package | Responsibility |
|---------|----------------|
| `thinking/api` | Engine control surface (`/v1/*`). |
| `thinking/observability` | P0 operational surface (metrics/health). |
| `thinking/rebuild` | SPEC-0167 §Reconciler cold-start rebuild. |

**Other internal**

| Package | Responsibility |
|---------|----------------|
| `internal/dbdriver` | Shared database-driver support. |
