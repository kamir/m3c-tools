---
layout: default
title: Service Index
---

# Service Index

**What stays running.** Long-lived processes in the `m3c-tools` ecosystem, each
paired with its **runtime wrapper** — the `deploy/*` stack, Dockerfile, compose
file, or MCP registration that turns a [program](program-index) into a running
service.

See also: [Program Index](program-index) · [Component Index](component-index).

## 1. m3c Thinking Engine

A per-user, event-driven **cognitive runtime** (SPEC-0167). Flask/aims-core does
the *sensing* (capture); this engine owns the *thinking*: it takes raw thoughts
off a stream and produces **Reflections → Insights → Artifacts** (the T→R→I→A→C
model) via an LLM, with a replayable, auditable log.

| Aspect | Detail |
|--------|--------|
| Program | `thinking-engine` (`cmd/thinking-engine/`) — see [Program Index](program-index) |
| Runtime wrapper | `deploy/thinking-engine/` |
| Listen / health | `:7140`, `GET /v1/health` |
| Launch (local) | `make thinking-up` → `make thinking-topics` → `make thinking-build` and run; or `tools/thinking-engine-start.sh` |
| Launch (container) | `docker compose -f deploy/thinking-engine/docker-compose.yml --profile engine up -d` |
| Isolation | Refuses to start without `--user-context-id`; every topic/group/HMAC claim derives from its `ctx_hash`; a runtime guard panics on cross-context topic access. |
| LLM backend | OpenAI, or **Ollama** for zero-cost local dev (`NewAdapterFromEnv`). |

**Runtime wrapper contents** (`deploy/thinking-engine/`):

| File | Role |
|------|------|
| `docker-compose.yml` | Phase-1 stack: Confluent `cp-*` broker set (zookeeper + broker + schema-registry + control-center, single broker RF=1) + the `engine` service (gated behind compose `profiles: [engine]`). Ports parameterized per user. |
| `Dockerfile` | Multi-stage build of the engine binary with the `thinking_kafka` tag (wires the real **franz-go** Kafka driver); static `CGO_ENABLED=0`, non-root Alpine, `<30 MB`. |
| `topic-bootstrap.sh` | Creates the **8 canonical topics** `m3c.<ctx_hash>.*` (thoughts.raw, reflections.generated, insights.generated, artifacts.created, process.commands, process.events, compilation.requests, context.snapshots). |
| `.env.example` | Per-user config template: `CTX_HASH`, `M3C_USER_CONTEXT_ID`, `THINKING_ENGINE_SECRET` (HMAC), per-user port allocation. |

Internals: [Component Index → Thinking Engine internals](component-index#g-thinking-engine-internals-internalthinking).

## 2. skillctl Trust-Plane (container)

The pure-Go skill **trust plane** packaged as an OCI image, and `.skb` skill
bundles published to a registry (SPEC-0354). The capture-plane (recorder,
menubar — cgo + macOS-only) is deliberately **excluded**.

| Aspect | Detail |
|--------|--------|
| Program | `skillctl` (`cmd/skillctl/`) |
| Runtime wrapper | `deploy/skillctl/` (`Dockerfile` + `README.md`) |
| Build | `make skillctl-image` (`make skillctl-image-smoke` to verify) |

## 3. mcp-skill-server (Claude Code MCP)

Exposes the skill lifecycle as native Claude Code tools so the agent can browse,
query, import, and track skills.

| Aspect | Detail |
|--------|--------|
| Program | `mcp-skill-server/server.py` |
| Transport | stdio |
| Registration | `~/.claude/mcp.json` |
| Wraps | the `skillctl` Go CLI + aims-core REST API |

## 4. rag-mcp-server (Claude Code MCP)

Local, air-gapped semantic search over a GitHub-backed workspace (SPEC-0268) —
the local twin of the ER1/aims-core memory search.

| Aspect | Detail |
|--------|--------|
| Program | `rag-mcp-server/rag_mcp_server.py` |
| Transport | stdio (also a `rag.py` CLI) |
| Engine | `turbovec` (TurboQuant) + local `BAAI/bge-m3` embedder — no data leaves the machine |
| State | per-repo, gitignored `.rag/` |
| Tools | `rag_search`, `rag_stats`, `rag_sync`, `rag_verify` |

## 5. Menu Bar App (desktop-resident)

A long-running macOS desktop service: the menu bar app with 4 capture channels,
the Observation Window pipeline, and ER1 upload.

| Aspect | Detail |
|--------|--------|
| Program | `m3c-tools --menubar` (production); `poc-menubar` (reference POC) |
| Launch | `make menubar` / `make menubar-app` |
| UI stack | `menuet` (menu bar) + native Cocoa via cgo |
| Details | [Menu Bar App](menubar-app) |

## External dependency — ER1 / aims-core

Not built in this repo, but the **server every capture flows into**. `m3c-tools`
uploads multimodal observations to it (`pkg/er1`), the Thinking Engine sinks
Artifacts to it (`internal/thinking/er1`, `internal/thinking/sink`), and both
MCP servers query it. Configure via `~/.m3c-tools.env`
(`ER1_API_URL` / `ER1_API_KEY` / `ER1_CONTEXT_ID`).
