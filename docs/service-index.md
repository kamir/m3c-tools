---
layout: default
title: Service Index
---

# Service Index

**What stays running.** Long-lived processes in the `m3c-tools` ecosystem, each
paired with its **runtime wrapper**: the `deploy/*` stack, Dockerfile, compose
file, or MCP registration that turns a [program](program-index) into a running
service.

See also: [Program Index](program-index) · [Component Index](component-index).

## 1. skillctl Trust-Plane (container)

The pure-Go skill **trust plane** packaged as an OCI image, and `.skb` skill
bundles published to a registry (SPEC-0354). The capture-plane (recorder,
menubar: cgo + macOS-only) is deliberately **excluded**.

| Aspect | Detail |
|--------|--------|
| Program | `skillctl` (`cmd/skillctl/`) |
| Runtime wrapper | `deploy/skillctl/` (`Dockerfile` + `README.md`) |
| Build | `make skillctl-image` (`make skillctl-image-smoke` to verify) |

## 2. mcp-skill-server (Claude Code MCP)

Exposes the skill lifecycle as native Claude Code tools so the agent can browse,
query, import, and track skills.

| Aspect | Detail |
|--------|--------|
| Program | `mcp-skill-server/server.py` |
| Transport | stdio |
| Registration | `~/.claude/mcp.json` |
| Wraps | the `skillctl` Go CLI + aims-core REST API |

## 3. rag-mcp-server (Claude Code MCP)

Local, air-gapped semantic search over a GitHub-backed workspace (SPEC-0268):
the local twin of the ER1/aims-core memory search.

| Aspect | Detail |
|--------|--------|
| Program | `rag-mcp-server/rag_mcp_server.py` |
| Transport | stdio (also a `rag.py` CLI) |
| Engine | `turbovec` (TurboQuant) + local `BAAI/bge-m3` embedder: no data leaves the machine |
| State | per-repo, gitignored `.rag/` |
| Tools | `rag_search`, `rag_stats`, `rag_sync`, `rag_verify` |

## 4. Menu Bar App (desktop-resident)

A long-running macOS desktop service: the menu bar app with 4 capture channels,
the Observation Window pipeline, and ER1 upload.

| Aspect | Detail |
|--------|--------|
| Program | `m3c-tools --menubar` (production); `poc-menubar` (reference POC) |
| Launch | `make menubar` / `make menubar-app` |
| UI stack | `menuet` (menu bar) + native Cocoa via cgo |
| Details | [Menu Bar App](old/menubar-app) |

## External dependency: ER1 / aims-core

Not built in this repo, but the **server every capture flows into**. `m3c-tools`
uploads multimodal observations to it (`pkg/er1`) and both MCP servers query
it. Configure via `~/.m3c-tools.env`
(`ER1_API_URL` / `ER1_API_KEY` / `ER1_CONTEXT_ID`).
