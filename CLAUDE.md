# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) and AI coding assistants when working with code in this repository.

## Project Overview

**m3c-tools** (Multi-Modal-Memory Tools) is a sovereign toolkit for turning observations into durable, structured memory and governing autonomous agent skills:

1. **`skillctl` (The Capability Plane)**: Agent trust, signing, verification, and governance CLI. Allows authors to package and sign skill bundles (`.skb`), operators to admit and attest skills, agents to verify identities offline, and security hooks to fail closed on unverified skills.
2. **`m3c-tools` (The Capture Pipeline)**: Captures transcripts (YouTube), screenshots, impulse notes, voice recordings (Whisper), Plaud/Pocket audio imports, and synchronizes them to an ER1 knowledge server.
3. **`skillctl-demo`**: Self-contained offline interactive demo and Kata training simulator.
4. **`thinking-engine`**: Kafka-based reasoning and event-processing worker (pure Go).
5. **MCP Servers**: Local FastMCP tools (`mcp-skill-server/`) and workspace RAG vector search (`rag-mcp-server/`).

---

## Build & Test Commands

```bash
# Build binaries
make build              # Build m3c-tools CLI → ./build/m3c-tools
make build-skillctl     # Build skillctl CLI → ./build/skillctl
make build-skillctl-demo# Build skillctl-demo CLI → ./build/skillctl-demo
make build-all          # Build CLI + skillctl + demo + POCs
make thinking-build     # Build thinking-engine → ./build/thinking-engine

# Code quality & tests
make vet                # go vet ./...
make lint               # golangci-lint run
make test-unit          # Fast offline unit tests
make ci                 # Full CI (vet + lint + test + build)

# Targeted test runs
go test -v -count=1 ./pkg/skillctl/...
go test -v -count=1 ./pkg/skillbundle/...
go test -v -count=1 ./pkg/skillgate/...
go test -v -count=1 ./pkg/er1/...

# GitLab & cross-platform builds
make gitlab-sync        # Push sanitized repository & tags to GitLab (192.168.0.135)
make build-windows      # Cross-compile for Windows
```

---

## Architecture & Subsystems

```
cmd/
  ├── m3c-tools/          # Multimodal capture CLI & macOS menu bar app
  ├── skillctl/           # Agent capability & trust governance CLI
  ├── skillctl-demo/      # Offline interactive demo & Kata runner
  ├── thinking-engine/    # Event-driven reasoning engine (Kafka)
  └── poc-*/              # Reference POC implementations
pkg/
  ├── skillctl/           # Skillctl subcommands, scan, trust, and verification logic
  ├── skillbundle/        # Skill bundle (.skb) pack, unpack, manifest, and digest computation
  ├── skillgate/          # Claude Code trust gate, signature verification, admission policies
  ├── er1/                # ER1 upload client, multipart encoding, retry queue
  ├── plaud/              # Plaud.ai sync client & token management
  ├── pocket/             # Pocket capture-device sync client
  ├── whisper/            # Whisper CLI subprocess runner
  ├── recorder/           # PortAudio microphone recording (cgo)
  ├── transcript/         # YouTube transcript InnerTube API parser
  ├── session/            # Session token and device registry management
  └── timetracking/       # Time tracking engine and PLM client
internal/
  └── thinking/           # Thinking engine core logic and Kafka drivers
```

---

## Configuration

Settings are loaded from `.env` or `~/.m3c-tools.env` (see [`.env.example`](.env.example)):
- `ER1_API_URL`, `ER1_API_KEY`, `ER1_CONTEXT_ID` — ER1 knowledge server connection
- `M3C_WHISPER_MODEL`, `M3C_WHISPER_LANGUAGE` — Whisper speech-to-text settings
- `GITLAB_REMOTE_URL` — Internal GitLab sync target (`git@192.168.0.135:ai-platform/m3c-tools.git`)

---

## Conventions & Rules

- **Zero-leaks policy**: Never commit personal filesystem paths, private developer configs (`.claude/`), or `.env` files.
- **Offline verification**: `skillctl` verification and policy checks must always run offline with no external authority in the critical verification path.
- **Cross-platform**: Core packages under `pkg/` must remain pure Go and compile with `CGO_ENABLED=0` across Linux, macOS, and Windows.
