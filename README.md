<div align="center">

# m3c-tools

### Give your agents a memory — and proof of what they're allowed to do.

**Multi-Modal-Memory Tools** is a personal, sovereign toolkit for turning everything you
see, hear and decide into durable, structured memory — and for governing the agent skills
that act on it. Two command-line tools, one repository, zero mandatory cloud middleman.

[![Latest release](https://img.shields.io/github/v/release/kamir/m3c-tools?sort=semver)](https://github.com/kamir/m3c-tools/releases/latest)
[![Platforms](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-blue)](#install)
[![Made with Go](https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go)](https://go.dev)

[Quickstart: m3c-tools](docs/quickstart-m3c-tools.md) ·
[Quickstart: skillctl](docs/quickstart-skillctl.md) ·
[Full manuals](#-documentation) ·
[Website](https://kamir.github.io/m3c-tools)

</div>

---

## Why this exists

Autonomous agents need two things you can't buy off the shelf:

1. **A memory of what actually happened** — not a chat log, but structured, multimodal,
   replayable observations that live on infrastructure *you* control.
2. **Proof of what they're allowed to do** — every skill an agent runs should carry a
   verifiable identity, be revocable on demand, and be checkable **offline**, with no
   external authority in the verification path.

This repository ships one focused tool for each half.

| Tool | The one-liner | You use it to… |
|------|---------------|----------------|
| **`m3c-tools`** | *The capture pipeline.* | Turn YouTube videos, audio, screenshots and voice notes into multimodal memory on your own [ER1](https://er1.io) knowledge server. |
| **`skillctl`** | *The capability plane.* | Sign, admit, verify and revoke the agent skills that read that memory and act — so nothing runs unless it's authorized and provable. |

`m3c-tools` fills the memory. `skillctl` governs the hands. Together they're the
personal-scale foundation for running agents you can actually trust in production.

---

## 60-second start

Pick the tool you came for. Both ship as single static binaries in every
[release](https://github.com/kamir/m3c-tools/releases/latest).

### `m3c-tools` — capture your first memory

```bash
# macOS (Apple Silicon) — see Install below for Intel / Linux / Windows
curl -sL https://github.com/kamir/m3c-tools/releases/latest/download/m3c-tools-darwin-arm64.tar.gz | tar xz \
  && sudo mv m3c-tools-darwin-arm64 /usr/local/bin/m3c-tools

m3c-tools setup                         # guided onboarding (ER1 URL, login, key)
m3c-tools transcript dQw4w9WgXcQ        # fetch a YouTube transcript, right now
m3c-tools doctor                        # verify connectivity & config
```

→ **Full walkthrough:** [Quickstart: m3c-tools](docs/quickstart-m3c-tools.md)

### `skillctl` — sign and verify your first skill

```bash
# macOS (Apple Silicon)
curl -sL https://github.com/kamir/m3c-tools/releases/latest/download/skillctl-darwin-arm64.tar.gz | tar xz \
  && sudo mv skillctl-darwin-arm64 /usr/local/bin/skillctl

skillctl keygen --out ~/.config/m3c/skill-keys/mykey            # ed25519 → mykey.priv + mykey.pub
skillctl pack --skill ./my-skill -o my-skill.skb --name my-skill --version 1.0.0
skillctl sign my-skill.skb --key ~/.config/m3c/skill-keys/mykey.priv
skillctl verify-sig my-skill.skb --pubkey ~/.config/m3c/skill-keys/mykey.pub   # offline, no server
```

→ **Full walkthrough:** [Quickstart: skillctl](docs/quickstart-skillctl.md)

---

## What `m3c-tools` captures

Four capture channels flow through one shared pipeline:

```
Capture → Preview + Record → Whisper transcribe → Tag editor → Store to ER1
```

| Channel | Trigger | What it captures |
|---------|---------|------------------|
| **A — YouTube** | Paste a video URL/ID | Transcript + thumbnail + your voice comment |
| **B — Screenshot** | Menu item | Screenshot + voice note (uses clipboard image if present) |
| **C — Impulse** | Menu item | Interactive region capture + quick voice note |
| **D — Audio Import** | Menu item / CLI | Batch audio from a folder (e.g. a voice recorder or Plaud/Pocket sync) |

Each observation becomes a multimodal ER1 document — text + audio + image, with tags and
metadata. On macOS this is a native menu-bar app; on Linux/Windows it's a full CLI.
Even without a transcript (e.g. subtitles disabled), a YouTube capture still keeps the
thumbnail and the link.

**Command surface:** `transcript`, `upload`, `whisper`, `thumbnail`, `record`, `screenshot`,
`import-audio`, `plaud`, `pocket`, `retry`, `schedule`, `status`, `doctor`, `login`,
`setup`, `menubar`. See the [m3c-tools manual](docs/manual-m3c-tools.md).

## What `skillctl` governs

`skillctl` is the trust-and-governance CLI for agent skills. It implements a full lifecycle
so a skill can be trusted end to end:

```
author → pack → sign → admit → attest → verify / install → use → audit → revoke
```

- **Offline-verifiable.** The trust-chain check needs no hosted CA in the verification path.
- **Revocable on demand.** Signed, offline revocation lists; freshness contracts, fail-closed.
- **Provable identity for agents.** `agentid` issues owner-signed mandates that verify offline.
- **Auditable.** A local transparency log (`translog`) and a Claude Code trust gate
  (`verify-hook`) that fails closed.

**Command surface:** `keygen`, `pack`, `sign`, `verify-sig`, `trust`, `install`, `verify`,
`attest`, `revoke`, `audit`, `publish`, `pull`, `registry`, `agentid`, `translog`,
`verify-hook`, `gate-stats`, `project`, `session`. See the [skillctl manual](docs/manual-skillctl.md).

---

## 📚 Documentation

| Page | For |
|------|-----|
| [**Quickstart: m3c-tools**](docs/quickstart-m3c-tools.md) | Capture your first memory in 5 minutes |
| [**Quickstart: skillctl**](docs/quickstart-skillctl.md) | Sign, install and verify a skill in 5 minutes |
| [**Manual: m3c-tools**](docs/manual-m3c-tools.md) | Every command, flag and config variable |
| [**Manual: skillctl**](docs/manual-skillctl.md) | The full trust lifecycle, command by command |
| [Menu Bar App](docs/menubar-app.md) | Channels, Observation Window, menu items (macOS) |
| [Platform differences](docs/PLATFORM-DIFFERENCES.md) | What works where |
| [Website](https://kamir.github.io/m3c-tools) | The rendered docs site |

---

## Install

Both binaries are attached to every [release](https://github.com/kamir/m3c-tools/releases/latest).
Swap `m3c-tools` ↔ `skillctl` in any one-liner below to install the other tool.

**macOS (Apple Silicon):**
```bash
curl -sL https://github.com/kamir/m3c-tools/releases/latest/download/m3c-tools-darwin-arm64.tar.gz | tar xz && sudo mv m3c-tools-darwin-arm64 /usr/local/bin/m3c-tools
```

**macOS (Intel):**
```bash
curl -sL https://github.com/kamir/m3c-tools/releases/latest/download/m3c-tools-darwin-amd64.tar.gz | tar xz && sudo mv m3c-tools-darwin-amd64 /usr/local/bin/m3c-tools
```

**Linux (amd64):**
```bash
curl -sL https://github.com/kamir/m3c-tools/releases/latest/download/m3c-tools-linux-amd64.tar.gz | tar xz && sudo mv m3c-tools-linux-amd64 /usr/local/bin/m3c-tools
```

**Windows:** download `m3c-tools-windows-amd64.zip` (or the `M3C-Tools-Setup.exe` installer)
from the [latest release](https://github.com/kamir/m3c-tools/releases/latest) and add it to your `PATH`.
See [Quickstart: m3c-tools](docs/quickstart-m3c-tools.md) for the PowerShell one-liner.

### Platform support

| Platform | CLI | Menu Bar | Audio Recording | Bridge Mode |
|----------|-----|----------|-----------------|-------------|
| macOS arm64 (Apple Silicon) | full | full GUI | full | yes |
| macOS amd64 (Intel) | full | full GUI | full | yes |
| Linux amd64 (Ubuntu) | full | — | — | yes |
| Linux arm64 (Jetson) | full | — | — | yes (relay) |
| Windows amd64 | full | — | — | — |

`skillctl` is CLI-only and runs identically on all five platforms.

---

## Build from source

Requires **Go 1.25+**. The macOS menu-bar GUI additionally needs `portaudio` + `ffmpeg` (cgo).

```bash
git clone https://github.com/kamir/m3c-tools.git && cd m3c-tools

make build          # build the m3c-tools CLI → ./build/m3c-tools
make build-all      # build the CLI + POC binaries
go build -o build/skillctl ./cmd/skillctl   # build skillctl

make install        # macOS: CLI + M3C-Tools.app + data dir + permission setup
make menubar        # macOS: build + launch the menu bar app (dev mode)

make test-unit      # offline unit tests
make vet            # go vet ./...
make help           # show all targets
```

---

## Architecture

```
cmd/m3c-tools/       m3c-tools CLI + macOS menu-bar app entry point
cmd/skillctl/        skillctl trust-&-governance CLI entry point
pkg/transcript/      YouTube InnerTube API client (pure Go, no API key)
pkg/er1/             ER1 upload client + retry queue + health check
pkg/impression/      Composite document builder + tag system
pkg/whisper/         Whisper CLI subprocess wrapper
pkg/recorder/        PortAudio microphone recording (cgo, macOS)
pkg/screenshot/      macOS screenshot capture + clipboard detection
pkg/menubar/         Native Cocoa UI via cgo (NSWindow, NSTabView, …)
pkg/importer/        Batch audio import pipeline
pkg/plaud/           Plaud.ai client + Chrome CDP auth
pkg/pocket/          Pocket capture-device sync
pkg/timetracking/    Project time tracking + Gantt chart + PLM client
```

Core logic (transcript, er1, impression) depends only on the Go standard library.

---

## The bigger picture

`skillctl` is the reference implementation of what we call the **capability plane** — one
plane of a *Sovereign Decision Fabric*: an architecture for running autonomous agents where
every decision is recorded and replayable, and every capability an agent holds is itself
authorized, provable, and revocable. This repo is the "ur-version" where that machinery is
built and battle-tested in the open.

## License

See [LICENSE](LICENSE).
