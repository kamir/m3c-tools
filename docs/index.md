---
layout: default
title: Home
---

# M3C Tools — Multi-Modal Memory Capture

A native macOS toolkit for capturing multimodal observations (text + audio + image) and uploading them to an ER1 personal knowledge server. Built in Go with native Cocoa UI via cgo.

## What's in the box?

| Component | What it does |
|-----------|-------------|
| **Menu Bar App** | macOS menu bar app with 4 capture channels, Observation Window, ER1 upload |
| **CLI** | `m3c-tools transcript` — fetch YouTube transcripts, manage imports, retry queue |
| **Transcript Library** | Pure Go port of youtube-transcript-api (no API key needed) |
| **Whisper Integration** | Local speech-to-text via whisper CLI subprocess |
| **ER1 Client** | Multipart upload to ER1 knowledge server with offline retry queue |

## Quick start

### Build from source

```bash
git clone https://github.com/kamir/m3c-tools.git
cd m3c-tools
make build
```

### Install (CLI + macOS .app bundle)

```bash
make install
```

This builds the binary, creates `M3C-Tools.app`, installs both, and walks you through macOS permission setup.

### Fetch a transcript (no key needed)

```bash
./build/m3c-tools transcript dQw4w9WgXcQ
```

### Run the menu bar app

```bash
make menubar
```

Or launch the installed app from `/Applications/M3C-Tools.app`.

---

## Capture Channels

| Channel | Trigger | Captures |
|---------|---------|----------|
| **A — YouTube** | Paste video URL/ID | Transcript + thumbnail + voice impression |
| **B — Screenshot** | Menu item | Screenshot + voice impression |
| **C — Impulse** | Menu item | Interactive region screenshot + voice impression |
| **D — Audio Import** | Menu item | Batch audio files from preconfigured folder |

All channels flow through the unified **Observation Window** pipeline: Capture → Record → Review → Tags → Store/Cancel.

---

Next: [Getting Started](getting-started) | [Menu Bar App](menubar-app)
