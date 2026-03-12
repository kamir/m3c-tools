---
layout: default
title: Home
---

# M3C Tools — Multi-Modal Memory Capture

A native macOS toolkit for capturing multimodal observations (text + audio + image) and uploading them to an [ER1](https://er1.io) personal knowledge server. Built in Go with native Cocoa UI via cgo.

## Quickstart

```bash
brew install pkg-config portaudio ffmpeg
python3 -m pip install openai-whisper
git clone https://github.com/kamir/m3c-tools.git && cd m3c-tools
make install
cp .env.example ~/.m3c-tools.env   # edit with your ER1 credentials
make menubar                        # launch the menu bar app
```

## What's in the box?

| Component | What it does |
|-----------|-------------|
| **Menu Bar App** | macOS menu bar app with 4 capture channels, Observation Window, ER1 upload |
| **CLI** | `m3c-tools transcript` — fetch YouTube transcripts, manage imports, retry queue |
| **Transcript Library** | Pure Go port of youtube-transcript-api (no API key needed) |
| **Whisper Integration** | Local speech-to-text via whisper CLI subprocess |
| **ER1 Client** | Multipart upload to ER1 knowledge server with offline retry queue |
| **Audio Import** | Batch import from a folder with SQLite tracking and bulk re-processing |

## Capture Channels

All channels flow through the unified **Observation Window** pipeline:

```
Capture → Preview + Record → Whisper Transcribe → Tag Editor → Store / Cancel
```

| Channel | Trigger | Captures |
|---------|---------|----------|
| **A — YouTube** | Paste video URL/ID | Transcript + thumbnail + voice comment |
| **B — Screenshot** | Menu item | Screenshot + voice note (uses clipboard if present) |
| **C — Impulse** | Menu item | Interactive region capture + quick voice note |
| **D — Audio Import** | Menu item | Batch audio files from preconfigured folder |

Each observation becomes a multimodal ER1 document containing text, audio, and image with tags and metadata.

## Configuration

Copy `.env.example` to `~/.m3c-tools.env` and set at minimum:

```
ER1_API_URL=https://your-er1-server:8081/upload_2
ER1_API_KEY=your-api-key
ER1_CONTEXT_ID=your-context-id
```

See the [Getting Started](getting-started) guide for the full configuration reference.

---

**Documentation:**

- [Getting Started](getting-started) — install, configure, first use
- [Menu Bar App](menubar-app) — channels, Observation Window, menu items
- [Roadmap](roadmap) — current state, future work, ideas
