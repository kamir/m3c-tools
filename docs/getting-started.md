---
layout: default
title: Getting Started
---

# Getting Started

## Prerequisites

- **macOS** (menu bar app uses native Cocoa via cgo)
- **Go 1.25+** (build from source)
- **PortAudio** — for microphone recording: `brew install portaudio`
- **Whisper** — for speech-to-text: `pip install openai-whisper` or `brew install openai-whisper`
- **ER1 server** (optional) — for uploading observations to your knowledge base

## Installation

```bash
git clone https://github.com/kamir/m3c-tools.git
cd m3c-tools
make install
```

This will:
1. Build the `m3c-tools` binary
2. Create `M3C-Tools.app` bundle with icon and Info.plist
3. Install CLI to `/usr/local/bin/m3c-tools`
4. Install app to `/Applications/M3C-Tools.app`
5. Walk you through macOS privacy permissions (Screen Recording, Microphone, Accessibility, Input Monitoring)

### Build without installing

```bash
make build       # CLI only → ./build/m3c-tools
make build-app   # CLI + .app bundle → ./build/M3C-Tools.app
```

## Configuration

Copy `.env.example` to your home directory:

```bash
cp .env.example ~/.m3c-tools.env
```

### Required settings (for ER1 upload)

| Variable | Purpose |
|----------|---------|
| `ER1_API_URL` | ER1 upload endpoint (e.g. `https://127.0.0.1:8081/upload_2`) |
| `ER1_API_KEY` | ER1 authentication key (sent as `X-API-KEY` header) |
| `ER1_CONTEXT_ID` | ER1 user/org context identifier |

### Optional settings

| Variable | Default | Purpose |
|----------|---------|---------|
| `M3C_WHISPER_MODEL` | `base` | Whisper model (tiny/base/small/medium/large) |
| `M3C_WHISPER_TIMEOUT` | `7200` | Transcription timeout in seconds |
| `YT_WHISPER_LANGUAGE` | `de` | Transcription language (ISO 639-1) |
| `M3C_SCREENSHOT_MODE` | `clipboard-first` | Screenshot mode (`clipboard-first` or `interactive`) |
| `IMPORT_AUDIO_SOURCE` | — | Audio import source folder (for Channel D) |
| `IMPORT_AUDIO_DEST` | `~/ER1` | Audio import destination folder |
| `YT_PROXY_URL` | — | HTTP/SOCKS5 proxy for YouTube (rate limit mitigation) |

See [`.env.example`](https://github.com/kamir/m3c-tools/blob/main/.env.example) for the complete list with descriptions.

## First use

### Launch the menu bar app

```bash
make menubar
```

Or open `/Applications/M3C-Tools.app`.

A menu bar icon appears. Click it to see the available actions.

### Fetch a transcript (CLI)

```bash
# Plain text
m3c-tools transcript dQw4w9WgXcQ

# SRT format
m3c-tools transcript dQw4w9WgXcQ --format srt

# List available languages
m3c-tools transcript dQw4w9WgXcQ --list

# Specify language
m3c-tools transcript dQw4w9WgXcQ --lang de
```

### Run tests

```bash
make test-unit      # Offline unit tests (no network, no hardware)
make ci             # Full CI (vet + lint + test + build)
make test-network   # YouTube API tests (requires internet)
make test-er1       # ER1 integration tests (requires running server)
```

## macOS Permissions

m3c-tools needs the following macOS permissions:

| Permission | Why | When prompted |
|------------|-----|---------------|
| **Microphone** | Voice recording for observations | First recording |
| **Screen Recording** | Interactive screenshot capture | First screenshot (interactive mode) |
| **Accessibility** | Clipboard monitoring for screenshot detection | First clipboard-first capture |

Grant these in **System Preferences → Privacy & Security**. The `make install` target walks you through this.

## Uninstalling

```bash
make uninstall
```

Or manually:
```bash
rm -f /usr/local/bin/m3c-tools
rm -rf /Applications/M3C-Tools.app
# Data preserved at ~/.m3c-tools/ — remove manually if desired
```

---

Next: [Menu Bar App](menubar-app) | [Home](/)
