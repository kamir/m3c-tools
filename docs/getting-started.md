---
layout: default
title: Getting Started
---

# Getting Started

## Prerequisites

- **Go 1.25+** (build from source)
- **macOS** (menu bar app uses native Cocoa via cgo)
- **PortAudio** — for microphone recording: `brew install portaudio`
- **Whisper** — for speech-to-text: `brew install openai-whisper` or install from [github.com/openai/whisper](https://github.com/openai/whisper)
- **ER1 server** (optional) — for uploading observations

## Installation

### From source

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

### Configuration

Copy `.env.example` to `.env` and fill in your settings:

```bash
cp .env.example .env
```

Key variables:

| Variable | Purpose | Required |
|----------|---------|----------|
| `ER1_API_URL` | ER1 upload endpoint | For uploads |
| `ER1_API_KEY` | ER1 authentication key | For uploads |
| `ER1_CONTEXT_ID` | ER1 user/org context | For uploads |
| `M3C_WHISPER_MODEL` | Whisper model (tiny/base/small/medium/large) | No (default: base) |
| `IMPORT_AUDIO_SOURCE` | Audio import source folder | For Channel D |
| `YT_PROXY_URL` | YouTube proxy URL (rate limit mitigation) | No |

## Usage

### 1. Fetch a transcript (CLI)

```bash
# Plain text
m3c-tools transcript dQw4w9WgXcQ

# JSON format
m3c-tools transcript dQw4w9WgXcQ --format json

# List available languages
m3c-tools transcript dQw4w9WgXcQ --list

# Specify language
m3c-tools transcript dQw4w9WgXcQ --lang de
```

### 2. Menu bar app

```bash
make menubar
# or
m3c-tools menubar
```

See the [Menu Bar App](menubar-app) page for full details.

### 3. Run tests

```bash
# Offline unit tests (no network, no hardware)
make test-unit

# Full CI (vet + lint + test + build)
make ci

# Network tests (YouTube API)
make test-network

# ER1 integration tests
make test-er1
```

---

Next: [Menu Bar App](menubar-app)
