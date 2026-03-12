# m3c-tools

**Multi-Modal-Memory-Capturing Tools** — a macOS menu bar app and CLI for capturing observations (text + audio + image) and uploading them to an [ER1](https://er1.io) personal knowledge server.

---

## Quickstart (5 minutes)

### 1. Install prerequisites

```bash
brew install pkg-config portaudio ffmpeg    # build tools + audio
python3 -m pip install openai-whisper       # speech-to-text
```

Or: `make deps` (after cloning) to install everything at once.

Requires **Go 1.25+** and **macOS** (Cocoa UI via cgo).

> **First-run note:** Whisper downloads its language model on first use (~150 MB for `base`, ~1.5 GB for `medium`). This requires internet access.

### 2. Build and install

```bash
git clone https://github.com/kamir/m3c-tools.git
cd m3c-tools
make install
```

This builds the binary, creates `M3C-Tools.app`, installs both to `/usr/local/bin` and `/Applications`, and walks you through macOS permission setup (Microphone, Screen Recording).

### 3. Configure

```bash
cp .env.example ~/.m3c-tools.env
```

Edit `~/.m3c-tools.env` — the three required settings for ER1 upload:

```
ER1_API_URL=https://your-er1-server:8081/upload_2
ER1_API_KEY=your-api-key
ER1_CONTEXT_ID=your-context-id
```

**No local ER1 server?** Use the public instance for testing:

```
ER1_API_URL=https://onboarding.guide/upload_2
```

### 4. Launch

```bash
make menubar
```

Or open `/Applications/M3C-Tools.app`. A menu bar icon appears — you're ready to capture.

### 5. Try it

- **Fetch a transcript**: click the menu bar icon → *Fetch Transcript...* → paste a YouTube URL
- **Screenshot observation**: click *Capture Screenshot* → record a voice note → Store to ER1
- **CLI only**: `m3c-tools transcript dQw4w9WgXcQ --format srt`

---

## What does m3c-tools do?

m3c-tools captures four types of observations, each flowing through a shared pipeline:

```
Capture → Preview + Record → Whisper Transcribe → Tag Editor → Store to ER1
```

| Channel | Trigger | What it captures |
|---------|---------|------------------|
| **A — YouTube** | Paste video URL | Transcript + thumbnail + your voice comment |
| **B — Screenshot** | Menu item | Screenshot + voice note (uses clipboard image if present) |
| **C — Impulse** | Menu item | Interactive region capture + quick voice note |
| **D — Audio Import** | Menu item | Batch audio files from a folder (e.g. voice recorder sync) |

Each observation becomes a multimodal ER1 document: text transcript + audio recording + image, with tags and metadata.

---

## Configuration Reference

Settings are loaded from `.env` in the project root or `~/.m3c-tools.env`. See [`.env.example`](.env.example) for all options.

### Required for ER1 upload

| Variable | Description |
|----------|-------------|
| `ER1_API_URL` | ER1 upload endpoint URL |
| `ER1_API_KEY` | API key (sent as `X-API-KEY` header) |
| `ER1_CONTEXT_ID` | Your ER1 context/user identifier |

### Whisper (speech-to-text)

| Variable | Default | Description |
|----------|---------|-------------|
| `M3C_WHISPER_MODEL` | `base` | Model size: `tiny`, `base`, `small`, `medium`, `large` |
| `M3C_WHISPER_TIMEOUT` | `7200` | Transcription timeout in seconds |
| `YT_WHISPER_LANGUAGE` | `de` | Language code (ISO 639-1) |
| `M3C_WHISPER_PRELOAD` | `true` | Preload model at startup |

### Screenshot capture

| Variable | Default | Description |
|----------|---------|-------------|
| `M3C_SCREENSHOT_MODE` | `clipboard-first` | `clipboard-first` or `interactive` |
| `M3C_SCREENSHOT_CLIPBOARD_TIMEOUT_SEC` | `20` | Wait time for clipboard image |

### Audio import (Channel D)

| Variable | Default | Description |
|----------|---------|-------------|
| `IMPORT_AUDIO_SOURCE` | — | Source folder for audio files |
| `IMPORT_AUDIO_DEST` | `~/ER1` | Destination for MEMORY folders |
| `IMPORT_CONTENT_TYPE` | — | ER1 content-type label |

### ER1 tuning

| Variable | Default | Description |
|----------|---------|-------------|
| `ER1_UPLOAD_TIMEOUT` | `600` | HTTP timeout in seconds |
| `ER1_VERIFY_SSL` | `false` | TLS certificate verification |
| `ER1_RETRY_INTERVAL` | `300` | Seconds between retry cycles |
| `ER1_MAX_RETRIES` | `10` | Max retries before dropping |

---

## macOS App Bundle

m3c-tools ships as a native macOS `.app` bundle (`M3C-Tools.app`) that runs as a menu bar agent. The bundle includes:

- Go binary compiled with cgo (native Cocoa UI)
- App icon (`.icns` generated from `maindset_icon.png`)
- `Info.plist` with microphone and screen capture usage descriptions
- `LSUIElement = true` (menu bar agent — no Dock icon)

### Build the app bundle only

```bash
make build-app
# Result: build/M3C-Tools.app
```

### Install to /Applications

```bash
make install
```

This runs `build-app` and then:
1. Copies the CLI binary to `/usr/local/bin/m3c-tools`
2. Copies `M3C-Tools.app` to `/Applications/`
3. Creates `~/.m3c-tools/` data directory

### Grant macOS permissions

After installing, run:

```bash
make permissions
```

This opens each System Settings pane one at a time:

| Permission | Why |
|------------|-----|
| **Screen Recording** | Screenshot capture (Channels B & C) |
| **Microphone** | Voice recording for observations |
| **Accessibility** | Clipboard monitoring for screenshot detection |
| **Input Monitoring** | Keystroke capture for hotkey support |

Toggle **M3C-Tools** ON in each pane (click `+` to add if not listed).

### Launch

Double-click `/Applications/M3C-Tools.app`, or:

```bash
open /Applications/M3C-Tools.app
```

Or for development:

```bash
make menubar    # builds + launches directly (no install needed)
```

### Uninstall

```bash
make uninstall
```

Removes `/usr/local/bin/m3c-tools` and `/Applications/M3C-Tools.app`. Data at `~/.m3c-tools/` is preserved.

---

## Build & Test

```bash
make build          # Build CLI binary → ./build/m3c-tools
make build-app      # Build macOS .app bundle → ./build/M3C-Tools.app
make menubar        # Build + launch menu bar app (dev mode)
make install        # Full install: CLI + .app + data dir

make test-unit      # Offline unit tests
make ci             # Full CI: vet + lint + test + build
make test-network   # YouTube API tests (requires internet)
make test-er1       # ER1 integration tests (requires server)

make help           # Show all targets
```

Run a single test:

```bash
go test -v -count=1 ./e2e/ -run TestTranscriptFetch
```

---

## Architecture

```
cmd/m3c-tools/       CLI + menu bar app entry point
pkg/transcript/      YouTube InnerTube API client (pure Go, no API key)
pkg/er1/             ER1 upload client + retry queue
pkg/impression/      Composite document builder + tag system
pkg/whisper/         Whisper CLI subprocess wrapper
pkg/recorder/        PortAudio microphone recording (cgo)
pkg/screenshot/      macOS screenshot capture + clipboard detection
pkg/menubar/         Native Cocoa UI via cgo (NSWindow, NSTabView, etc.)
pkg/importer/        Batch audio import pipeline
pkg/tracking/        SQLite tracking database
```

## Documentation

Full documentation: **[kamir.github.io/m3c-tools](https://kamir.github.io/m3c-tools)**

- [Getting Started](https://kamir.github.io/m3c-tools/getting-started)
- [Menu Bar App](https://kamir.github.io/m3c-tools/menubar-app)
- [Roadmap](https://kamir.github.io/m3c-tools/roadmap)

## Uninstalling

```bash
make uninstall
```

Data at `~/.m3c-tools/` is preserved — remove manually if desired.

## License

See [LICENSE](LICENSE).
