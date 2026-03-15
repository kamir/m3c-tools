# m3c-tools

**Multi-Modal-Memory-Capturing Tools** — a macOS menu bar app and CLI for capturing observations (text + audio + image) and uploading them to an [ER1](https://er1.io) personal knowledge server.

---

## Install (one-liner)

**macOS (Apple Silicon):**
```bash
curl -sL https://github.com/kamir/m3c-tools/releases/latest/download/m3c-tools-darwin-arm64.tar.gz | tar xz && sudo mv m3c-tools-darwin-arm64 /usr/local/bin/m3c-tools
```

**macOS (Intel):**
```bash
curl -sL https://github.com/kamir/m3c-tools/releases/latest/download/m3c-tools-darwin-amd64.tar.gz | tar xz && sudo mv m3c-tools-darwin-amd64 /usr/local/bin/m3c-tools
```

**Linux (Ubuntu/Debian):**
```bash
curl -sL https://github.com/kamir/m3c-tools/releases/latest/download/m3c-tools-linux-amd64.tar.gz | tar xz && sudo mv m3c-tools-linux-amd64 /usr/local/bin/m3c-tools
```

**Windows (PowerShell — run as Administrator):**
```powershell
# Download and install to C:\m3c-tools
New-Item -ItemType Directory -Force -Path C:\m3c-tools
Invoke-WebRequest -Uri https://github.com/kamir/m3c-tools/releases/latest/download/m3c-tools-windows-amd64.zip -OutFile "$env:TEMP\m3c-tools.zip"
Expand-Archive -Path "$env:TEMP\m3c-tools.zip" -DestinationPath C:\m3c-tools -Force
Rename-Item C:\m3c-tools\m3c-tools-windows-amd64.exe C:\m3c-tools\m3c-tools.exe -Force

# Add to system PATH (requires restart of terminal)
$oldPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($oldPath -notlike "*C:\m3c-tools*") {
    [Environment]::SetEnvironmentVariable("PATH", "$oldPath;C:\m3c-tools", "Machine")
}
```

After installation, **open a new PowerShell window** and verify: `m3c-tools help`

### Platform support

| Platform | Install | CLI | Menu Bar | Audio Recording | Bridge Mode |
|----------|---------|-----|----------|-----------------|-------------|
| macOS arm64 (Apple Silicon) | one-liner | full | full GUI | full | yes |
| macOS amd64 (Intel/iMac) | one-liner | full | full GUI | full | yes |
| Linux amd64 (Ubuntu) | one-liner | full | — | — | yes |
| Linux arm64 (Jetson) | one-liner | full | — | — | yes (relay) |
| Windows amd64 | one-liner | full | — | — | — |

---

## Quickstart (5 minutes)

### 1. Install prerequisites (macOS full build from source)

```bash
brew install pkg-config portaudio ffmpeg    # build tools + audio
python3 -m pip install openai-whisper       # speech-to-text
```

Or: `make deps` (after cloning) to install everything at once.

Requires **Go 1.25+** and **macOS** (Cocoa UI via cgo).

> **First-run note:** Whisper downloads its language model on first use (~150 MB for `base`, ~1.5 GB for `medium`). This requires internet access.

> **Windows/Linux users:** Use the one-liner install above — no build from source needed.

### 2. Build and install

```bash
git clone https://github.com/kamir/m3c-tools.git
cd m3c-tools
make install
```

This builds the binary, creates `M3C-Tools.app`, installs both to `/usr/local/bin` and `/Applications`, and walks you through macOS permission setup (Microphone, Screen Recording).

### 3. Configure

**Guided setup (recommended):**

```bash
m3c-tools setup
```

The wizard walks you through:
1. ER1 server URL (defaults to `https://onboarding.guide/upload_2`)
2. Browser login — opens Chrome, captures your User ID automatically
3. API key — you'll need an ER1 API key (get one from your ER1 admin)
4. Default tags for Plaud sync

This writes `~/.m3c-tools.env` with all required settings.

**Manual setup** (if you prefer):

```bash
cp .env.example ~/.m3c-tools.env
```

Edit `~/.m3c-tools.env`:

```
ER1_API_URL=https://onboarding.guide/upload_2
ER1_API_KEY=your-api-key
ER1_CONTEXT_ID=your-context-id
```

> **Note:** An API key is required for uploads. The browser login flow captures your User ID (context), but all API calls (upload, project list) authenticate via `X-API-KEY` header. You cannot use Google login alone — ask your ER1 admin for an API key.

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

## Cross-Platform CLI (Windows, Linux, Jetson)

On non-macOS platforms, m3c-tools runs in CLI-only mode (no menu bar GUI):

```bash
m3c-tools setup                  # Interactive onboarding wizard
m3c-tools plaud auth login       # Authenticate with Plaud (auto-launches Chrome)
m3c-tools plaud list             # List all Plaud recordings
m3c-tools plaud sync all         # Sync all recordings to ER1
m3c-tools transcript <video_id>  # Fetch YouTube transcript
m3c-tools check-er1              # Verify ER1 connectivity
```

### Plaud auth (all platforms)

`plaud auth login` works on macOS, Windows, and Linux. It auto-launches Chrome (or Edge) with remote debugging, opens `app.plaud.ai`, and extracts the auth token after you log in. No manual Chrome flags needed. On macOS, it can also extract the token directly from a running Chrome via AppleScript (no debug port needed).

### Context Processor Bridge (macOS / Ubuntu only)

An iMac or Ubuntu box can serve as a dedicated batch processing node for transcription and bulk ingestion. Windows is **desktop interaction mode only** — no bridge mode.

```bash
# One-command bridge setup (macOS or Ubuntu):
curl -sL https://raw.githubusercontent.com/kamir/m3c-tools-maintenance/master/scripts/setup-bridge.sh | bash

# Then:
m3c-tools import-audio ~/m3c-inbox/ --run    # Batch-transcribe
m3c-tools import-audio retry                  # Retry failed uploads
m3c-tools plaud sync all                      # Sync all Plaud recordings
```

Setup details: [scripts/setup-bridge.sh](https://github.com/kamir/m3c-tools-maintenance/blob/master/scripts/setup-bridge.sh) | Hardware planning: [SPEC-0018](https://github.com/kamir/m3c-tools-maintenance/blob/master/SPEC/SPEC-0018-jetson-nano-whisper.md)

---

## Architecture

```
cmd/m3c-tools/       CLI + menu bar app entry point
  main.go            macOS: full GUI + CLI
  main_other.go      Windows/Linux: CLI only
pkg/transcript/      YouTube InnerTube API client (pure Go, no API key)
pkg/er1/             ER1 upload client + retry queue + health check
pkg/impression/      Composite document builder + tag system
pkg/whisper/         Whisper CLI subprocess wrapper (heartbeat, progress)
pkg/recorder/        PortAudio microphone recording (cgo, macOS only)
pkg/screenshot/      macOS screenshot capture + clipboard detection
pkg/menubar/         Native Cocoa UI via cgo (NSWindow, NSTabView, etc.)
pkg/importer/        Batch audio import pipeline
pkg/tracking/        SQLite tracking database
pkg/plaud/           Plaud.ai client + Chrome CDP auth
pkg/timetracking/    Project time tracking + Gantt chart
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
