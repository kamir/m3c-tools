# m3c-tools

**Multi-Modal-Memory-Capturing Tools** — a macOS CLI and menu bar app for fetching YouTube transcripts, capturing voice impressions, and uploading multimodal observations (text + audio + image) to an ER1 personal knowledge server.

## Quickstart

Install and launch in one line:

```bash
git clone https://github.com/kamir/m3c-tools.git && cd m3c-tools && make install
```

Then launch the menu bar app:

```bash
make menubar
```

Or run a single command:

```bash
make run ARGS="transcript dQw4w9WgXcQ --format srt"
```

## Features

- **Transcript fetching** — YouTube transcripts via InnerTube API (no API key needed), 4 output formats (Text, SRT, JSON, WebVTT), translation support
- **ER1 upload** — Multipart upload of transcript + thumbnail + audio to an ER1 knowledge server, with automatic retry queue
- **Voice recording** — 16kHz/16-bit mono WAV capture via PortAudio, whisper transcription
- **Screenshot capture** — Full screen, window, or region capture with clipboard-first detection
- **Menu bar app** — macOS menu bar integration with transcript fetch, screenshot, impulse, and ER1 upload workflows
- **Batch audio import** — Scan directories for audio files, track status in SQLite

## Observation Types

m3c-tools captures four types of observations, each following a shared pipeline: **capture → record voice note → whisper transcribe → review → upload to ER1**.

| Type | Channel | Trigger | Description |
|------|---------|---------|-------------|
| **Progress** | A | `upload <video_id>` | YouTube video transcript + thumbnail |
| **Idea** | B | Capture Screenshot | Clipboard-first: uses an existing clipboard image, or falls back to interactive region selection. For capturing something you're already looking at. |
| **Impulse** | C | Quick Impulse | Always launches interactive region selection. A faster, more intentional "grab and annotate" flow. |
| **Import** | D | `import-audio <dir>` | Batch audio file import from a directory |

After capture, **Idea** and **Impulse** share the same pipeline:

1. The Observation Window opens with the captured image in the **Record** tab
2. Record a voice note with a live VU meter
3. Whisper transcribes the audio; the result appears in the **Review** tab
4. Edit tags and notes in the **Tags** tab
5. **Store** uploads to ER1, or **Cancel** saves a local draft

## Requirements

- macOS (menu bar, screenshot, and recording features are macOS-only)
- Go 1.25+
- PortAudio (`brew install portaudio`)
- [whisper](https://github.com/openai/whisper) (optional, for voice transcription)

## Build & Test

```bash
make build          # Build CLI binary → ./build/m3c-tools
make build-all      # Build CLI + POC binaries
make build-app      # Build macOS .app bundle
make menubar        # Build and launch menu bar app

make test-unit      # Run offline tests
make ci             # Run full CI locally (vet + lint + test + build)

make release        # Release with patch version bump
make release-minor  # Release with minor version bump
make release-major  # Release with major version bump
```

Run `make help` for all available targets.

## Configuration

Copy `.env.example` to `.env` (or `~/.m3c-tools.env`) and set:

```
ER1_API_URL=https://your-er1-server/api
ER1_API_KEY=your-api-key
ER1_CONTEXT_ID=your-context-id
```

## License

See [LICENSE](LICENSE).
