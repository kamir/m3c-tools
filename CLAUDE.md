# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**m3c-tools** (Multi-Modal-Memory Tools) is a Go rewrite of a Python-based YouTube transcript toolkit. It fetches YouTube transcripts, captures voice impressions, and uploads multimodal observations (text + audio + image) to an ER1 personal knowledge server.

The core pipeline: **YouTube video → transcript + thumbnail → composite document → ER1 upload**.

Four observation types: Progress (YouTube video), Idea (screenshot), Impulse (quick note), Import (batch audio).

## Build & Test Commands

```bash
make build              # Build CLI → ./build/m3c-tools
make build-all          # Build CLI + 4 POC binaries
make vet                # go vet ./...

# Tests (all in e2e/ directory, no pkg-level unit tests)
make test-unit          # Offline-only tests (composites, tags, queue, WAV encoding)
make test-network       # Requires internet (transcript fetch, thumbnails)
make test-er1           # Requires running ER1 server
make test-whisper       # Requires whisper binary in PATH
make test-recorder      # Requires PortAudio + microphone
make e2e                # Run all e2e tests

# Run a single test
go test -v -count=1 ./e2e/ -run TestTranscriptFetch

# Run the CLI
make run ARGS="transcript dQw4w9WgXcQ --format srt"
```

## Architecture

### Data Flow

```
transcript.API.Fetch(videoID)  →  FetchedTranscript (snippets)
                                        ↓
                              impression.CompositeDoc.Build()  →  composite text
                                        ↓
transcript.Fetcher.FetchThumbnail()  →  JPEG bytes
                                        ↓
                              er1.Upload(config, payload)  →  ER1 server
                                        ↓ (on failure)
                              er1.Queue.Add(entry)  →  JSON file (retry later)
```

### Package Responsibilities

- **pkg/transcript/** — Complete port of Python's youtube-transcript-api. Uses YouTube's InnerTube API (no official API key needed). Handles: video page fetch → API key extraction → InnerTube POST → caption XML parsing → snippet extraction. Supports 4 output formats (Text, SRT, JSON, WebVTT), proxy configs, and 10+ error types. Also handles thumbnail fetching with size fallback.

- **pkg/er1/** — ER1 knowledge server integration. Multipart HTTP upload with `transcript_file_ext`, `audio_data_ext`, `image_data` fields. ER1 requires all three fields — system sends placeholder audio (1s silence WAV) or placeholder image (1x1 red PNG) when real data is unavailable. Includes JSON-backed retry queue with mutex synchronization.

- **pkg/impression/** — Composite document builder and tag system. Builds structured text documents combining video transcript + user commentary. Tags auto-generated from observation type.

- **pkg/whisper/** — Wraps the whisper CLI binary as a subprocess (not C bindings). Finds binary in PATH or standard locations, runs with `--output_format json`, parses segments.

- **pkg/recorder/** — PortAudio microphone recording via cgo. Records 16kHz/16-bit PCM mono WAV (whisper-compatible format).

### Entry Points

- **cmd/m3c-tools/** — Main CLI with subcommands: transcript, upload, whisper, thumbnail, check-er1, record, devices.
- **cmd/poc-*/** — Four validated proof-of-concept binaries (menubar, transcript, whisper, recorder). These are reference implementations, not production code.

### Key Technical Details

- **Zero external deps for core logic** — transcript, er1, impression packages use only Go stdlib. External deps (menuet, portaudio) are only for POC features.
- **InnerTube API**: Uses Android client context to avoid age-restriction issues. Must set `CONSENT=YES+cb` cookie. Must strip `&fmt=srv3` from caption baseUrl to get XML format.
- **PoToken check**: If caption URLs contain `&exp=xpe`, raise an error (YouTube anti-bot measure).
- **CLI flag parsing**: Uses manual `os.Args` parsing (no cobra/flag). Follow the existing pattern in `cmdTranscript()` when adding commands.

## Configuration

Settings loaded from `.env` or `~/.m3c-tools.env` (see `.env.example`). Key variables:
- `ER1_API_URL`, `ER1_API_KEY`, `ER1_CONTEXT_ID` — server connection
- `ER1_VERIFY_SSL` — set `false` for local dev with self-signed certs

## Current Status

Core MVP complete: transcript fetching, ER1 upload, composite docs, whisper, recording, thumbnails — all implemented and tested. Stubbed: `record` and `devices` CLI commands, background retry scheduler, menu bar integration into main binary, screenshot capture, batch audio importer.

See `docs/go-rewrite-plan.md` for the full migration spec and `docs/requirements-er1-integration.md` for ER1 requirements.
