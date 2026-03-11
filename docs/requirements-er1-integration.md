---
layout: default
title: ER1 Integration — Requirements
---

# ER1 Integration — Requirements & Implementation

## Context

The project [audio-checklist-checker-py](https://github.com/kamir/my-ai-X) establishes a pattern for capturing audio impulses and pushing them into **ER1** — a personal knowledge/memory management system with a REST API. The workflow is:

```
Source (capture) → Metadata extraction → Whisper transcription
  → Composite document → ER1 API upload → Post-processing (Gemini, future)
```

M3C Tools brings this pattern to four capture channels: YouTube transcripts, screenshots, quick impulses, and batch audio import.

---

## Terminology

| Term | Definition |
|------|-----------|
| **ER1** | External memory/knowledge API at `https://127.0.0.1:8081/upload_2` (local) or `https://onboarding.guide/upload_2` (remote) |
| **Observation** | A multimodal capture: image + audio + transcript bundled as one ER1 entry |
| **Observation Window** | Native NSWindow with 3 tabs (Record, Review, Tags) for the unified capture pipeline |
| **context_id** | ER1 user/org identifier, set via `ER1_CONTEXT_ID` or runtime login |

---

## Requirements

### R1 — ER1 Upload (IMPLEMENTED)

**R1.1** The system uploads multimodal observations to ER1 via `POST /upload_2` with:
- Header: `X-API-KEY`
- Form fields: `context_id`, `content_type`, `tags`
- File attachments: `transcript_file_ext`, `audio_data_ext`, `image_data`

**R1.2** Failed uploads are queued in a persistent retry queue with exponential backoff.

**Implementation:** `pkg/er1/upload.go`, `pkg/er1/config.go`, `pkg/menubar/capture.go`

---

### R2 — Impression Capture (IMPLEMENTED)

**R2.1** All 4 capture channels flow through the unified Observation Window pipeline.

**R2.2** The composite transcript format:

```
=== VIDEO TRANSCRIPT ===
Title: {title}
Video ID: {video_id}
Language: {language_code}

{video_transcript_text}

=== USER IMPRESSION ===
Recorded: {timestamp}
Model: {whisper_model}

{user_voice_note_text}
```

**R2.3** Tags are pre-filled per channel and user-editable before upload:
- Channel A (YouTube): `youtube, <videoID>`
- Channel B (Screenshot): `idea, screenshot`
- Channel C (Impulse): `impulse`
- Channel D (Audio Import): `audio-import, transcript.provided, <filename-derived>`

**Implementation:** `pkg/impression/`, `pkg/menubar/observation_darwin.go`, `pkg/menubar/capture.go`

---

### R3 — Configuration (IMPLEMENTED)

ER1 connection settings via environment variables (`.env`):

| Variable | Default | Description |
|----------|---------|-------------|
| `ER1_API_URL` | `https://127.0.0.1:8081/upload_2` | ER1 upload endpoint |
| `ER1_API_KEY` | *(required)* | API key for ER1 authentication |
| `ER1_CONTEXT_ID` | `107677460544181387647___mft` | ER1 user/org context |
| `M3C_WHISPER_MODEL` | `base` | Whisper model for menu bar recordings |
| `M3C_WHISPER_TIMEOUT` | `120` | Whisper transcription timeout (seconds) |
| `IMPORT_AUDIO_SOURCE` | *(required for Channel D)* | Audio import source folder |
| `IMPORT_AUDIO_DEST` | `/Users/kamir/ER1` | Audio import destination |
| `YT_PROXY_URL` | *(optional)* | YouTube proxy for rate limit mitigation |
| `YT_PROXY_AUTH` | *(optional)* | Proxy authentication |

**Implementation:** `pkg/er1/config.go`, `.env.example`

---

### R4 — ER1 Login Linking (IMPLEMENTED)

**R4.1** Menu items: "Login to ER1..." and "Logout from ER1".

**R4.2** Login opens `<ER1_BASE_URL>/login/multi?next=<callback>` in Chrome. Local callback server captures `context_id` from redirect.

**R4.3** Runtime context override applied to all subsequent uploads.

**R4.4** Optional session persistence via `M3C_ER1_SESSION_PERSIST=true` (stored in `~/.m3c-tools/er1_session.json`).

**Implementation:** `pkg/menubar/app.go`, `cmd/m3c-tools/main.go`, `docs/feature-er1-login.md`

---

### R5 — Post-Processing (FUTURE)

**R5.1** The system SHOULD support tag-to-prompt mapping for post-processing via Gemini, following the `tag_promptKey_map` pattern from audio-checklist-checker.

**R5.2** Post-processing is out of scope for the current version but the architecture supports it (tags and structured composite documents are the integration points).

---

### R6 — Offline Resilience (IMPLEMENTED)

**R6.1** Failed ER1 uploads are enqueued in a JSON-backed persistent queue (`~/.m3c-tools/retry/`).

**R6.2** Background retry scheduler processes the queue with exponential backoff.

**R6.3** CLI commands: `m3c-tools schedule`, `m3c-tools status`, `m3c-tools cancel`.

**Implementation:** `pkg/er1/queue.go`, `pkg/tracking/`

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        User Interface                       │
│  ┌──────────────┐                    ┌───────────────────┐  │
│  │  Menu Bar App │                    │  CLI              │  │
│  │  (menuet+cgo)│                    │  (m3c-tools)      │  │
│  └──────┬───────┘                    └───────┬───────────┘  │
│         │                                    │              │
│  ┌──────┴────────────────────────────────────┴───────────┐  │
│  │              Observation Window (NSWindow+cgo)         │  │
│  │  Record → Review → Tags → Store/Cancel                │  │
│  └──────┬──────────────────┬──────────────────┬──────────┘  │
│         │                  │                  │              │
│  ┌──────┴───────┐  ┌──────┴───────┐  ┌───────┴──────────┐  │
│  │  ER1 Client   │  │  Whisper     │  │  YT Transcript   │  │
│  │  (pkg/er1)    │  │  (pkg/whisper)│  │  (pkg/transcript)│  │
│  └──────┬───────┘  └──────────────┘  └──────────────────┘  │
│         │                                                    │
└─────────┼────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────┐     ┌─────────────────────────────┐
│  Local Drafts/Cache  │     │  ER1 API                    │
│  ~/.m3c-tools/       │────▶│  POST /upload_2             │
│  drafts/ cache/ retry│     │  X-API-KEY authentication   │
└─────────────────────┘     └─────────────────────────────┘
```

---

## Go Package Structure

| Package | Purpose |
|---------|---------|
| `pkg/transcript/` | YouTube transcript API (fetch, list, format, proxy, errors) |
| `pkg/menubar/` | Menu bar app, Observation Window, capture pipeline |
| `pkg/er1/` | ER1 config, upload, reachability |
| `pkg/whisper/` | Whisper CLI subprocess wrapper |
| `pkg/impression/` | Observation types, tag system, composite documents |
| `pkg/screenshot/` | Clipboard + screencapture integration |
| `pkg/importer/` | Audio import scanner, filename parser |
| `pkg/recorder/` | PortAudio microphone recording |
| `pkg/tracking/` | Retry queue, file tracking DB |

---

Back: [Roadmap](roadmap) | [Home](/)
