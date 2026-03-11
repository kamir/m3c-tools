---
layout: default
title: Menu Bar App
---

# M3C Tools — macOS Menu Bar App

A native macOS menu bar app for capturing multimodal observations. Built in Go using `caseymrm/menuet` for the menu bar and native Cocoa (NSWindow, NSTabView) via cgo for the Observation Window.

## Features

- Native macOS menu bar with custom icon
- 4 capture channels: YouTube, Screenshot, Impulse, Audio Import
- Unified **Observation Window** with 3 tabs: Record, Review, Tags
- Live VU meter with color-coded audio levels and dB readout
- Local Whisper transcription of voice recordings
- Multimodal ER1 uploads (image + audio + transcript)
- Offline retry queue with exponential backoff
- ER1 browser login linking (runtime context override)
- Transcript history (last 20 fetches)
- Draft saving on cancel (`~/.m3c-tools/drafts/`)
- Coordinated bulk ingestion lock + live progress for Audio Import/Re-process

## Installation

### Build and install

```bash
git clone https://github.com/kamir/m3c-tools.git
cd m3c-tools
make install
```

### Build from source only

```bash
make build-app
# Result: build/M3C-Tools.app
```

### Run without installing

```bash
make menubar
```

## Capture Channels

### Channel A — YouTube

1. Click **Fetch Transcript...** in the menu bar
2. Paste a YouTube URL or video ID
3. Transcript is fetched, thumbnail downloaded
4. **Observation Window** opens showing the thumbnail
5. Record a voice impression about the video
6. Review transcribed text, edit tags, Store or Cancel

### Channel B — Screenshot

1. Click **Capture Screenshot** in the menu bar
2. Screen is captured (clipboard-first, falls back to interactive)
3. **Observation Window** opens showing the screenshot
4. Record your observations about what you see
5. Review, tag, Store or Cancel

### Channel C — Quick Impulse

1. Click **Quick Impulse** in the menu bar
2. Interactive region selection appears
3. Capture a specific area of the screen
4. **Observation Window** opens
5. Record a quick voice note about the impulse
6. Review, tag, Store or Cancel

### Channel D — Audio Import

1. Click **Import Audio** in the menu bar
2. Scans preconfigured folder (`IMPORT_AUDIO_SOURCE`) for audio files
3. Shows tracked/new/uploaded status for each file
4. Select files to import
5. Each file is transcribed via Whisper and uploaded to ER1

### Bulk import/re-process UX

- Tracking DB window displays a live bulk progress strip:
  - determinate progress bar
  - current file + phase
  - success/failure counters
  - last error message
- Source table statuses are overlaid with in-flight states:
  - `queued`, `importing`, `transcribing`, `uploading`, `done`, `failed`, `skipped`
- Bulk buttons are disabled while a bulk session is active.
- During active bulk whisper/upload processing, other ingestion actions are blocked.

## Observation Window

The Observation Window is a native NSWindow with NSTabView, shared by all capture channels:

### Record Tab
- Captured image displayed (max 50% screen width/height)
- Live VU meter showing microphone input levels (green/yellow/red)
- Elapsed recording timer (MM:SS)
- Stop Recording button
- Window close (red X) = stop + "Keep this recording?" dialog

### Review Tab
- Metadata header: video ID, language, snippet count, char count
- Scrollable transcript text (editable)
- Recording details: duration, file size, sample rate

### Tags Tab
- Pre-filled tags per channel (editable comma-separated field)
- **[Store]** — upload to ER1 (queues on failure for retry)
- **[Cancel]** — save draft to `~/.m3c-tools/drafts/`, return to idle

## Menu Items

| Item | Action |
|------|--------|
| Status line | Current app state (Idle, Fetching, Recording...) |
| Fetch Transcript... | Channel A — YouTube |
| Capture Screenshot | Channel B — Screenshot |
| Quick Impulse | Channel C — Interactive region capture |
| Import Audio | Channel D — Batch audio import |
| Login to ER1... | Open ER1 login in Chrome |
| Logout from ER1 | Clear runtime ER1 session |
| History submenu | Last 20 transcripts (click to re-copy) |
| Open Log File | Opens `/tmp/m3c-tools.log` |
| Mein Nutzerkonto | Opens ER1 profile page in Chrome |

## Logs

```
/tmp/m3c-tools.log
```

Structured log prefixes: `[fetch]`, `[cache]`, `[store]`, `[auth]`, `[whisper]`, `[recorder]`

Bulk import/re-process lifecycle markers:

- `[bulk][RUN_START]`
- `[bulk][ITEM_START]`
- `[bulk][PHASE]`
- `[bulk][ITEM_DONE]`
- `[bulk][RUN_DONE]`

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

Back: [Getting Started](getting-started) | [Home](/)
