---
layout: default
title: Architecture
---

# Architecture

## Package Structure

```
cmd/m3c-tools/main.go    — CLI entry point, menu bar wiring, observation pipeline
pkg/
  menubar/                — macOS menu bar app (menuet), Observation Window (Cocoa/cgo)
    app.go                — App struct, menu items, action dispatch
    observation_darwin.go — NSWindow with 3 tabs (Record/Review/Tags) via cgo
    fetch.go              — YouTube transcript fetcher with cache + proxy + graceful 429
    cache.go              — Local transcript cache (~/.m3c-tools/cache/)
  transcript/             — YouTube transcript API (InnerTube, no API key needed)
    api.go                — Fetch, List, FetchTranslated, FetchThumbnail
    fetcher.go            — HTTP client with cookie jar, proxy support
    proxy.go              — Generic + Webshare proxy configs
  recorder/               — PortAudio microphone capture (16kHz/16-bit/mono WAV)
  whisper/                — whisper CLI wrapper for audio transcription
  screenshot/             — macOS screencapture CLI wrapper + clipboard detection
  er1/                    — ER1 server upload client (multipart, retry queue)
  impression/             — CompositeDoc builder for observation payloads
  importer/               — Batch audio file scanner + tracking DB
  tracking/               — SQLite tracking for exports and imports
```

## Observation Pipeline

All four channels follow the same flow:

```
Capture → Observation Window → Record → Review → Store/Cancel
```

### Channel Flow

1. **Capture**: Channel-specific acquisition (screenshot, YouTube fetch, etc.)
2. **Record tab**: Shows captured image + live VU meter + timer during voice recording
3. **Review tab**: Whisper transcription → structured memo text (editable)
4. **Tags tab**: Pre-filled tags per channel → Store uploads to ER1, Cancel saves draft

### Cocoa UI via cgo

The Observation Window is a native `NSWindow` with `NSTabView`, built in Objective-C inside cgo comment blocks in `observation_darwin.go`. Key patterns:

- **`dispatch_sync`** (not `dispatch_async`) for all UI operations — prevents use-after-free with Go's `defer C.free()`
- **`setHidesOnDeactivate:NO`** — prevents LSUIElement apps from losing windows on deactivation
- **Activation policy switching** — `Regular` when window is open, `Accessory` when closed

### Rate Limit Mitigation (YouTube)

Three layers protect against YouTube 429 errors:

1. **Local cache** — `~/.m3c-tools/cache/transcripts/<videoID>.json` (7-day TTL)
2. **Proxy support** — `YT_PROXY_URL` env var routes through SOCKS5/HTTP proxy
3. **Graceful degradation** — on 429, proceeds with thumbnail + voice note, no transcript

### ER1 Upload

On successful upload, the response `DocID` is used to build and open the item URL:
```
<ER1_API_URL base>/memory/<ER1_CONTEXT_ID>/<DocID>
```

Failed uploads are queued to `~/.m3c-tools/queue.json` with exponential backoff retry.

---

Next: [Getting Started](getting-started) | [Roadmap](roadmap)
