---
layout: default
title: "Feature Spec: Plaud.ai Integration"
---

# Feature Spec: Plaud.ai Integration

**Status:** Draft
**Date:** 2026-03-13
**Observation Type:** Import (Channel D) — extends existing audio import pipeline

## Problem

m3c-tools currently captures observations from YouTube (video transcripts), screenshots, voice recordings, and batch audio files. The user also captures field observations (customer visits, sales calls, consulting sessions) using a **Plaud.ai** voice recorder device. These recordings are uploaded to Plaud's cloud, transcribed, and summarized — but there is no way to pull them into the m3c-tools → ER1 knowledge pipeline.

The gap: field recordings captured via Plaud sit in a separate silo, disconnected from the user's ER1 knowledge base.

## Goal

Add a new capture source: **Plaud.ai cloud recordings**. The integration should:

1. List recent Plaud recordings (title, duration, date, status)
2. Download audio files (MP3/WAV)
3. Fetch Plaud-generated transcripts (with speaker diarization)
4. Build composite documents and upload to ER1 (same pipeline as other observation types)

## Plaud.ai API Landscape

### Option A: Official Partner API (docs.plaud.ai)

- **Base URLs:** `https://platform.plaud.ai/developer/api` (US), `https://platform-eu.plaud.ai/developer/api` (EU)
- **Auth:** OAuth2 — partner `client_id:secret_key` → partner access token → per-user token
- **Capabilities:** Submit audio for transcription, retrieve transcription results
- **Limitations:** No file listing, no audio download, no access to existing Plaud cloud recordings
- **Access:** Requires partner agreement with Plaud (contact support@plaud.ai)
- **Verdict:** Designed for SaaS partners embedding Plaud transcription — does NOT provide access to the user's own recording library

### Option B: Plaud Web API (unofficial, used by openplaud)

- **Base URLs:** `https://api.plaud.ai` (US), `https://api-euc1.plaud.ai` (EU)
- **Auth:** Bearer token extracted from web app localStorage (`tokenstr`)
- **Capabilities:** List files, download audio (MP3/WAV), fetch transcripts + AI summaries
- **Limitations:** Unofficial, token expires (needs periodic refresh), no documented rate limits
- **Access:** Any user with a plaud.ai account
- **Verdict:** Only option that provides access to the user's recording library

### Option C: Plaud SDK (iOS/Android)

- **Platforms:** iOS 13+, Android API 21+, React Native (Web/macOS/Windows: under development)
- **Capabilities:** Device discovery, recording control, file download, cloud processing
- **Limitations:** Requires physical device binding via BLE, mobile-only
- **Verdict:** Not suitable for desktop CLI/menu bar integration

### Recommendation

**Use Option B (Web API)** for initial integration. It's the only path that provides access to the user's existing recording library. Migrate to Option A (Partner API) if/when Plaud opens file listing + download endpoints for partners.

## Data Model

Each Plaud recording maps to an m3c-tools observation:

```
Plaud Recording                    m3c-tools Observation
─────────────────                  ──────────────────────
title                         →    observation title
audio file (MP3/WAV)          →    audio_data (ER1 field)
generated transcript          →    transcript text (composite doc)
AI summary                    →    commentary section (composite doc)
duration                      →    metadata tag
timestamp                     →    observation timestamp
speaker diarization           →    speaker labels in transcript
```

**Observation type:** New type `Fieldnote` (Channel E) or reuse `Import` (Channel D) with source tag `plaud`.

## Architecture

### New Package: `pkg/plaud/`

```
pkg/plaud/
├── client.go        # HTTP client for Plaud Web API
├── auth.go          # Token management (load, validate, refresh)
├── types.go         # API response types (FileList, Recording, Transcript)
└── config.go        # Plaud-specific config (.env variables)
```

### API Client

```go
type Client struct {
    BaseURL    string // e.g., https://api-euc1.plaud.ai
    Token      string // Bearer token from web app
    HTTPClient *http.Client
}

// Core methods
func (c *Client) ListRecentFiles(limit int) ([]Recording, error)
func (c *Client) GetRecording(fileID string) (*RecordingDetail, error)
func (c *Client) DownloadAudio(fileID string) ([]byte, string, error) // bytes, format, err
func (c *Client) GetTranscript(fileID string) (*Transcript, error)
```

### Data Types

```go
type Recording struct {
    ID        string
    Title     string
    Duration  time.Duration
    CreatedAt time.Time
    Status    string // "Generated", "Processing", etc.
}

type Transcript struct {
    Segments []Segment
    Summary  string // AI-generated summary
}

type Segment struct {
    Speaker   string
    StartTime float64
    EndTime   float64
    Text      string
}
```

### Integration Points

```
                    ┌─────────────┐
                    │  plaud.ai   │
                    │  Web API    │
                    └──────┬──────┘
                           │ Bearer token auth
                    ┌──────▼──────┐
                    │ pkg/plaud/  │
                    │  client.go  │
                    └──────┬──────┘
                           │ Recording + Transcript + Audio
              ┌────────────▼────────────────┐
              │  pkg/impression/            │
              │  CompositeDoc.Build()       │
              │  (title + transcript +      │
              │   speaker labels + summary) │
              └────────────┬────────────────┘
                           │ composite text + audio bytes
                    ┌──────▼──────┐
                    │  pkg/er1/   │
                    │  Upload()   │
                    └─────────────┘
```

### CLI Commands

```bash
# List recent Plaud recordings
m3c-tools plaud list [--limit 10]

# Import a specific recording → ER1
m3c-tools plaud import <file-id>

# Import all recent recordings since last sync
m3c-tools plaud sync [--since 2026-03-01]

# Store/refresh Plaud auth token
m3c-tools plaud auth <token>
```

### Menu Bar Integration

Add a new menu item under the existing menu:
- **"Plaud Sync"** — opens a list of recent Plaud recordings (like the "Recent files" view in the screenshot)
- Checkbox selection for which recordings to import
- "Import Selected" button → builds composite docs → uploads to ER1
- Status indicator showing sync state and last sync time

## Configuration

New `.env` variables:

```env
# Plaud.ai Integration
PLAUD_API_URL=https://api-euc1.plaud.ai    # EU region
PLAUD_TOKEN=<bearer-token>                   # From web app localStorage
PLAUD_AUTO_SYNC=false                        # Auto-sync on app launch
PLAUD_SYNC_INTERVAL=3600                     # Seconds between auto-syncs
```

### Token Extraction (One-Time Setup)

1. Log in to `https://web.plaud.ai`
2. Open browser DevTools → Application → Local Storage
3. Copy `tokenstr` value
4. Run: `m3c-tools plaud auth <token>`
5. Token stored in `~/.m3c-tools/plaud-session.json` (encrypted at rest, like ER1 session)

## Composite Document Format

```
═══════════════════════════════════════════
  FIELDNOTE: 02-11 Kundenbesuch: Erstkontakt Werkzeugbau
  Source: Plaud.ai | Duration: 1m 26s
  Recorded: 2026-02-12 19:44:41
═══════════════════════════════════════════

── AI Summary ──────────────────────────────
[Plaud-generated summary text here]

── Transcript (Speaker Diarized) ───────────
[Speaker 1] 00:00 - 00:23
Text of first speaker segment...

[Speaker 2] 00:23 - 00:45
Text of second speaker segment...

── Tags ────────────────────────────────────
#fieldnote #plaud #kundenbesuch #import
═══════════════════════════════════════════
```

## Implementation Phases

### Phase 1: CLI Read-Only (pkg/plaud + CLI commands)
- `pkg/plaud/` client with auth, list, get, download
- `m3c-tools plaud auth`, `plaud list`, `plaud import`
- Token storage in `~/.m3c-tools/plaud-session.json`
- Composite doc builder for Plaud recordings
- ER1 upload via existing `pkg/er1/`

### Phase 2: Menu Bar Integration
- "Plaud Sync" window in menu bar app
- List view matching Plaud's "Recent files" layout
- Checkbox multi-select + Import button
- Last sync time display

### Phase 3: Auto-Sync
- Background sync on configurable interval
- Dedup: skip recordings already uploaded (track by Plaud file ID in tracking DB)
- Notification on new recordings imported

## Cross-Platform Notes (ST-002)

- `pkg/plaud/` is pure Go HTTP client — **cross-platform ready** from day one
- Token extraction works in any browser (not macOS-specific)
- CLI commands work on Windows/Ubuntu/Android(gomobile) without changes
- Menu bar UI is platform-specific (Phase 2 follows ST-002 GUI framework choice)

## Testing Strategy

- **Unit tests:** Mock HTTP responses for list/get/download, composite doc formatting
- **Integration test:** Fetch real Plaud data with token (gated by `M3C_TEST_PLAUD=1`)
- **e2e:** Full pipeline: Plaud → composite → ER1 upload (gated by `M3C_TEST_PLAUD=1` + ER1 server)

## Open Questions

1. **Token refresh:** How long do Plaud web tokens last? Need to test expiry and re-auth flow.
2. **Rate limits:** Plaud web API rate limits are undocumented — need to add conservative backoff.
3. **Observation type:** New `Fieldnote` (Channel E) vs reuse `Import` (Channel D) with `source:plaud` tag?
4. **Partner API migration:** Worth applying for partner access to get stable, documented endpoints?
5. **Audio format:** Store original MP3 from Plaud or convert to WAV (whisper-compatible)?

## References

- [Plaud Developer Platform](https://www.plaud.ai/pages/developer-platform)
- [Plaud Partner API Docs](https://docs.plaud.ai/documentation/get_started/quickstart)
- [Plaud SDK (GitHub)](https://github.com/Plaud-AI/plaud-sdk)
- [OpenPlaud — self-hosted alternative](https://github.com/openplaud/openplaud)
- [Plaud Exporter Chrome Extension](https://github.com/josephhyatt/plaud-exporter)
- [Plaud Web Export Guide](https://support.plaud.ai/hc/en-us/articles/10976177688975)
