# M3C Tools — Requirements

## Interview Decisions (2026-03-10)

| # | Question | Decision |
|---|---|---|
| Q1 | UI for Preview+Record | Custom Cocoa window via cgo |
| Q2 | Tag Editor UI | Custom Cocoa panel via cgo |
| Q3 | Implementation order | B (Screenshot) → A (YouTube) → D (Audio Import flagship) |
| Q4 | Audio Import file picker | Preconfigured folder scan (from `IMPORT_AUDIO_SOURCE`) |
| Q5 | Window close behavior | Stop recording + Ask "Keep this recording?" |
| Q6 | Recording feedback | Live VU meter (audio level visualization) |
| Q7 | Transcript display | Metadata header + scrollable full content |
| Q8 | Cancel behavior | Keep drafts in `~/.m3c-tools/drafts/` |
| Q9 | Window architecture | Single Observation Window with tabs: Record / Review / Tags |

---

## Observation Window (Core UI Component)

A single native **NSWindow** (built via cgo) that serves all capture channels.
Three tabs/pages, navigated via sidebar or tab bar:

```
┌──────────────────────────────────────────────────────────┐
│  Observation Window                              [─][□][×]│
├────────┬─────────────────────────────────────────────────┤
│        │                                                 │
│ Record │  ┌─────────────────────────────────┐            │
│        │  │                                 │            │
│ Review │  │   Captured Image                │            │
│        │  │   (max 50% screen w/h)          │            │
│  Tags  │  │                                 │            │
│        │  └─────────────────────────────────┘            │
│        │                                                 │
│        │  ████████░░░░  VU Meter                         │
│        │  ● Recording... 0:07                            │
│        │                                                 │
│        │              [🛑 Stop Recording]                │
│        │                                                 │
├────────┴─────────────────────────────────────────────────┤
│  Window close (×) = Stop + Ask "Keep this recording?"    │
└──────────────────────────────────────────────────────────┘
```

### Record Tab
- Shows captured image (screenshot/thumbnail) at max 50% screen size
- Live VU meter showing microphone input levels
- Elapsed timer (0:00, 0:01, ...)
- [🛑 Stop Recording] button
- Window close = stop + confirmation dialog

### Review Tab
- Metadata header: video ID, language, snippet count, char count, duration
- Scrollable full transcript/transcription text (NSTextView)
- Recording details: duration, file size, sample rate, peak amplitude

### Tags Tab
- Pre-filled tags displayed as editable field (comma-separated)
- Per-channel defaults:
  - A (YouTube): video ID, `"youtube"`, YT video tags
  - B (Screenshot): `"idea"`, timestamp
  - C (Impulse): `"impulse"`, timestamp
  - D (Audio Import): filename-derived tags, `"audio-import"`, `"transcript.provided"`
- [Store] → upload to ER1 (queue on failure)
- [Cancel] → save to `~/.m3c-tools/drafts/`, return to idle

---

## Unified Main Flow

All capture channels follow the same 4-step pipeline:

```
┌─────────────────────────────────────────────────────────────┐
│  STEP 1: CAPTURE                                            │
│                                                             │
│  Channel A: YouTube      → fetch transcript + thumbnail     │
│  Channel B: Screenshot   → capture screen (clipboard-first) │
│  Channel C: Quick Impulse → interactive region screenshot   │
│  Channel D: Audio Import → scan preconfigured folder        │
└──────────────────────────┬──────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  STEP 2: OBSERVATION WINDOW — Record Tab                    │
│                                                             │
│  • Open Observation Window showing captured image           │
│  • Image: max 50% screen w/h, original if smaller           │
│  • Live VU meter + elapsed timer                            │
│  • User speaks to describe the scene                        │
│  • [🛑 Stop] or window close (→ ask "Keep?")               │
│  • User-controlled duration (no fixed timer, 120s safety)   │
└──────────────────────────┬──────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  STEP 3: OBSERVATION WINDOW — Review Tab (auto-switch)      │
│                                                             │
│  • Transcribe recorded audio via local whisper              │
│  • Show progress: "Transcribing..." with spinner            │
│  • Log: whisper START/DONE with timing + char count         │
│  • Display: metadata header + scrollable full transcript    │
│  • For Audio Import: whisper runs on the imported file      │
│  • Graceful degradation: continue without text on failure   │
└──────────────────────────┬──────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  STEP 4: OBSERVATION WINDOW — Tags Tab (auto-switch)        │
│                                                             │
│  • Pre-filled tags (per channel)                            │
│  • Editable tag field                                       │
│  • [Store] → upload to ER1 (queue on failure)               │
│  • [Cancel] → save draft to ~/.m3c-tools/drafts/            │
│  • FINAL GATE — nothing uploads without user confirmation   │
└─────────────────────────────────────────────────────────────┘
```

---

## Requirements

### REQ-1: Observation Window — Record Tab (Step 2)
- Custom Cocoa NSWindow via cgo with NSImageView, VU meter, timer, Stop button
- Image sizing: max 50% of screen width and height; original if smaller
- Live audio level visualization (VU meter bar)
- Elapsed recording timer
- Window close = stop + ask "Keep this recording?"
- Implementation: `pkg/menubar/observation_darwin.go`
- Status: PENDING

### REQ-2: Audio file import — configurable properties and flow (Channel D)
Replicate the Python audio import pipeline in Go.

#### Import flow:
1. Scan `IMPORT_AUDIO_SOURCE` folder for `.mp3` / `.wav` files
2. Extract timestamp from filename pattern: `<tags> YYYY-MM-DD HH-MM-SS.mp3`
3. Parse tags from hyphen-separated prefix (strip optional `RECORDING-` prefix)
4. Prepend fixed tag `"transcript.provided"` to derived tags
5. Copy file to `<IMPORT_AUDIO_DEST>/MEMORY-YYYYMMDD_HHMMSS/`
6. Open Observation Window → Steps 2-4 of unified flow
7. Track processed file in tracker (append filename)

#### Configurable properties (all via `.env` + UI):
| Property | Env var | Default |
|---|---|---|
| Source folder | `IMPORT_AUDIO_SOURCE` | `/Users/kamir/GDMirror/GCP-AUDIO-TRANSCRIPT-SERVICE` |
| Dest base folder | `IMPORT_AUDIO_DEST` | `/Users/kamir/ER1` |
| API key | `ER1_API_KEY` | (none) |
| Upload URL | `ER1_API_URL` | `https://127.0.0.1:8081/upload_2` |
| Context ID | `ER1_CONTEXT_ID` | `107677460544181387647___mft` |
| Content type | `IMPORT_CONTENT_TYPE` | `Audio-Track vom Diktiergerät` |
| Tracker file | `IMPORT_TRACKER_FILE` | `~/.m3c-tools/transcript_tracker.md` |

#### Selection: Preconfigured folder scan with tracked/untracked status

- Status: PENDING

### REQ-3: YT API rate limit protection in tests
- Run only ONE test against the YouTube API by default (transcript retrieval)
- All other YT API tests are skipped unless `--yt-calls-enforce-all` flag is passed
- Status: PENDING

### REQ-4: Better transcript fetch logging (Step 1 + Step 3)
- On success: log video ID, snippet count, character count, language, fetch duration
- On failure: log precise error with context (HTTP status, rate limit info, etc.)
- Example:
  ```
  [fetch] START video=uWdIgftpvBI lang=en
  [fetch] DONE in 1.2s: 342 snippets, 28401 chars, language=English (en), generated=true
  ```
- Status: PENDING

### REQ-5: Observation Window — Tags Tab (Step 4)
- Final gate before any ER1 upload — unified across all channels
- Metadata header + scrollable full transcript
- Pre-filled tags (per channel) + editable tag field
- **[Store]** → upload to ER1 (queues on failure)
- **[Cancel]** → save draft to `~/.m3c-tools/drafts/`, return to idle
- Status: PENDING

---

## Implementation Order

1. **REQ-3** + **REQ-4** — Quick wins (test protection + logging)
2. **REQ-1** — Observation Window cgo scaffold (Record tab for Channel B)
3. **REQ-5** — Tags tab (completes Channel B end-to-end)
4. Wire Channel A (YouTube) through Observation Window
5. **REQ-2** — Audio Import (Channel D flagship)
