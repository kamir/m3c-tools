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

## Project Time Tracking

m3c-tools maintains a per-project time ledger so you can see, retroactively,
how much time you spent on which project — even if you forgot to start a
timer. Two complementary mechanisms feed the ledger:

1. **Explicit sessions** — start/stop a project from the **Projects ▶**
   submenu. Time accumulates between activate and deactivate events.
2. **Reverse time tracking** — every observation you capture (transcript,
   screenshot, voice impulse, audio import) is examined; if its tags
   match a project, a 15-minute time block centred on the observation
   timestamp is added to that project automatically.

Both feed the same store (`~/.m3c-tools/timetracking.db`) and both are
visible in the Gantt chart (open via **Projects ▶ Show Time Tracker…**).

> **Specifications:**
> [SPEC-0007 — Project Time Tracking](https://github.com/kamir/m3c-tools-maintenance/blob/main/SPEC/SPEC-0007-project-time-tracking.md)
> covers the full design, including the requirements referenced below.

### How reverse tracking works

When you store an observation, the menubar app:

1. **Extracts the observation's tags** from the upload payload — built by
   `impression.BuildTags`, `BuildVideoTags`, or `ParseMetadataTags`
   depending on capture type.
2. **Compares those tags against every active/validating project** loaded
   from PLM (`~/.m3c-tools/timetracking.db`, refreshed every 5 minutes).
   Match priority (per [SPEC-0007 §REQ-9](https://github.com/kamir/m3c-tools-maintenance/blob/main/SPEC/SPEC-0007-project-time-tracking.md#req-9-reverse-time-tracking-observation-inferred-time-blocks)):

   | Strength | Trigger | Example |
   |---|---|---|
   | **Strong** | Observation tag `project:<slug>` matches a project's `<slug>` | Audio file `project_alpha_braindump.wav` → tag `project:alpha` → Project Alpha |
   | **Medium** | Observation tag `client:<name>` matches a project's `client` field or `client:<name>` tag | `ZOOM0001_client_acme.wav` → tag `client:acme` → ACME Onboarding |
   | **Weak** | ≥ 2 plain tags overlap between observation and project | `braindump,sprint,review` overlaps `sprint,review,agile` → Sprint Project |

3. **Picks the best-matching project.** Ties are broken by the project's
   `updated_at` (most recently active wins). If no project matches, no
   block is created and you'll see a `[reverse-tracking] no project
   match` line in the log — that's diagnostic, not an error.
4. **Creates an inferred time block** (15 min default, centred on the
   observation timestamp) with `trigger="observation_inferred"` and
   `content_ref=<doc_id>`. The Gantt chart renders inferred blocks with
   a semi-transparent fill and dashed border so they're visually distinct
   from explicit sessions.
5. **Skips if covered.** If you already had an explicit session active
   for the matched project at that timestamp, no inferred block is
   created — the explicit session already accounts for the time.
6. **Merges adjacent blocks.** Two inferred blocks for the same project
   that overlap or are within 5 minutes of each other are merged into
   one session, so a flurry of captures in 20 minutes shows up as a
   single 20-minute block, not five fragmented ones.

### Backfill — replaying past observations

Tag rules and project lists change over time. To make sure historical
observations still get credited when their target project is added or
re-tagged later, m3c-tools replays observations through the reverse
tracker on two triggers (per
[SPEC-0007 §REQ-10](https://github.com/kamir/m3c-tools-maintenance/blob/main/SPEC/SPEC-0007-project-time-tracking.md#req-10-reverse-tracking-backfill-observation-replay)):

| Trigger | Window |
|---|---|
| App start | All observations from the **current calendar month** |
| Gantt navigation | Observations from the period the user navigates to |

Replay is **idempotent** — observations already credited to a project
are skipped on re-run, so leaving the app to backfill repeatedly costs
nothing.

A typical startup log line:

```
[reverse-tracking] backfill 2026-04-01–2026-05-01: 41/41 observations processed
[reverse-tracking] startup backfill: processed 41 observations for April 2026
```

### How to make reverse tracking work for your captures

If reverse tracking is silent (lots of `no project match` lines, no
inferred blocks in the Gantt), the cause is almost always **tags don't
overlap**. Two ways to fix it:

1. **Add tags to the project record.** From your PLM project page, add
   tag terms that show up in your captures (e.g. add `nate's thoughts`,
   `scalytics strategy`, `s3` to the relevant project). The next refresh
   (≤ 5 min) plus the next backfill will pick them up.
2. **Tag your captures with project anchors.** Include a
   `project:<slug>` or `client:<name>` tag when you capture. Strong
   matches always win — one explicit anchor is more reliable than
   relying on weak overlap.

### Configuration

Per [SPEC-0007 §REQ-9](https://github.com/kamir/m3c-tools-maintenance/blob/main/SPEC/SPEC-0007-project-time-tracking.md#req-9-reverse-time-tracking-observation-inferred-time-blocks),
three environment variables tune the behaviour. Set them in your active
profile (`~/.m3c-tools/profiles/<name>.env`) or in `~/.m3c-tools/preferences.env`:

| Variable | Default | What it does |
|---|---|---|
| `M3C_REVERSE_BLOCK_ENABLED` | `true` | Master switch. Set `false` to disable inferred blocks entirely. |
| `M3C_REVERSE_BLOCK_DURATION` | `900` | Block size in seconds. 900 = 15 minutes centred on the observation. |
| `M3C_REVERSE_MIN_TAG_OVERLAP` | `2` | Minimum tag overlap for a weak match. Raising it makes the matcher pickier; lowering it produces more (potentially noisier) matches. |

### Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Projects submenu is empty | PLM auth failed at startup | `m3c-tools doctor` — the device-token / API-key check there will pinpoint it. See also [BUG-0124](https://github.com/kamir/m3c-tools-maintenance/blob/main/bug-reports/BUG-0124-menubar-no-projects-active-profile-placeholder-key.md) for the v2.7.0 fix. |
| Many `no project match` log lines, no inferred blocks | Project tag patterns don't overlap with capture tags | See "How to make reverse tracking work" above. |
| Inferred blocks appear at wrong project | Tag overlap is too generic | Add a `project:<slug>` anchor to either the project's tags or your capture tags — strong matches override weak overlap. |
| Profile is mis-configured (placeholder API key etc.) | Init wizard left a `once-only` / `minimal-key` placeholder | `m3c-tools config doctor` — the profile validator (see [SPEC-0177](https://github.com/kamir/m3c-tools-maintenance/blob/main/SPEC/SPEC-0177-profile-doctor.md)) flags placeholder keys, missing context ids, malformed URLs, and duplicate keys across profiles. |

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
