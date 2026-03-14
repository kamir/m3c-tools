---
layout: default
title: "SPEC: Plaud ↔ ER1 Sync Pipeline"
---

# SPEC: Plaud ↔ ER1 Sync Pipeline

**Status:** Implemented (Phase 1 + 2), Phase 3 planned
**Date:** 2026-03-13
**Supersedes:** Sync section of `feature-plaud-integration.md`

## Overview

The Plaud sync pipeline moves field recordings from Plaud.ai cloud into the ER1 knowledge server via a local staging folder (`~/plaud-sync/`). The pipeline has three stages, each independently resumable:

```
  Plaud.ai Cloud          Local Staging           ER1 Server
  ──────────────          ─────────────           ──────────
  97 recordings    ──→    ~/plaud-sync/     ──→   ER1 upload
  (audio + tx)       ①    per-recording/      ②   (multipart)
                          folders                  composite doc
                                                   + audio + image
```

**Stage 1 (Plaud → Local):** Download audio + fetch transcript/summary from Plaud API, save to local folder.
**Stage 2 (Local → ER1):** Build composite fieldnote document, upload to ER1 with audio.
**Stage 3 (State Tracking):** Record sync state in tracking DB for deduplication and re-upload.

## Data Flow

### Stage 1: Plaud Cloud → Local (`~/plaud-sync/`)

For each recording in the Plaud cloud:

1. **List recordings** via `GET /file/simple/web?skip=0&limit=100&is_trash=2&is_desc=true`
2. **Download audio** via `GET /file/download/<id>` → raw OGG (Opus codec)
3. **Fetch detail** via `GET /file/detail/<id>` → `content_list[]` with signed S3 URLs
4. **Fetch transcript** from S3 `trans_result.json.gz` (if `is_trans=true`)
5. **Fetch summary** from S3 `outline_result.json.gz` (if `is_summary=true`)
6. **Save locally** to `~/plaud-sync/<recording_id>/`

#### Local Folder Structure

```
~/plaud-sync/
├── 52949d168dc74f953779a8310dbe009f/
│   ├── audio.ogg              # Original Plaud audio (Opus/OGG)
│   ├── fieldnote.txt          # Composite document (ready for ER1)
│   ├── transcript.txt         # Raw transcript text (or placeholder)
│   └── metadata.json          # Recording metadata + sync state
├── 3dc1eb8d83fd45e397cd0fe4695babb1/
│   ├── audio.ogg
│   ├── fieldnote.txt
│   ├── transcript.txt         # "[No transcript available — audio only]"
│   └── metadata.json
└── ...
```

#### metadata.json Schema

```json
{
  "recording_id": "52949d168dc74f953779a8310dbe009f",
  "title": "02-04 Abwicklung einer Fehllieferung",
  "duration": 41,
  "created_at": "2026-02-04T14:19:03+01:00",
  "synced_at": "2026-03-13T22:29:27+01:00",
  "tags": "plaud,fieldnote,recording:...",
  "audio_file": "audio.ogg",
  "audio_format": "ogg",
  "audio_size": 175616
}
```

### Stage 2: Local → ER1

For each recording folder in `~/plaud-sync/`:

1. Read `metadata.json` for recording metadata
2. Read `audio.ogg` as audio payload
3. Read `fieldnote.txt` as transcript payload (composite doc)
4. Build ER1 `UploadPayload`:
   - `transcript_file_ext` = `fieldnote_<timestamp>.txt`
   - `audio_data_ext` = `plaud_<id>.ogg`
   - `image_data` = placeholder (1x1 red PNG)
   - `tags` = from metadata
   - `content_type` = `Plaud-Fieldnote` (configurable via `PLAUD_CONTENT_TYPE`)
5. Upload via `er1.Upload()`
6. On success: update tracking DB status to `uploaded`
7. On failure: enqueue in ER1 retry queue for background retry

### Stage 3: State Tracking

#### Tracking DB Table: `processed_files`

Plaud recordings are tracked in the existing `processed_files` table (same as audio imports):

| Column | Value for Plaud |
|--------|----------------|
| `file_path` | `plaud://<recording_id>` |
| `file_hash` | SHA-256 of audio bytes |
| `file_size` | Audio size in bytes |
| `import_type` | `plaud` |
| `status` | See state machine below |
| `memory_id` | ER1 MEMORY folder ID (after upload) |
| `transcript_text` | Raw transcript (if available) |
| `upload_doc_id` | ER1 document ID (after upload) |

#### State Machine

```
                    ┌──────────┐
                    │  (new)   │  Not in DB yet
                    └────┬─────┘
                         │ plaud sync → download audio + save locally
                         ▼
                    ┌──────────┐
                    │ imported │  Audio + metadata saved to ~/plaud-sync/
                    └────┬─────┘
                         │ ER1 upload succeeds
                         ▼
                    ┌──────────┐
                    │ uploaded │  Uploaded to ER1, doc_id recorded
                    └──────────┘

    Error paths:
      imported ──[ER1 down]──→ imported (stays, retry later)
      imported ──[retry queue]──→ imported (background retry picks up)
```

**States:**
- **(not in DB)** — Recording exists in Plaud cloud but never synced
- **imported** — Downloaded to `~/plaud-sync/`, not yet uploaded to ER1
- **uploaded** — Successfully uploaded to ER1, `upload_doc_id` set

#### Deduplication

- **By recording ID:** `file_path = 'plaud://<id>'` prevents re-downloading the same recording
- **By audio hash:** `UNIQUE(file_hash, import_type)` prevents uploading duplicate audio
- **Re-sync safe:** `plaud sync all` checks tracking DB and skips already-processed entries

## Plaud API Reference (Discovered)

### Authentication

- Token extracted from Chrome localStorage (`tokenstr` key on any `plaud.ai` tab)
- Sent as raw `Authorization: <token>` header (no `Bearer` prefix)
- Required headers: `app-platform: web`, `edit-from: web`
- Token persisted at `~/.m3c-tools/plaud-session.json` (0600 permissions)

### Region Routing

Initial requests to `https://api.plaud.ai` return a redirect response:
```json
{"status": -302, "data": {"domains": {"api": "https://api-euc1.plaud.ai"}}}
```
The client auto-follows this redirect and caches the regional URL.

### Endpoints

| Method | Path | Response |
|--------|------|----------|
| GET | `/file/simple/web?skip=0&limit=100&is_trash=2&is_desc=true` | List recordings |
| GET | `/file/detail/<id>` | Recording detail + `content_list` with S3 URLs |
| GET | `/file/download/<id>` | Raw audio bytes (OGG/Opus) |
| GET | `/user/me` | User profile + subscription info |

### List Response Format

```json
{
  "status": 0,
  "data_file_total": 97,
  "data_file_list": [
    {
      "id": "3dc1eb8d...",
      "filename": "2026-01-08 23:14:35",
      "duration": 76000,
      "start_time": 1767910475000,
      "is_trans": false,
      "is_summary": false,
      "filesize": 326144,
      "file_md5": "f6f00b7c..."
    }
  ]
}
```

Key fields:
- `duration` — **milliseconds** (divide by 1000 for seconds)
- `start_time` — **Unix milliseconds**
- `is_trans` — `true` if Plaud has transcribed this recording
- `is_summary` — `true` if Plaud has generated a summary

### Detail Response Format (`/file/detail/<id>`)

```json
{
  "status": 0,
  "data": {
    "file_id": "52949d16...",
    "file_name": "02-04 Abwicklung einer Fehllieferung",
    "duration": 41000,
    "start_time": 1770211143000,
    "content_list": [
      {
        "data_type": "transaction",
        "task_status": 1,
        "data_link": "https://euc1-prod-plaud-content-storage.s3.amazonaws.com/.../trans_result.json.gz?<signed>"
      },
      {
        "data_type": "outline",
        "task_status": 1,
        "data_link": "https://euc1-prod-plaud-content-storage.s3.amazonaws.com/.../outline_result.json.gz?<signed>"
      }
    ]
  }
}
```

- `content_list[].data_type = "transaction"` → transcript (gzipped JSON)
- `content_list[].data_type = "outline"` → summary/outline (gzipped JSON)
- `task_status = 1` → content ready for download
- `data_link` — pre-signed S3 URL (expires ~5 minutes)

### Transcript Format (`trans_result.json.gz`)

```json
[
  {
    "start_time": 1410,
    "end_time": 8970,
    "content": "Bei meinem ersten Kunde heute früh...",
    "speaker": "Speaker 1",
    "original_speaker": "Speaker 1"
  }
]
```

### Summary Format (`outline_result.json.gz`)

```json
[
  {
    "start_time": 1410,
    "end_time": 9110,
    "topic": "Erster Kundentermin kurz"
  }
]
```

## Composite Document Format

```
=== PLAUD FIELDNOTE ===
Recording: 02-04 Abwicklung einer Fehllieferung: Rückführungsprozess
Duration: 41s
Date: 2026-03-13 22:29:27

[Speaker 1] 4.2.26, bei meinem ersten Kunde heute früh, gab es nichts
weiter zu besprechen.
[Speaker 2] Der einzigste Grund meines Besuches war, ich habe zwei
falsch gelieferte Werkzeuge abgeholt...

=== SUMMARY ===
- Erster Kundentermin kurz
- Falsche Werkzeuge abgeholt
=== END FIELDNOTE ===
```

For audio-only recordings (no Plaud transcript):
```
=== PLAUD FIELDNOTE ===
Recording: 2026-01-08 23:14:35
Duration: 1m16s
Date: 2026-03-13 22:45:02

[No transcript available — audio only]
=== END FIELDNOTE ===
```

## CLI Commands

```bash
# Authenticate (extract token from Chrome automatically)
m3c-tools plaud auth login

# Authenticate (manual token)
m3c-tools plaud auth <token>

# List all recordings with sync status
m3c-tools plaud list

# Sync a single recording
m3c-tools plaud sync <recording_id>

# Sync ALL recordings (skips already-synced)
m3c-tools plaud sync all

# Debug API endpoints
m3c-tools plaud debug
```

## Re-Upload Workflow (Phase 3 — Planned)

When ER1 becomes available after a local-only sync:

```bash
# Re-upload all locally-synced recordings to ER1
m3c-tools plaud upload-local [--all | --id <recording_id>]
```

This command:
1. Scans `~/plaud-sync/` for folders with `metadata.json`
2. Checks tracking DB — skips entries with `status = 'uploaded'`
3. For each unuploaded folder:
   a. Read `fieldnote.txt` + `audio.ogg` + `metadata.json`
   b. Build `UploadPayload`
   c. Upload to ER1
   d. Update tracking DB: `status = 'uploaded'`, set `upload_doc_id`

### Future: Dedicated State Table

If the sync grows beyond the `processed_files` table's scope, add a dedicated table:

```sql
CREATE TABLE IF NOT EXISTS plaud_sync (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    recording_id    TEXT NOT NULL UNIQUE,
    title           TEXT,
    duration_sec    INTEGER,
    plaud_created   TEXT,           -- ISO 8601
    has_transcript  BOOLEAN DEFAULT FALSE,
    has_summary     BOOLEAN DEFAULT FALSE,
    local_path      TEXT,           -- ~/plaud-sync/<id>/
    local_synced_at TEXT,           -- when downloaded
    er1_uploaded_at TEXT,           -- when uploaded to ER1
    er1_doc_id      TEXT,           -- ER1 document ID
    er1_error       TEXT,           -- last upload error
    audio_hash      TEXT,           -- SHA-256
    audio_size      INTEGER,
    status          TEXT NOT NULL DEFAULT 'pending'
        -- pending | downloaded | uploaded | failed
);
CREATE INDEX IF NOT EXISTS idx_plaud_sync_status ON plaud_sync(status);
```

**Migration path:** When this table is added, existing `processed_files` entries with `import_type='plaud'` are migrated automatically on first access.

## Configuration

```env
# Plaud API base URL (auto-redirects to regional endpoint)
PLAUD_API_URL=https://api.plaud.ai

# Path to session token file
PLAUD_TOKEN_FILE=~/.m3c-tools/plaud-session.json

# ER1 content-type label for Plaud uploads
PLAUD_CONTENT_TYPE=Plaud-Fieldnote
```

## Current Metrics (2026-03-13)

- Total recordings: **97**
- With Plaud transcript: **54** (speaker-diarized, German/English)
- Audio only: **35** (short clips, untranscribed)
- Other: **8**
- Total audio: **402 MB** (OGG/Opus)
- Sync time: **~3.5 minutes** for all 97 (no whisper, direct API)
- Average per recording: **~2 seconds** (download + API + save)
- Largest recording: **149 min / 22 MB** (Kafka APIs lecture)
- Smallest recording: **1 second / 6 KB**

## Testing

| Test | Gate | What |
|------|------|------|
| `TestFieldnoteCompositeDoc` | offline | Composite doc format |
| `TestFieldnoteCompositeDocWithNotes` | offline | Composite doc with user notes |
| `TestFieldnoteTags` | offline | Tag generation |
| `TestBuildFieldnoteTags` | offline | Tag builder function |
| `TestPlaudConfigDefaults` | offline | Config defaults |
| `TestPlaudTokenRoundTrip` | offline | Token save/load |
| `TestPlaudFormatDuration` | offline | Duration formatting |
| `TestPlaudListRecordings` | `M3C_TEST_PLAUD=1` | Real API list |
| `TestPlaudSyncRecording` | `M3C_TEST_PLAUD=1` | Full sync pipeline |

## Open Items

1. **Token expiry:** Plaud web tokens appear long-lived but expiry behavior is undocumented. Monitor for 401s and prompt re-auth.
2. **`plaud upload-local`:** CLI command for re-uploading locally-synced recordings to ER1 (Phase 3).
3. **Dedicated `plaud_sync` table:** Migrate from `processed_files` when state tracking needs grow.
4. **Incremental sync:** `plaud sync --since <date>` to limit API calls for accounts with many recordings.
5. **Whisper fallback toggle:** `PLAUD_WHISPER_FALLBACK=true` to enable local whisper for untranscribed recordings (currently disabled for speed).
6. **Menu bar progress:** PlaudSyncWindow per-item progress during bulk sync (wired but needs ER1 to test end-to-end).
