# Audio Import & Upload Tracking

This document describes the audio import pipeline, the tracking database, and the
seed procedure for initializing the tracking state.

## Overview

The audio import pipeline processes files from a source directory through four stages:

```
Source folder (IMPORT_AUDIO_SOURCE)
    → Scan & deduplicate (tracking DB)
    → Copy to MEMORY folder (IMPORT_AUDIO_DEST)
    → Transcribe via Whisper
    → Upload to ER1
```

Each file's progress is tracked in the **SQLite tracking database** at
`~/.m3c-tools/tracking.db`.

## File Lifecycle

| Status     | Meaning                                              |
|------------|------------------------------------------------------|
| `new`      | File is on disk but not in the DB — ready to import  |
| `imported` | Copied to MEMORY folder, recorded in DB              |
| `uploaded` | Successfully uploaded to ER1 (has `upload_doc_id`)   |
| `failed`   | Import or upload failed (see `upload_error` column)  |

## Tracking Database Schema

```sql
CREATE TABLE processed_files (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    file_path       TEXT NOT NULL,        -- Full source path
    file_hash       TEXT NOT NULL,        -- SHA-256 of file content
    file_size       INTEGER NOT NULL,     -- File size in bytes
    import_type     TEXT DEFAULT 'audio', -- Always 'audio' for this pipeline
    status          TEXT DEFAULT 'imported',
    memory_id       TEXT,                 -- MEMORY folder name
    processed_at    TEXT NOT NULL,        -- ISO 8601 timestamp
    transcript_text TEXT,                 -- Full whisper transcript
    transcript_lang TEXT,                 -- Language code (e.g. 'de')
    transcript_len  INTEGER DEFAULT 0,   -- Character count of transcript
    upload_doc_id   TEXT,                 -- ER1 document ID on success
    upload_error    TEXT,                 -- Error message on failure
    uploaded_at     TEXT,                 -- ISO 8601 upload timestamp
    UNIQUE(file_hash, import_type)
);
```

### Key columns for tracking

- **transcript_text / transcript_lang / transcript_len**: Recorded after Whisper
  transcription completes. If transcription fails, `transcript_text` contains
  the error message prefixed with `[Transcription failed: ...]`.
- **upload_doc_id**: The ER1 document ID returned on successful upload. This is
  the definitive proof that the file reached ER1.
- **upload_error**: Stores the error message when an upload fails. Cleared on
  successful retry.
- **uploaded_at**: Timestamp of successful upload.

## Seed Procedure

When setting up m3c-tools for the first time (or resetting the tracking state),
follow these steps to establish the correct baseline.

### Prerequisites

- The **authoritative tracker file** lists filenames that have already been
  uploaded to ER1 via the legacy Python tool. Default location:
  `/Users/kamir/GITHUB.active/my-ai-X/experiments/audio-checklist-checker-py/bin/transcript_tracker.md`
- The **audio source folder** (`IMPORT_AUDIO_SOURCE`) contains all audio files.
- Already-uploaded files are moved to a `DONE/` subfolder in the source.

### Steps

1. **Backup the existing DB** (if any):
   ```bash
   cp ~/.m3c-tools/tracking.db ~/.m3c-tools/tracking.db.bak
   ```

2. **Delete the existing DB**:
   ```bash
   rm ~/.m3c-tools/tracking.db
   ```

3. **Seed from the authoritative tracker**. For each file listed in the tracker,
   compute the SHA-256 hash and insert into the DB as `status='uploaded'`:
   ```bash
   SOURCE_DIR="/Users/kamir/GDMirror/GCP-AUDIO-TRANSCRIPT-SERVICE"
   TRACKER="/Users/kamir/GITHUB.active/my-ai-X/experiments/audio-checklist-checker-py/bin/transcript_tracker.md"
   DB="$HOME/.m3c-tools/tracking.db"

   # The app will create the schema on first open. Alternatively, start the
   # menubar app once to initialize: m3c-tools menubar &; sleep 2; kill %1

   while IFS= read -r basename; do
     [ -z "$basename" ] && continue
     [[ "$basename" =~ ^# ]] && continue
     fullpath="$SOURCE_DIR/DONE/$basename"
     [ ! -f "$fullpath" ] && echo "SKIP (not found): $basename" && continue
     hash=$(shasum -a 256 "$fullpath" | cut -d' ' -f1)
     size=$(stat -f%z "$fullpath")
     sqlite3 "$DB" "INSERT OR IGNORE INTO processed_files
       (file_path, file_hash, file_size, import_type, status, processed_at)
       VALUES ('$fullpath', '$hash', $size, 'audio', 'uploaded', datetime('now'));"
   done < "$TRACKER"
   ```

4. **Update the m3c-tools tracker** to match:
   ```bash
   cp "$TRACKER" ~/.m3c-tools/transcript_tracker.md
   ```

5. **Verify**:
   ```bash
   sqlite3 "$DB" "SELECT status, COUNT(*) FROM processed_files GROUP BY status;"
   # Expected: uploaded|6 (or however many files are in DONE/)
   ```

### After seeding

- All files in the main source folder (not in `DONE/`) appear as **"new"** in
  the Audio Import menu.
- Select individual files or use "Run Import Pipeline" for batch processing.
- Each file progresses: `new → imported → uploaded` (or `failed`).
- The "Tracking DB" submenu shows all records with their status, transcript
  length, and upload doc ID.

## Import Modes

### Single-file import (menu click)

When you click a file in the Audio Import submenu:
1. Only that one file is imported (via `ImportAudioFiltered`)
2. Whisper transcription runs on it
3. Transcript details are saved to the DB
4. Upload to ER1 is attempted
5. Upload result (doc_id or error) is saved to the DB
6. Menu refreshes to remove the file from the "new" list

### Batch import ("Run Import Pipeline")

Imports ALL new files in the source directory, transcribes each, and uploads.
Same per-file tracking as single-file mode.

## Bulk Operation UX, Locking, and Logs

Bulk actions from the **Tracking DB → Source Files** tab now run as explicit
sessions with a `run_id` and live progress.

### Locking behavior

- While a bulk session is active, new ingestion actions are blocked:
  - YouTube fetch/record flow
  - Screenshot flow
  - Quick Impulse flow
  - Audio Import actions (single + batch)
  - Additional tracking bulk actions
- The user receives a notification with current progress and remaining items.

### Live progress surfaces

- **Tracking window** shows:
  - Top progress strip (determinate bar)
  - Session counters: `done/total`, `ok`, `fail`
  - Current file + phase
  - Last error line (if any)
  - Bulk buttons disabled while session is active
- **Menubar Audio Import** shows:
  - `Running X/Y`
  - Current file
  - Failed count
  - Elapsed time

### Source row status overlays

Selected files transition through in-flight labels:

- `queued`
- `importing`
- `transcribing`
- `uploading`
- terminal: `done`, `failed`, or `skipped`

### Structured bulk logs

Each session writes parseable lifecycle markers:

- `[bulk][RUN_START]`
- `[bulk][ITEM_START]`
- `[bulk][PHASE] phase=import|whisper|upload`
- `[bulk][ITEM_DONE]`
- `[bulk][RUN_DONE]`

Each line includes `run_id`, item index/total where relevant, and outcome/error code.

## Environment Variables

| Variable               | Default                              | Description                    |
|------------------------|--------------------------------------|--------------------------------|
| `IMPORT_AUDIO_SOURCE`  | (required)                           | Source directory for audio files|
| `IMPORT_AUDIO_DEST`    | `~/ER1`                              | Destination for MEMORY folders |
| `IMPORT_CONTENT_TYPE`  | (required)                           | ER1 content-type label         |
| `IMPORT_TRACKER_FILE`  | `~/.m3c-tools/transcript_tracker.md` | Legacy tracker file path       |

## Viewing Tracking History

The **"Tracking DB"** submenu in the menu bar shows up to 50 recent records.
Each entry shows:
- Status icon: ✅ uploaded, 📦 imported, ❌ failed
- File name
- Expandable details: transcript length/language, ER1 doc ID, error message
