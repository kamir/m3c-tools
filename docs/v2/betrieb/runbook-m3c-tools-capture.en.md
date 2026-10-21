# Operations runbook: the capture side of m3c-tools

Sprachen / Languages: [Deutsch](runbook-m3c-tools-capture.de.md) | [English](runbook-m3c-tools-capture.en.md)

What happens to an upload that cannot reach ER1: where pending items live,
in what format, and how recovery works. This page covers the upload path
and retry queue; the short English user-facing version is in the
[manual, "Exit behavior & the retry queue"](../referenz/manual-m3c-tools.md#exit-behavior--the-retry-queue).

Audience: the person operating a machine on which m3c-tools uploads
observations to ER1 and who needs to know after an outage what is still
pending and how it drains.

Role: Operations · Language: EN · Updated: 2026-09-16

**How much of this runbook has been measured.** The two blocks beginning
with "Measured" were run on 2026-09-16 against a local binary from this tree
(`make build`, reporting `skillctl/v0.5.1-6-g307b414`), using a throwaway
scratchpad database; paths are shortened with `/…/`. All other statements
come from reading the code (file and line are given) and are not demonstrated
by execution; wherever this distinction matters, it is stated locally.

## The core rule in one sentence

**There are two ledgers: `m3c-tools retry` processes the JSON queue
`~/.m3c-tools/queue.json`, while `status`, `schedule` and `cancel` read and
write the separate SQLite file `~/.m3c-tools/exports.db`**; checking only one
after an outage overlooks the other half (queue: `pkg/er1/queue.go`;
tracking DB: `cmd/m3c-tools/commands_shared.go`, `defaultExportsDBPath`).

## 1. The upload path and what failure leaves behind

An upload (`m3c-tools upload <video-id> ...` or Store from the menu bar app)
is sent to ER1 as a multipart request with the three fields
`transcript_file_ext`, `audio_data_ext`, `image_data`
(`pkg/er1/upload.go`); absent real audio or images are replaced by placeholders.

When the upload fails, `HandleUploadFailure`
(`pkg/er1/failure.go:23`) does two things:

1. It appends an entry to the JSON queue (section 2).
2. It creates a `MEMORY-<zeitstempel>/` directory and saves the payload files
   there so a later retry can find actual content. Root: `ER1_MEMORY_PATH`,
   otherwise `~/.m3c-tools/MEMORY` (`pkg/er1/memory.go:29-35`). MEMORY
   directories are created ONLY on failure, not for every upload.

## 2. The queue: location and format

| Item | Value | Source |
|---|---|---|
| Path | `~/.m3c-tools/queue.json` (overridden by flag `--queue`) | `pkg/er1/queue.go:12-26` |
| Permissions | Directory 0700, file 0600 | `queue.go:20`, `queue.go:192` |
| Format | A JSON array of entries, saved with indentation | `queue.go:179` |
| Fields per entry | `id`, `transcript_path`, `audio_path`, `image_path`, `tags`, `current_time` (the actual capture time, retained across retries), `queued_at`, `last_retry`, `retry_count`, `last_error` | `queue.go:29-40` |

The file is human-readable; an empty or absent `queue.json` means nothing
is waiting. An entry contains file paths, not the content itself; that is
why the MEMORY directories in section 1 exist and why section 3 includes a warning.

## 3. Recovery

### 3a. Manually: `m3c-tools retry`

```bash
m3c-tools retry                      # Vorgaben: --interval 30, --max-retries 10
m3c-tools retry --interval 60 --queue /pfad/zu/queue.json
```

Read from the code (`cmd/m3c-tools/commands_shared.go:46-149`,
`pkg/er1/retry.go`):

1. The queue is processed FIFO, oldest first.
2. Backoff per entry: `interval * 2^versuch`, capped at 5 minutes; an entry
   whose waiting time has not elapsed is skipped for that cycle.
3. Success removes the entry (`[retry] SUCCESS`); failure increments
   `retry_count` and writes `last_error` (`[retry] FAILED`); entries reaching
   `--max-retries` are DROPPED and removed from the queue
   (`[retry] DROPPED`).
4. The process blocks until Ctrl+C and finishes the current cycle cleanly
   ("Retry loop stopped.").
5. Content is reread from the paths recorded in the entry. If the transcript
   path is no longer readable, the placeholder text `Retry upload for <id>`
   is sent instead (`commands_shared.go:92-100`).

### 3b. Automatically, with a limitation

Two places start a background retry on their own
(`pkg/er1/background.go`):

| Trigger | Interval | Source |
|---|---|---|
| `m3c-tools upload` (runs alongside the current upload) | `ER1_RETRY_INTERVAL`, default 300 s; `ER1_MAX_RETRIES`, default 10 | `commands_shared.go:424-437`, `pkg/er1/config.go:123-124` |
| The menu bar app at startup | Fixed 5 minutes | `cmd/m3c-tools/main.go:2281-2291` |

**The limitation:** the background path does NOT reread payload files; it
sends placeholder content ("Retry upload for <id>", placeholder audio and
image), because the queue contains only filenames (`background.go:38-45`).
To submit the actual content later, use recovery from 3a; the background
path drains the queue but does not restore content. Both statements come
from reading the code, not from testing against a server.

## 4. Inspection: the second ledger

`status`, `schedule` and `cancel` operate on the SQLite tracking DB
`~/.m3c-tools/exports.db` (overridden by `--db`), not on `queue.json`.

Measured on 2026-09-16 against a throwaway DB (stderr additionally contains
`[config]`/`[auth]` lines, omitted here):

```
$ m3c-tools status --db /…/exports.db
ER1 Retry Queue Status:
  pending:   0
  retrying:  0
  completed: 0
  failed:    0
  total:     0
$ echo $?
0
```

Measured on 2026-09-16, `cancel` for an entry that does not exist:

```
$ m3c-tools cancel gibt-es-nicht --db /…/exports.db
Entry not found: gibt-es-nicht
$ echo $?
1
```

`status --entry <id>` displays one entry; `cancel <id>` marks it
`cancelled` and refuses for entries already completed
(`commands_shared.go:248-390`; the refusal branch was not measured).

## 5. What this runbook does not solve

1. No block here measured recovery against a real or newly reachable ER1
   server; section 3 is based on reading code.
2. Whisper transcription and batch import with their own tracking tables
   are not covered; see
   [Audio Import & Tracking](../nutzer/audio-import-tracking.md) (EN).
3. The skillctl side (registry, trust, revocation) has separate runbooks;
   start at the [operations overview](ueberblick.en.md).
