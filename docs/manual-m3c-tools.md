---
layout: default
title: Manual — m3c-tools
---

# Manual: m3c-tools

`m3c-tools` (Multi-Modal-Memory Tools) is a capture pipeline: it turns YouTube videos,
audio, screenshots and voice notes into structured, **multimodal observations** (text +
audio + image) uploaded to *your* [ER1](https://er1.io) personal knowledge server. On
macOS it ships as a native menu-bar app **and** a full CLI; on Linux and Windows it is
CLI-only. The core packages (`transcript`, `er1`, `impression`) use only the Go standard
library. If you just want the 5-minute path, start with the
[Quickstart](quickstart-m3c-tools.md) — **this page is the exhaustive reference** for
every command, flag and configuration variable.

---

## Installation & build

Grab the single binary from the
[latest release](https://github.com/kamir/m3c-tools/releases/latest), or use the
platform one-liners in the [Quickstart](quickstart-m3c-tools.md#1-install) and the
[README](../README.md#build-from-source). To build from source (Go 1.25+):

```bash
go build -o m3c-tools ./cmd/m3c-tools   # plain Go build
make build                              # → ./build/m3c-tools
make install                            # build + install CLI (and the macOS app)
make menubar                            # build & launch the menu-bar app (macOS, dev)
```

On macOS the menu-bar GUI additionally needs `brew install pkg-config portaudio ffmpeg`
and `python3 -m pip install openai-whisper`. See the
[README](../README.md#build-from-source) for the full install matrix.

---

## Usage & conventions

```bash
m3c-tools <command> [args] [flags]
```

- Flags use the `--<flag> <value>` form and follow their command.
- Run `m3c-tools help` for the top-level listing, or `m3c-tools <command> --help` for a
  single command. When in doubt about a flag, trust `--help` over any doc.
- Every run prints two informational log lines first (`[config] profile: …` and
  `[auth] …`) — these are diagnostics, not command output.

**Where configuration comes from.** Settings load from `~/.m3c-tools.env` (the global
config), from a project-local `.env`, and from named **profiles** managed by
`m3c-tools config`. See [Configuration reference](#configuration-reference) for the full
variable list and copy `.env.example` as a starting template.

**Authentication.** Uploads to ER1 authenticate with an **API key** (sent as the
`X-API-KEY` header, from `ER1_API_KEY`) **and/or** a **device token** (paired via
`m3c-tools login`). Set up at least one. Check what the tool sees with
`m3c-tools token` and `m3c-tools doctor`.

---

## Command reference

Fetching a YouTube transcript needs **no ER1 credential and no API key** (it uses
YouTube's InnerTube API). Everything that touches ER1 (`upload`, `import-audio`, `plaud
sync`, `pocket sync`, the retry/queue commands) needs a working ER1 config.

### Capture

#### `transcript` — fetch a YouTube transcript

```bash
m3c-tools transcript <video_id> [flags]
```

Fetches a video's transcript via YouTube's InnerTube API and prints it in the chosen
format. Also lists available transcript tracks and can translate to another language.

| Flag | Argument | Default | Meaning |
|------|----------|---------|---------|
| `--lang` | `<code>` | `en` | Language code of the transcript to fetch |
| `--format` | `<fmt>` | `text` | Output format: `text`, `srt`, `json`, `webvtt` |
| `--translate` | `<code>` | — | Translate the transcript to this language code |
| `--list` | — | — | List available transcripts only (no fetch) |
| `--exclude-generated` | — | — | With `--list`: exclude auto-generated transcripts |
| `--exclude-manually-created` | — | — | With `--list`: exclude manually created transcripts |
| `--proxy-url` | `<url>` | — | HTTP/SOCKS5 proxy URL, e.g. `http://host:port` |
| `--proxy-auth` | `<creds>` | — | Proxy credentials as `user:password` |

```bash
m3c-tools transcript dQw4w9WgXcQ --format srt
m3c-tools transcript dQw4w9WgXcQ --list --exclude-generated
```

#### `upload` — capture a full observation to ER1

```bash
m3c-tools upload <video_id> [flags]
```

Fetches the transcript **and** the thumbnail, builds a composite document, and uploads it
to ER1. If subtitles are disabled the capture still keeps the thumbnail and the link, so
the observation is never empty.

| Flag | Argument | Default | Meaning |
|------|----------|---------|---------|
| `--audio` | `<file>` | — | Include an audio file with the observation |
| `--impression` | `<text>` | — | Add your own impression / commentary text |

```bash
m3c-tools upload dQw4w9WgXcQ --impression "Great intro to the topic"
m3c-tools upload dQw4w9WgXcQ --audio note.wav --impression "My take"
```

#### `whisper` — transcribe local audio

```bash
m3c-tools whisper <audio_file> [flags]
```

Transcribes an audio file by invoking your local `whisper` binary as a subprocess.

| Flag | Argument | Default | Meaning |
|------|----------|---------|---------|
| `--model` | `<model>` | `base` | Whisper model (`tiny`, `base`, `small`, `medium`, `large`) |
| `--language` | `<lang>` | — | Language hint for transcription |

```bash
m3c-tools whisper meeting.wav --model base --language en
```

#### `thumbnail` — download a video thumbnail

```bash
m3c-tools thumbnail <video_id> [flags]
```

Downloads the highest-available thumbnail for a video (with size fallback).

| Flag | Argument | Default | Meaning |
|------|----------|---------|---------|
| `--output` | `<file>` | `<video_id>_thumbnail.jpg` | Output file path |

```bash
m3c-tools thumbnail dQw4w9WgXcQ --output cover.jpg
```

#### `record` — record from the microphone

```bash
m3c-tools record [output.wav] [flags]
```

Records from the default microphone to a WAV file (16 kHz / 16-bit PCM mono,
whisper-compatible). Requires PortAudio and a microphone.

| Flag | Argument | Default | Meaning |
|------|----------|---------|---------|
| `--duration` | `<secs>` | `5` | Recording duration in seconds |

```bash
m3c-tools record note.wav --duration 15
```

#### `screenshot` — capture a screenshot (macOS only)

```bash
m3c-tools screenshot [flags]
```

Captures the screen, a window, or a selected region and writes an image file. macOS only.

| Flag | Argument | Default | Meaning |
|------|----------|---------|---------|
| `--mode` | `<mode>` | `full` | Capture mode: `full`, `window`, `region` |
| `--output` | `<dir>` | current dir | Output directory |
| `--filename` | `<name>` | timestamped | Output filename |
| `--silent` | — | — | Suppress the capture sound |
| `--hide-cursor` | — | — | Hide the cursor in the capture |

```bash
m3c-tools screenshot --mode region --output ~/shots --silent
```

#### `import-audio` — scan / import a folder of audio

```bash
m3c-tools import-audio <dir> [flags]
```

Scans a directory for audio files. With `--run` it transcribes, uploads and tags each new
file end-to-end. Progress is tracked in a local SQLite DB so re-runs skip what's done.

| Flag | Argument | Default | Meaning |
|------|----------|---------|---------|
| `--run` | — | — | Import, transcribe, upload and tag end-to-end |
| `--extensions` | — | — | List supported audio extensions |
| `--compact` | — | — | Machine-readable TSV output (status, path, size, tags) |
| `--db` | `<path>` | `~/.m3c-tools/tracking.db` | Tracking DB path |

```bash
m3c-tools import-audio ~/m3c-inbox/ --run
m3c-tools import-audio --extensions
```

**`import-audio reset`** clears tracking records so items can be imported again. It only
touches the DB — it never deletes audio files. At least one of `--status`, `--file` or
`--all` is required; with no selector it prints the current per-status counts and exits
non-zero.

| Flag | Argument | Default | Meaning |
|------|----------|---------|---------|
| `--status` | `<state>` | — | Reset entries in this state (`imported`, `uploaded`, `failed`, `whisper-error`) |
| `--type` | `<kind>` | — | Narrow `--status` to one import type (e.g. `plaud`, `audio`) |
| `--file` | `<path>` | — | Reset the single entry with this file path |
| `--all` | — | — | Remove **all** tracking records (full reset) |

```bash
m3c-tools import-audio reset --status failed
m3c-tools import-audio reset --status failed --type plaud
m3c-tools import-audio reset --all
```

### Capture devices

#### `plaud` — Plaud recorder integration

```bash
m3c-tools plaud <subcommand> [flags]
```

Syncs recordings from a Plaud.ai device into ER1. There are **two transports**: the
scraped web session (`plaud list` / `plaud sync`, driven by the `web.plaud.ai` token) and
the official developer API (`plaud dev …`, driven by the durable OAuth token). Both write
into the same tracking ledger, so an item synced by one is not re-synced by the other.

| Subcommand | Meaning |
|------------|---------|
| `plaud list` | List Plaud recordings with sync status |
| `plaud sync <#\|ID>` | Sync one Plaud recording to ER1 |
| `plaud sync --all` | Sync all new Plaud recordings to ER1 |
| `plaud dev list` | List recordings via the developer API, newest first |
| `plaud dev sync <#\|ID\|N-M>` | Sync the selected items via the developer API |
| `plaud dev status` | Show the server-side transcription queue |
| `plaud check` | Check the stored token against the Plaud API |
| `plaud fix-times` | Repair wrong recording timestamps in already-synced items |
| `plaud auth login` | Extract the API token from Chrome (`web.plaud.ai`) |
| `plaud auth paste` | Import the `Authorization` header from the clipboard (best for SSO) |
| `plaud auth password` | Email+password login → long-lived token |
| `plaud auth` | Save the token from `$M3C_PLAUD_TOKEN` (secure) |
| `plaud auth <token>` | Save the token from argv — **deprecated** (leaks via `ps`) |

**`plaud sync` flags**

| Flag | Argument | Default | Meaning |
|------|----------|---------|---------|
| `--all` | — | — | Sync every not-yet-synced recording instead of one selector |
| `--force` | — | — | Re-sync: re-download from Plaud and re-upload to ER1 (also `-f`) |
| `--tags` | `<list>` | — | Comma-separated tags applied to every synced item |
| `--filter` | `<regex>` | — | Only sync items whose title matches this regular expression |
| `--dry-run` | — | — | Print what *would* be synced; download and upload nothing |

**`plaud dev` flags** — `dev list` takes `--preview` (alias `--transcript`) and `--limit`;
`dev sync` takes the rest.

| Flag | Argument | Default | Meaning |
|------|----------|---------|---------|
| `--all` | — | — | Sync every not-yet-synced recording |
| `--limit` | `<n>` | — | Restrict to the `n` most recent recordings |
| `--preview` | — | — | `dev list`: also print the transcript preview |
| `--whisper` | — | — | Transcribe un-transcribed audio locally instead of skipping it |
| `--force` | — | — | Re-sync items already in the ledger (also `-f`) |
| `--tags` | `<list>` | — | Comma-separated tags applied to every synced item |
| `--dry-run` | — | — | Print what *would* be synced; download and upload nothing |

**`plaud auth` flags**

| Flag | Argument | Default | Meaning |
|------|----------|---------|---------|
| `--token-file` | `<path>` | — | Read the token from a file (secure — keeps it out of `ps`) |
| `--from-er1` | — | — | Pull the token from the ER1 credential vault (SPEC-0304) |

**`plaud fix-times` flags**

| Flag | Argument | Default | Meaning |
|------|----------|---------|---------|
| `--apply` | — | — | Write the corrected timestamps; without it the run is a preview |

```bash
m3c-tools plaud auth login
m3c-tools plaud sync --all
m3c-tools plaud sync --all --filter '^(02-04|03-12)' --tags 'Denny,DV' --dry-run
m3c-tools plaud dev sync --limit 5 --whisper
m3c-tools plaud fix-times --apply
```

#### `pocket` — Pocket recorder integration

```bash
m3c-tools pocket <subcommand> [flags]
```

Syncs recordings from a Pocket device into ER1. `pocket sync` reads the **mounted
device**; `pocket cloud-sync` ingests from the Pocket **cloud API** instead (SPEC-0173
Path B) and needs a `pk_…` API key — see [`setup pocket-key`](#setup--set-up-the-python-venv--whisper).

| Subcommand | Meaning |
|------------|---------|
| `pocket list` | List Pocket recordings with sync status |
| `pocket sync --all` | Sync all new Pocket recordings from the mounted device |
| `pocket cloud-sync` | Sync all new recordings from the Pocket cloud API |
| `pocket api <sub>` | Low-level Pocket API calls (`list`, `get`, …) |
| `pocket backfill` | Register a mapping for an item uploaded outside the sync flow |
| `pocket mappings` | List the recorded recording → ER1 doc-id mappings |

| Flag | Argument | Default | Meaning |
|------|----------|---------|---------|
| `--all` | — | — | `pocket sync`: sync every new recording (required — there is no single-item form) |
| `--path` | `<dir>` | from config | Override the device recording path (`pocket list` / `pocket sync`) |
| `--dry-run` | — | — | `pocket cloud-sync`: list what would be ingested; upload nothing (also `-n`) |

```bash
m3c-tools pocket list
m3c-tools pocket sync --all --path /Volumes/POCKET
m3c-tools pocket cloud-sync --dry-run
```

#### `devices` — list audio input devices

```bash
m3c-tools devices
```

Lists the available audio input devices (useful before `record`). No flags.

### ER1 & queue

#### `check-er1` — test ER1 reachability

```bash
m3c-tools check-er1
```

A quick reachability check against the ER1 server. For a full diagnostic use `doctor`.
No flags.

#### `doctor` — connectivity & config diagnostics

```bash
m3c-tools doctor
```

Runs the full diagnostic: active profile, authentication (API key and/or device token),
DNS, TLS, and the ER1 health/auth endpoints. Run this first when uploads fail. No flags.

#### `token` — show device-token status

```bash
m3c-tools token [--print]
```

Shows whether a device token is loaded.

| Flag | Argument | Default | Meaning |
|------|----------|---------|---------|
| `--print` | — | — | Emit the Bearer token to stdout (for shell capture) |

```bash
m3c-tools token
export TOKEN=$(m3c-tools token --print)
```

#### `retry` — run the retry loop for queued uploads

```bash
m3c-tools retry [flags]
```

Processes the local retry queue of failed uploads, polling on an interval.

| Flag | Argument | Default | Meaning |
|------|----------|---------|---------|
| `--interval` | `<secs>` | `30` | Poll interval in seconds |
| `--max-retries` | `<n>` | `10` | Max retries per entry |
| `--queue` | `<path>` | `~/.m3c-tools/queue.json` | Queue file path |

```bash
m3c-tools retry --interval 60 --max-retries 5
```

#### `schedule` — schedule a retry entry in the tracking DB

```bash
m3c-tools schedule <entry_id> --transcript <path> [flags]
```

Registers an ER1 retry entry in the SQLite tracking DB. `--transcript` is required.

| Flag | Argument | Default | Meaning |
|------|----------|---------|---------|
| `--transcript` | `<path>` | — (required) | Transcript file path |
| `--audio` | `<path>` | — | Audio file path |
| `--image` | `<path>` | — | Image file path |
| `--tags` | `<tags>` | — | Comma-separated tags |
| `--max-attempts` | `<n>` | `10` | Max retry attempts |
| `--db` | `<path>` | `~/.m3c-tools/exports.db` | SQLite DB path |

```bash
m3c-tools schedule vid-001 --transcript out.txt --tags progress,youtube
```

#### `status` — show retry entry status

```bash
m3c-tools status [flags]
```

Shows the status of ER1 retry entries in the tracking DB.

| Flag | Argument | Default | Meaning |
|------|----------|---------|---------|
| `--entry` | `<id>` | — | Show a specific entry only |
| `--db` | `<path>` | `~/.m3c-tools/exports.db` | SQLite DB path |

```bash
m3c-tools status
m3c-tools status --entry vid-001
```

#### `cancel` — cancel a pending retry entry

```bash
m3c-tools cancel <entry_id> [flags]
```

Cancels a pending ER1 retry entry.

| Flag | Argument | Default | Meaning |
|------|----------|---------|---------|
| `--db` | `<path>` | `~/.m3c-tools/exports.db` | SQLite DB path |

```bash
m3c-tools cancel vid-001
```

### Config & app

#### `setup` — set up the Python venv + whisper

```bash
m3c-tools setup [flags]
```

**On macOS** this sets up the Python virtual environment and installs whisper for local
transcription.

| Flag | Argument | Default | Meaning |
|------|----------|---------|---------|
| `--force` | — | — | Recreate the venv from scratch |
| `--check` | — | — | Check setup status without installing |

```bash
m3c-tools setup --check
m3c-tools setup --force
```

**On Linux and Windows** `setup` is instead the interactive ER1 onboarding wizard (whisper
is installed by hand there). It asks for the server, opens the browser to pair the device
and writes the result into the active profile.

| Flag | Argument | Default | Meaning |
|------|----------|---------|---------|
| `--er1-url` | `<url>` | prompted | Pre-fill the ER1 server URL instead of asking for it |
| `--no-browser` | — | — | Print the pairing URL instead of opening a browser (headless hosts) |
| `--tags` | `<list>` | — | Default tags to store in the profile |

```bash
m3c-tools setup --er1-url https://er1.example.com --no-browser
```

**`setup pocket-key <pk_…>`** (macOS) validates a Pocket API key live against the Pocket
API and writes it to a profile on success. An unreachable API is **not** fatal — the key
is still saved; only an outright *unauthorized* answer fails the command.

| Flag | Argument | Default | Meaning |
|------|----------|---------|---------|
| `--no-write` | — | — | Validate only; do not save the key to any profile |
| `--profile` | `<name>` | active profile | Write the key to this profile instead of the active one |

```bash
m3c-tools setup pocket-key pk_… --no-write
m3c-tools setup pocket-key pk_… --profile dev
```

#### `config` — configuration profile management

```bash
m3c-tools config <list|show|switch|create|test|import|delete|doctor>
```

Manages named configuration profiles.

| Subcommand | Meaning |
|------------|---------|
| `config list` | List available profiles |
| `config show` | Show the active profile's settings |
| `config switch` | Switch the active profile |
| `config create` | Create a new profile |
| `config test` | Test a profile's ER1 connectivity |
| `config import` | Import a profile |
| `config delete` | Delete a profile |
| `config doctor` | Validate profile consistency; exits non-zero on any FAIL |

`config doctor` takes a profile name, or one of the following:

| Flag | Argument | Default | Meaning |
|------|----------|---------|---------|
| `--all` | — | *the default* | Validate every profile in `~/.m3c-tools/profiles` (the literal word `all` works too) |

```bash
m3c-tools config list
m3c-tools config switch cloud
m3c-tools config doctor --all
m3c-tools config doctor cloud
```

#### `settings` — open the profile settings editor

```bash
m3c-tools settings
```

Opens the profile settings editor in your browser. No flags.

#### `login` — pair this device via the browser

```bash
m3c-tools login
```

Opens the browser to sign in to ER1 and links this device (captures your context and can
store a device token). Run any time to re-pair. No flags.

#### `menubar` — launch the macOS menu-bar app

```bash
m3c-tools menubar [flags]
```

Launches the native menu-bar app (macOS only). See the
[Menu Bar App guide](menubar-app.md) for every menu item.

| Flag | Argument | Default | Meaning |
|------|----------|---------|---------|
| `--title` | `<text>` | `M3C` | Menu-bar title text |
| `--icon` | `<path>` | — | Menu-bar icon PNG path |
| `--log` | `<path>` | `~/.m3c-tools/m3c-tools.log` | Log file path |
| `--verbose` | — | — | Also mirror the log to stderr (the terminal), not just the log file |
| `--quiet` | — | — | Log to the file only — the default, and the way to undo an earlier `--verbose` |

```bash
m3c-tools menubar --title "M3C" --icon ~/icons/m3c.png
```

#### `version` — print the version

```bash
m3c-tools version
```

Prints the build version. It takes no flags of its own, but `--version` and `-v` are
accepted as top-level aliases for the subcommand (`m3c-tools --version`). Likewise
`--help` and `-h` are aliases for `help`.

#### `help` — show the command listing

```bash
m3c-tools help
```

Prints the full command + flag listing. No flags.

---

## Configuration reference

Variables are read from `~/.m3c-tools.env`, a project `.env`, or the active profile. Copy
`.env.example` as a template. All examples below show the documented defaults; commented
lines in `.env.example` mean the value is optional.

### ER1 connection (required for uploads)

| Variable | Default | Meaning |
|----------|---------|---------|
| `ER1_API_URL` | — | ER1 upload endpoint URL, e.g. `https://onboarding.guide/upload_2` |
| `ER1_API_KEY` | — | API key sent as the `X-API-KEY` header |
| `ER1_CONTEXT_ID` | — | Context identifier for uploads |
| `ER1_VERIFY_SSL` | `false` | SSL verification: `true` \| `false` (use `false` for self-signed local dev) |
| `ER1_CONTENT_TYPE` | `YouTube-Video-Impression` | Content-type label in the upload form payload |

### ER1 tuning

| Variable | Default | Meaning |
|----------|---------|---------|
| `ER1_UPLOAD_TIMEOUT` | `600` | HTTP timeout (seconds) for upload requests |
| `ER1_RETRY_INTERVAL` | `300` | Seconds between automatic retry-queue cycles |
| `ER1_MAX_RETRIES` | `10` | Max retry attempts before dropping a failed upload |
| `M3C_ER1_SESSION_PERSIST` | `false` | Persist login-linked context across app restarts |
| `M3C_ER1_SESSION_FILE` | `~/.m3c-tools/er1_session.json` | Custom path for the persisted ER1 session JSON |

> Retry backoff itself is hardcoded in `pkg/er1/retry.go` — the former
> `ER1_RETRY_BASE_DELAY` / `ER1_RETRY_MAX_DELAY` variables were removed and have no effect.

### YouTube rate-limit mitigation

| Variable | Default | Meaning |
|----------|---------|---------|
| `YT_PROXY_URL` | — | HTTP/SOCKS5 proxy to avoid YouTube 429 rate limits |
| `YT_PROXY_AUTH` | — | Proxy credentials as `user:password` |

> Transcripts are also cached at `~/.m3c-tools/cache/transcripts/` (7-day TTL). On a 429,
> the app proceeds without the transcript (graceful degradation).

### Whisper transcription

Used for menu-bar voice recording, audio import, and local speech-to-text (**not** for
YouTube transcripts, which are fetched directly).

| Variable | Default | Meaning |
|----------|---------|---------|
| `M3C_WHISPER_MODEL` | `large` | Model size: `tiny` \| `base` \| `small` \| `medium` \| `large` |
| `M3C_WHISPER_FALLBACK` | `medium,base,tiny` | Comma-separated fallback chain if the primary model fails |
| `M3C_WHISPER_TIMEOUT` | `7200` | Transcription timeout in seconds (`0` = no timeout) |
| `M3C_WHISPER_LANGUAGE` | `de` | Transcription language (ISO 639-1 code) |
| `M3C_WHISPER_PRELOAD` | `true` | Preload the model at menu-bar startup (lower first-run latency) |

### Screenshot capture

| Variable | Default | Meaning |
|----------|---------|---------|
| `M3C_SCREENSHOT_MODE` | `clipboard-first` | `clipboard-first` \| `interactive` \| `screencapture-legacy` |
| `M3C_SCREENSHOT_CLIPBOARD_TIMEOUT_SEC` | `20` | Seconds to wait for a clipboard screenshot in clipboard-first mode |
| `M3C_SCREENSHOT_FOCUS_DELAY_MS` | `700` | Delay (ms) before an interactive capture from menu-bar actions (`0` to disable) |
| `YT_MEMORY_DIR` | `~/Library/Application Support/YTTranscript/MEMORY` | Root directory for MEMORY folders (impression storage) |

> Interactive capture also requires Screen Recording permission for `m3c-tools`.

### Audio import

| Variable | Default | Meaning |
|----------|---------|---------|
| `IMPORT_AUDIO_SOURCE` | — | Source folder for audio files (e.g. a GDrive mirror) |
| `IMPORT_AUDIO_DEST` | `~/ER1` | Destination base folder for imported MEMORY folders |
| `IMPORT_CONTENT_TYPE` | `Audio-Track vom Diktiergerät` | Content-type label for audio imports |
| `IMPORT_TRACKER_FILE` | `~/.m3c-tools/transcript_tracker.md` | Tracks which files have been imported |

### Plaud integration

| Variable | Default | Meaning |
|----------|---------|---------|
| `PLAUD_API_URL` | `https://api.plaud.ai` | Plaud API base URL |
| `PLAUD_TOKEN_FILE` | `~/.m3c-tools/plaud-session.json` | Path to the Plaud session token file |
| `PLAUD_CONTENT_TYPE` | `Plaud-Fieldnote` | Content-type label for Plaud fieldnote uploads |
| `M3C_PLAUD_TOKEN` | — | Plaud API token consumed by `plaud auth` (secure, avoids argv leaks) |
| `PLAUD_TRANSCRIBE_MODE` | `queue` | For un-transcribed recordings in `plaud dev sync`: `queue` (server-side whisper, SPEC-0111), `lazy` (`todo.transcribe` tag), or `off` (audio only). 🍎 |
| `PLAUD_MAX_AUDIO_MB` | `30` | Max audio (MB) attached to an ER1 upload by `plaud dev sync`. Larger clips upload **transcript-only** (they still land; the recording stays in Plaud) to avoid the ER1 ingress **HTTP 413** — Cloud Run rejects requests over ~32 MiB. Raise toward ~31 to mirror bigger recordings. 🍎 |

### Time tracking & reverse tracking (menu-bar app)

The menu-bar app can **infer** project time blocks from your captures: when an
observation is uploaded, its tags are matched against your PLM projects and a
~15-minute block is created for the best match. This runs **only in the menu-bar
app** (the plain CLI does not track time). The full matching rules (strong
`project:<slug>` / medium `client:<name>` / weak ≥2-tag overlap), the month-at-startup
backfill, and the `[reverse-tracking] no project match` diagnostic are documented in
**[Menu Bar App → How reverse tracking works](menubar-app.md#how-reverse-tracking-works)**.

| Variable | Default | Meaning |
|----------|---------|---------|
| `M3C_REVERSE_BLOCK_ENABLED` | `true` | Master switch for inferred time blocks. `false` disables them (observations are still recorded, so a later backfill can credit them). |
| `M3C_REVERSE_BLOCK_DURATION` | `900` | Inferred block size in seconds (900 = 15 min, centred on the observation timestamp). |
| `M3C_REVERSE_MIN_TAG_OVERLAP` | `2` | Minimum plain-tag overlap for a **weak** match. Lower = more (noisier) matches. A `project:<slug>` or `client:<name>` tag is a strong match regardless of this. |

---

## Exit behavior & the retry queue

Uploads that fail (network error, ER1 unreachable, auth problem) are **not lost** — they
are queued locally and can be retried later.

- **Where.** The JSON retry queue lives at `~/.m3c-tools/queue.json`. The `schedule`,
  `status` and `cancel` commands use a separate SQLite tracking DB at
  `~/.m3c-tools/exports.db`.
- **Retry.** Run `m3c-tools retry` to process the queue on an interval (`--interval`,
  `--max-retries`, `--queue`). Automatic cycles are governed by `ER1_RETRY_INTERVAL` and
  `ER1_MAX_RETRIES`; the backoff itself is hardcoded in `pkg/er1/retry.go`.
- **Inspect / cancel.** `m3c-tools status` lists tracked entries (`--entry <id>` for one);
  `m3c-tools cancel <entry_id>` drops a pending entry.

```bash
m3c-tools status
m3c-tools retry --interval 60
m3c-tools cancel vid-001
```

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Uploads fail / auth failing (`key_set=false`) | Run `m3c-tools doctor`. The active profile likely has a placeholder key — re-run `setup` or `login`, and make sure `ER1_API_KEY` is real. |
| `whisper` command not found | Install it: `python3 -m pip install openai-whisper` (needs `ffmpeg`). Or run `m3c-tools setup`. |
| `subtitles are disabled for this video` | Expected. The capture still keeps the **thumbnail + link** — add a voice note or `--impression`. |
| "Projects" menu stuck on *Loading…* | No ER1 credential reached the app. Fix the active profile's key or run `login`, then **restart the menu-bar app**. |
| `[reverse-tracking] no project match` in the log | Diagnostic, not an error: a capture's tags didn't overlap any PLM project. Add matching tags to the project, or capture with a `project:<slug>` / `client:<name>` tag — see [reverse tracking](menubar-app.md#how-to-make-reverse-tracking-work-for-your-captures). |
| Upload fails, then retries | Failed uploads queue at `~/.m3c-tools/queue.json`. Run `m3c-tools retry`, check `m3c-tools status`. |
| YouTube 429 / rate limited | Set `YT_PROXY_URL`; transcripts are cached for 7 days and the app degrades gracefully without them. |
| `plaud dev sync` → HTTP 413 | The recording's audio exceeds the ER1 ingress limit (~32 MiB). `plaud dev sync` already drops audio over `PLAUD_MAX_AUDIO_MB` (default 30) and uploads transcript-only. If you still see 413, lower `PLAUD_MAX_AUDIO_MB`; a stricter proxy may cap below 30 MB. |

---

## See also

- [Quickstart: m3c-tools](quickstart-m3c-tools.md) — the 5-minute path
- [Menu Bar App](menubar-app.md) — projects, the Gantt time tracker, and reverse tracking in depth
- [Manual: skillctl](manual-skillctl.md) — the agent-skill trust lifecycle, command by command
- [Menu Bar App](menubar-app.md) — every menu item and the Observation Window
- [Platform differences](PLATFORM-DIFFERENCES.md) — macOS vs Linux vs Windows behavior
