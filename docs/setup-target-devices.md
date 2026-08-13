---
layout: default
title: Setup & Operations — Intel Mac & Windows
---

# Setup & Operations Guide — Intel Mac & Windows

A practical, zero-to-operating runbook for deploying and running **m3c-tools v2.10.0**
on two fresh target devices:

- **Intel Mac** — macOS, `x86_64` (`darwin/amd64`) → **full feature build**
- **Windows PC** — `amd64` (`windows/amd64`) → **CLI core + system tray + settings web UI**

> The two platforms do **not** ship the same features. macOS builds from `main.go`
> (native menubar, voice recording, screenshot, and the durable `plaud dev` capture
> workflow); Windows builds from `main_other.go` (CLI + `fyne` systray, no cgo).
> The exact split is in the [Platform capability matrix](#platform-capability-matrix) below
> and in [Platform differences](PLATFORM-DIFFERENCES.md).

Related docs: [Getting started](getting-started.md) ·
[Quickstart: m3c-tools](quickstart-m3c-tools.md) ·
[Manual: m3c-tools](manual-m3c-tools.md) (every command + flag) ·
[Platform differences](PLATFORM-DIFFERENCES.md)

**🍎 macOS only** marks features that exist **only** on the Intel Mac build. On Windows they
either print a clear error (`record`, `devices`, `screenshot`) or are not compiled in
(`plaud dev`, `import-audio`, `pocket`, `token`).

---

## Platform capability matrix

Verified against `cmd/m3c-tools/main.go` (darwin) and `cmd/m3c-tools/main_other.go` (`!darwin`).

| Capability | Intel Mac (`darwin/amd64`) | Windows (`amd64`) |
|-----------|:--------------------------:|:-----------------:|
| CLI core (`transcript`, `upload`, `whisper`, `thumbnail`) | ✓ | ✓ |
| ER1 retry cluster (`retry`, `schedule`, `status`, `cancel`) | ✓ | ✓ |
| `doctor`, `check-er1`, `config`, `settings`, `setup`, `login` | ✓ | ✓ |
| System tray / `menubar` | ✓ native Cocoa (menuet) | ✓ systray (fyne) |
| Settings web UI (`settings`) | ✓ | ✓ |
| Voice recording (`record`, `devices`) | ✓ PortAudio | ✗ error: requires macOS |
| Screenshot capture (`screenshot`) | ✓ | ✗ error: requires macOS |
| Whisper transcription (`whisper`) | ✓ | ✓ *(needs `whisper` on `PATH`)* |
| **Plaud — legacy** (`auth`, `list`, `check`, `sync`, `fix-times`) | ✓ | ✓ |
| **Plaud — durable dev API** (`plaud dev list/sync/status`) | ✓ 🍎 | ✗ not available |
| `import-audio`, `pocket`, `token` | ✓ 🍎 | ✗ not available |

> **Windows Plaud is the LEGACY surface only.** `plaud dev …` (durable OAuth token,
> server-side whisper, `dev list`/`dev sync`/`dev status`) is macOS-only today. Multi-platform
> parity for the darwin-coupled commands (`import-audio`, `pocket`, and the `plaud dev` cluster)
> is tracked under **Pending / SPEC-0251 §5** in [`../CHANGELOG.md`](../CHANGELOG.md).

---

## Part 1 — Intel Mac (macOS, x86_64)

### 1A. Download the prebuilt binary (fastest)

From the [latest release](https://github.com/kamir/m3c-tools/releases/latest), grab the
Intel macOS archive and its checksum.

```bash
cd ~/Downloads
curl -sL -O https://github.com/kamir/m3c-tools/releases/latest/download/m3c-tools-darwin-amd64.tar.gz
curl -sL -O https://github.com/kamir/m3c-tools/releases/latest/download/checksums.txt

# Verify the download (compares against the published checksums.txt)
shasum -a 256 m3c-tools-darwin-amd64.tar.gz
grep m3c-tools-darwin-amd64.tar.gz checksums.txt        # the two hashes must match

tar xzf m3c-tools-darwin-amd64.tar.gz                   # → m3c-tools-darwin-amd64
chmod +x m3c-tools-darwin-amd64
sudo mv m3c-tools-darwin-amd64 /usr/local/bin/m3c-tools
```

**Gatekeeper** — if macOS blocks the unsigned binary ("cannot be opened because the developer
cannot be verified"), clear the quarantine attribute:

```bash
sudo xattr -d com.apple.quarantine /usr/local/bin/m3c-tools
```

### 1B. Build from source (full build, with recording)

Requires **Go 1.26+** (the module pins `toolchain go1.26.5`; CI builds on 1.26). The macOS
build links PortAudio (cgo) for voice recording and menubar, so install the native deps first.

```bash
brew install pkg-config portaudio ffmpeg
git clone https://github.com/kamir/m3c-tools.git && cd m3c-tools

make build            # → ./build/m3c-tools   (runs `check-deps` then `go build`)
make build-all        # optional: CLI + 4 POC binaries
make vet              # go vet ./...
```

`make build` outputs `./build/m3c-tools`. Add it to your `PATH`, or run it in place
(`./build/m3c-tools …`).

### 1C. What the Intel Mac build gives you

The full command surface — everything in the [matrix](#platform-capability-matrix), including:

- 🍎 **Voice recording**: `record`, `devices`
- 🍎 **Screenshot capture**: `screenshot`
- 🍎 **Native menubar app**: `menubar` (Cocoa/menuet)
- 🍎 **Durable Plaud capture**: `plaud dev list` / `plaud dev sync` / `plaud dev status`
  (see [Operating — Plaud](#plaud-capture))

---

## Part 2 — Windows PC (amd64)

### 2A. Download prebuilt (NSIS installer — recommended)

From the [latest release](https://github.com/kamir/m3c-tools/releases/latest):

- **`M3C-Tools-Setup.exe`** — NSIS installer (recommended; installs and puts `m3c-tools` on `PATH`).
- **`m3c-tools-windows-amd64.zip`** — portable ZIP (unzip, add the folder to `PATH` yourself).
- **`checksums.txt`** — published alongside; verify before running.

**Verify a download in PowerShell:**

```powershell
cd $HOME\Downloads
# Compare this hash against the matching line in checksums.txt
Get-FileHash .\m3c-tools-windows-amd64.zip -Algorithm SHA256
Select-String -Path .\checksums.txt -Pattern 'm3c-tools-windows-amd64.zip'
```

**Portable ZIP install:**

```powershell
Expand-Archive .\m3c-tools-windows-amd64.zip -DestinationPath "$HOME\m3c-tools"
# Add $HOME\m3c-tools to your PATH (or call the .exe by full path)
& "$HOME\m3c-tools\m3c-tools-windows-amd64.exe" version
```

### 2B. Build from source (CLI, no cgo)

Requires **Go 1.26+**. The Windows build needs **no** native libraries — it compiles with
cgo disabled.

```powershell
git clone https://github.com/kamir/m3c-tools.git
cd m3c-tools
$env:CGO_ENABLED=0
go build .\cmd\m3c-tools           # → m3c-tools.exe
```

> The `make` targets are macOS-oriented (they run `check-deps` for PortAudio). On Windows,
> build with the raw `go build` command above.

### 2C. What the Windows build gives you (and what it does NOT)

**Available:** CLI core (`transcript`, `upload`, `whisper`, `thumbnail`), the ER1 retry cluster
(`retry`/`schedule`/`status`/`cancel`), `doctor`, `check-er1`, `config`, `settings`, `setup`,
`login`, the **systray** app (`menubar`, via `fyne`), and the **legacy** Plaud surface
(`plaud auth` / `list` / `check` / `sync` / `fix-times`).

**Not available on Windows:**

| Command | Behavior on Windows |
|---------|---------------------|
| `record`, `devices` | Prints `Error: audio recording requires macOS with PortAudio`, exits 1 |
| `screenshot` | Prints `Error: screenshot capture requires macOS`, exits 1 |
| `plaud dev …` | Not compiled in — use `plaud sync` (legacy) instead |
| `import-audio`, `pocket`, `token` | Not compiled in (darwin-coupled — SPEC-0251 §5, see [`../CHANGELOG.md`](../CHANGELOG.md)) |

**Whisper on Windows** works **only if** a `whisper` executable is on your `PATH`
(m3c-tools shells out to it — it is not bundled). Without it, `whisper` and any transcription
step that needs it will fail.

---

## Part 3 — Configuration (both platforms)

Copy the example config and fill in your ER1 credentials. m3c-tools reads, in order:
the active profile, `~/.m3c-tools.env` (global), then a project-local `.env`.

**Intel Mac:**

```bash
cp .env.example ~/.m3c-tools.env     # or ./.env in the repo dir
$EDITOR ~/.m3c-tools.env
```

**Windows (PowerShell):**

```powershell
Copy-Item .\.env.example "$HOME\.m3c-tools.env"
notepad "$HOME\.m3c-tools.env"
```

### Key variables

| Variable | Purpose |
|----------|---------|
| `ER1_API_URL` | ER1 upload endpoint, e.g. `https://onboarding.guide/upload_2` |
| `ER1_API_KEY` | API key — sent **only** as the `X-API-KEY` header (see security note) |
| `ER1_CONTEXT_ID` | Context/user id for uploads, e.g. `1076…___mft` |
| `ER1_VERIFY_SSL` | `true` for a valid cert; `false` for local dev with self-signed certs |
| `ER1_UPLOAD_TIMEOUT` | HTTP upload timeout in seconds (default `600`) |
| `ER1_RETRY_INTERVAL` | Seconds between retry-queue cycles (default `300`) |
| `ER1_MAX_RETRIES` | Max retry attempts before dropping a failed upload (default `10`) |

See `.env.example` for the complete annotated list (whisper, screenshot, Plaud, audio-import
settings). Prefer the guided path — `m3c-tools setup` — which writes the config and verifies
reachability for you.

> **🔒 Security**
> - `ER1_API_KEY` is transmitted **only** as the `X-API-KEY` HTTP header — never on the
>   command line, never in logs. Do not print or echo it.
> - **Never commit `.env`.** It is gitignored (`.env`, `.env.*`, with `!.env.example` kept).
>   Keep real credentials in `~/.m3c-tools.env` or the active profile.

---

## Part 4 — Verify the setup

Run these on either platform, in order. (The binary prints two informational lines to
**stderr** on startup — `[config] profile: …` and `[auth] device token loaded …` — this is
**normal**, not an error.)

```bash
m3c-tools version        # build version, commit, build date
m3c-tools doctor         # full connectivity & config diagnostics (profile, auth, DNS, TLS, /health)
m3c-tools check-er1      # quick ER1 reachability probe (exit 1 if unreachable)
```

`doctor` is the authoritative health check — it reports the active profile, auth method
(Bearer device token vs API key), config conflicts, DNS/TLS, and the ER1 `/health` status.
On a released build, `version` prints `m3c-tools v2.10.0 (commit=…, built=…)`; a local source
build without release ldflags prints `m3c-tools dev (commit=none, built=unknown)`.

First-time onboarding (writes config, captures context id, checks reachability):

```bash
m3c-tools setup          # interactive: ER1 URL → login → default tags → API key
```

---

## Part 5 — Operate (core flows)

All commands below work on **both** platforms unless marked **🍎 macOS only**.

### YouTube capture

```bash
m3c-tools transcript <videoID>                      # plain-text transcript
m3c-tools transcript <videoID> --format srt         # text | srt | json | webvtt
m3c-tools transcript <videoID> --translate de       # translate to a target language
m3c-tools transcript <videoID> --list               # list available transcript tracks
m3c-tools thumbnail  <videoID>                       # download the video thumbnail (JPEG)
m3c-tools upload     <videoID> --impression "note"  # transcript + thumbnail → ER1
m3c-tools upload     <videoID> --audio note.wav      # attach an audio file to the upload
```

### Local transcription

```bash
m3c-tools whisper recording.wav                     # transcribe an audio file (needs whisper on PATH)
m3c-tools whisper recording.wav --model base        # tiny | base | small | medium | large
```

### ER1 retry queue

Failed uploads are queued and retried; the cluster inspects and manages that queue.

```bash
m3c-tools retry                                     # process the queued uploads now
m3c-tools schedule <entry_id> --transcript t.txt    # schedule an entry in the SQLite tracking DB
m3c-tools status                                    # show status of all retry entries
m3c-tools status --entry <id>                       # status of one entry
m3c-tools cancel <entry_id>                         # cancel a pending entry
```

### Tray / settings

```bash
m3c-tools menubar        # macOS: native Cocoa menubar · Windows: fyne system tray
m3c-tools settings       # open the profile settings editor in the browser (localhost)
```

The menu-bar app also does **reverse time tracking** — it infers project time
blocks from your capture tags (and logs `[reverse-tracking] no project match`
when a capture matches no project). See
[Menu Bar App → reverse tracking](menubar-app.md#how-reverse-tracking-works) and
the `M3C_REVERSE_*` variables in [Manual → Time tracking](manual-m3c-tools.md#time-tracking--reverse-tracking-menu-bar-app).

### Voice & screen capture — 🍎 macOS only

```bash
m3c-tools devices                       # 🍎 list audio input devices
m3c-tools record out.wav --duration 5   # 🍎 record 5s of 16kHz/16-bit mono WAV
m3c-tools screenshot --mode full        # 🍎 capture screen (full | window | region)
```

On Windows these print a "requires macOS" error and exit 1. Record on another device and bring
the WAV in via `whisper` / `upload`.

<a id="plaud-capture"></a>
### Plaud field-recording capture

**Windows — legacy surface (also on macOS):**

```bash
m3c-tools plaud auth login          # authenticate (extract token from Chrome)
m3c-tools plaud list                # list recordings + sync status + ER1 doc_id
m3c-tools plaud check               # sync-coverage report
m3c-tools plaud sync <#|ID>         # sync one recording to ER1
m3c-tools plaud sync --all          # sync all new recordings
m3c-tools plaud fix-times --apply   # backfill true recording time onto synced items
```

**🍎 macOS only — durable developer-API surface** (official OAuth token, no daily re-auth,
server-side whisper by default):

```bash
m3c-tools plaud dev list                    # 🍎 numbered list, newest first
m3c-tools plaud dev sync --all              # 🍎 capture → ER1 (server-side transcription)
m3c-tools plaud dev sync 1-5 --tags a,b     # 🍎 sync selected items (# / ID / N-M ranges)
m3c-tools plaud dev sync 3 --whisper        # 🍎 override: transcribe un-transcribed audio LOCALLY
m3c-tools plaud dev status                  # 🍎 server-side transcription queue progress
# extra flags: --dry-run   --force (re-sync)   --limit N
```

By default `plaud dev sync` leaves un-transcribed audio to the **server-side whisper** queue;
`--whisper` transcribes locally instead. `plaud dev` is **not available on Windows** — use the
legacy `plaud sync` there.

---

## Troubleshooting quick reference

| Symptom | Fix |
|---------|-----|
| `[config]` / `[auth]` lines on startup | Normal informational stderr output — ignore |
| macOS "developer cannot be verified" | `sudo xattr -d com.apple.quarantine <binary>` |
| `check-er1` → UNREACHABLE | Run `m3c-tools doctor`; verify `ER1_API_URL`, network, and `ER1_VERIFY_SSL` |
| `whisper` fails on Windows | Install a `whisper` binary and put it on `PATH` |
| `record`/`screenshot` error on Windows | Expected — macOS-only features |
| `plaud dev` unknown on Windows | Expected — use `plaud sync` (legacy); `dev` is macOS-only |

---

*See also:* [Platform differences](PLATFORM-DIFFERENCES.md) ·
[Getting started](getting-started.md) ·
[Quickstart: m3c-tools](quickstart-m3c-tools.md) ·
[Manual: m3c-tools](manual-m3c-tools.md)
