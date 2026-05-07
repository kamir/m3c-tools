# m3c-tools

**Multi-Modal-Memory-Capturing Tools** — a macOS menu bar app and CLI for capturing observations (text + audio + image) and uploading them to an [ER1](https://er1.io) personal knowledge server.

---

## Quickstart (5 minutes)

### 1. Install prerequisites

```bash
brew install portaudio           # microphone recording
pip install openai-whisper       # speech-to-text (or: brew install openai-whisper)
```

Requires **Go 1.25+** and **macOS** (Cocoa UI via cgo).

### 2. Build and install

```bash
git clone https://github.com/kamir/m3c-tools.git
cd m3c-tools
make install
```

This builds the binary, creates `M3C-Tools.app`, installs both to `/usr/local/bin` and `/Applications`, and walks you through macOS permission setup (Microphone, Screen Recording).

### 3. Configure

```bash
cp .env.example ~/.m3c-tools.env
```

Edit `~/.m3c-tools.env` — the three required settings for ER1 upload:

```
ER1_API_URL=https://your-er1-server:8081/upload_2
ER1_API_KEY=your-api-key
ER1_CONTEXT_ID=your-context-id
```

### 4. Launch

```bash
make menubar
```

Or open `/Applications/M3C-Tools.app`. A menu bar icon appears — you're ready to capture.

### 5. Try it

- **Fetch a transcript**: click the menu bar icon → *Fetch Transcript...* → paste a YouTube URL
- **Screenshot observation**: click *Capture Screenshot* → record a voice note → Store to ER1
- **CLI only**: `m3c-tools transcript dQw4w9WgXcQ --format srt`

---

## What does m3c-tools do?

m3c-tools captures four types of observations, each flowing through a shared pipeline:

```
Capture → Preview + Record → Whisper Transcribe → Tag Editor → Store to ER1
```

| Channel | Trigger | What it captures |
|---------|---------|------------------|
| **A — YouTube** | Paste video URL | Transcript + thumbnail + your voice comment |
| **B — Screenshot** | Menu item | Screenshot + voice note (uses clipboard image if present) |
| **C — Impulse** | Menu item | Interactive region capture + quick voice note |
| **D — Audio Import** | Menu item | Batch audio files from a folder (e.g. voice recorder sync) |

Each observation becomes a multimodal ER1 document: text transcript + audio recording + image, with tags and metadata.

---

## Configuration Reference

Settings are loaded from `.env` in the project root or `~/.m3c-tools.env`. See [`.env.example`](.env.example) for all options.

### Required for ER1 upload

| Variable | Description |
|----------|-------------|
| `ER1_API_URL` | ER1 upload endpoint URL |
| `ER1_API_KEY` | API key (sent as `X-API-KEY` header) |
| `ER1_CONTEXT_ID` | Your ER1 context/user identifier |

### Whisper (speech-to-text)

| Variable | Default | Description |
|----------|---------|-------------|
| `M3C_WHISPER_MODEL` | `base` | Model size: `tiny`, `base`, `small`, `medium`, `large` |
| `M3C_WHISPER_TIMEOUT` | `7200` | Transcription timeout in seconds |
| `YT_WHISPER_LANGUAGE` | `de` | Language code (ISO 639-1) |
| `M3C_WHISPER_PRELOAD` | `true` | Preload model at startup |

### Screenshot capture

| Variable | Default | Description |
|----------|---------|-------------|
| `M3C_SCREENSHOT_MODE` | `clipboard-first` | `clipboard-first` or `interactive` |
| `M3C_SCREENSHOT_CLIPBOARD_TIMEOUT_SEC` | `20` | Wait time for clipboard image |

### Audio import (Channel D)

| Variable | Default | Description |
|----------|---------|-------------|
| `IMPORT_AUDIO_SOURCE` | — | Source folder for audio files |
| `IMPORT_AUDIO_DEST` | `~/ER1` | Destination for MEMORY folders |
| `IMPORT_CONTENT_TYPE` | — | ER1 content-type label |

### ER1 tuning

| Variable | Default | Description |
|----------|---------|-------------|
| `ER1_UPLOAD_TIMEOUT` | `600` | HTTP timeout in seconds |
| `ER1_VERIFY_SSL` | `false` | TLS certificate verification |
| `ER1_RETRY_INTERVAL` | `300` | Seconds between retry cycles |
| `ER1_MAX_RETRIES` | `10` | Max retries before dropping |

---

## Build & Test

```bash
make build          # Build CLI binary → ./build/m3c-tools
make build-app      # Build macOS .app bundle
make menubar        # Build + launch menu bar app
make install        # Full install (CLI + .app + permissions)

make test-unit      # Offline unit tests
make ci             # Full CI: vet + lint + test + build
make test-network   # YouTube API tests (requires internet)
make test-er1       # ER1 integration tests (requires server)

make help           # Show all targets
```

Run a single test:

```bash
go test -v -count=1 ./e2e/ -run TestTranscriptFetch
```

---

## Architecture

```
cmd/m3c-tools/       CLI + menu bar app entry point
pkg/transcript/      YouTube InnerTube API client (pure Go, no API key)
pkg/er1/             ER1 upload client + retry queue
pkg/impression/      Composite document builder + tag system
pkg/whisper/         Whisper CLI subprocess wrapper
pkg/recorder/        PortAudio microphone recording (cgo)
pkg/screenshot/      macOS screenshot capture + clipboard detection
pkg/menubar/         Native Cocoa UI via cgo (NSWindow, NSTabView, etc.)
pkg/importer/        Batch audio import pipeline
pkg/tracking/        SQLite tracking database
```

## Documentation

Full documentation: **[kamir.github.io/m3c-tools](https://kamir.github.io/m3c-tools)**

- [Getting Started](https://kamir.github.io/m3c-tools/getting-started)
- [Menu Bar App](https://kamir.github.io/m3c-tools/menubar-app)
- [Audio Import & Tracking](https://kamir.github.io/m3c-tools/audio-import-tracking)
- [Roadmap](https://kamir.github.io/m3c-tools/roadmap)

## Uninstalling

```bash
make uninstall
```

Data at `~/.m3c-tools/` is preserved — remove manually if desired.

## Branch & worktree workflow

The repo uses a strict feature-branch + worktree workflow. Following these
rules prevents the "uncommitted overnight work disappears in branch chaos"
class of incident (post-mortem: `m3c-tools-maintenance/PLAN/incident-2026-05-07-m3c-tools-master-drift.md`).

### Naming

Branch names match `^(feat|feature|fix|chore|docs|test|refactor|spec-\d+|s\d+-m\d+|r-\d+|archive|rescue)/.+$`.
This is enforced on PR open by the `branch-name-check` GH Action.

Examples:
- `feat/spec-0188-bundle-pack` — feature for a SPEC.
- `fix/bug-0124-time-tracking-auth` — bug fix.
- `s2-m1/awareness-sync` — sprint 2, milestone 1.
- `r-01/tenant-aware-verifier` — release-blocker R-01.
- `archive/<name>` — historical refs preserved as branches (typically also tagged).

`master`, `main`, `gh-pages`, and `pre-release-*` are reserved.

### Worktrees

Each active branch gets one worktree under `../wt/<spec>/<short-name>`.
Create with the canonical entry-point:

```bash
make worktree SPEC=spec-0195 STEP=awareness-S2.1 BRANCH=s2-m1/awareness-sync
# creates ../wt/spec-0195/awareness-S2.1, attaches to (or creates) the branch
```

Optional `BASE=<ref>` (default `origin/master`) controls where new branches start.

### Audit

```bash
git wta              # global alias — works from any repo
make branches-audit  # in-repo equivalent
```

Both print path / branch / age / dirty-file count. Use them at session start
and end. A nightly launchd job runs `~/.config/m3c/end-of-day-audit.sh` at
23:30 and posts a macOS notification if any worktree is dirty.

### Don't

- **Don't `git checkout master`** to "clean up" — local `master` is a tracking
  ref that follows `origin/master`; only update it via `git land` (alias)
  or by going through PR merge. Direct work on master is an anti-pattern.
- **Don't leave merged feature branches around.** A weekly GH Action
  (`archive-merged-branches.yml`) auto-tags merged PR branches as
  `archive/<branch>` and deletes them on origin; pull + prune to keep your
  local view tidy:
  ```bash
  git fetch origin --prune
  git branch --merged origin/master | grep -v master | xargs -n1 git branch -D
  ```
- **Don't share a worktree across two branches.** One branch, one worktree.
  Switch by creating a second worktree, not by `git checkout` inside the
  existing one.

### Recovery

If you lose track:
- `git reflog --date=iso` — every HEAD movement, with timestamps. Reflog
  entries live 90 days. If a branch tip got lost, it's recoverable here.
- `archive/<name>` tags on origin — every merged-and-deleted branch lives
  on as a tag.
- `m3c-tools-maintenance/PLAN/incident-2026-05-07-m3c-tools-master-drift.md`
  — full recovery worked example (master → wrong line → fix).

## License

See [LICENSE](LICENSE).
