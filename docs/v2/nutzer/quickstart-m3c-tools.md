---
layout: default
title: "Quickstart: m3c-tools"
---

# Quickstart: m3c-tools

[Deutsch](quickstart-m3c-tools.de.md) · [English](quickstart-m3c-tools.md)

Capture your first multimodal memory in about five minutes. By the end you'll have
`m3c-tools` installed, connected to an [ER1](https://er1.io) knowledge server, and a
YouTube transcript fetched and (optionally) uploaded.

> **What is m3c-tools?** A capture pipeline: it turns YouTube videos, audio, screenshots
> and voice notes into structured, multimodal observations stored on *your* ER1 server.
> On macOS it's a native menu-bar app; on Linux/Windows it's a full CLI. For the exhaustive
> command reference, see the [m3c-tools manual](../referenz/manual-m3c-tools.md).

---

## 1. Install

This installs `m3c-tools` for your user, with no admin rights. You need cosign, or an OpenSSL with ed25519 support. On macOS run `brew install cosign` first.

```bash
curl -fsSL https://raw.githubusercontent.com/kamir/m3c-tools/953dd07dfe440309f5702f296346b5e85bc5c1e1/tools/m3c-tools-install.sh | bash
```

```powershell
irm https://raw.githubusercontent.com/kamir/m3c-tools/953dd07dfe440309f5702f296346b5e85bc5c1e1/tools/m3c-tools-install.ps1 | iex
```

The URLs are pinned to an immutable commit. Expected SHA-256: `tools/m3c-tools-install.sh` is `709f6bd339c1feedcb1e2156348823341b1192ba3c139765e2fff8f5fddf67e7`; `tools/m3c-tools-install.ps1` is `b54a562f17fe6c1c8cf34375e002a0286859359e421f397a6bf95065f7dd3339`. The [README](../../../README.md#verify-before-you-run) has a verify-then-run recipe.

Check it, then fetch a first transcript. This needs no account:

```bash
m3c-tools version
m3c-tools transcript dQw4w9WgXcQ
```

> **Prefer to build from source?** You need Go 1.26.10+. On macOS the menu-bar GUI also needs
> `brew install pkg-config portaudio ffmpeg` and `python3 -m pip install openai-whisper`.
> Then `make install`. See [Build from source](../../../README.md#build-from-source).

---

## 2. Connect to ER1 (guided setup)

```bash
m3c-tools setup
```

The wizard walks you through:

1. **ER1 server URL**: defaults to `https://onboarding.guide/upload_2`.
2. **Browser login**: opens Chrome and captures your User ID (context) automatically.
3. **API key**: required for uploads (sent as the `X-API-KEY` header). To request access, write to mirko.kaempf@gmail.com.
4. **Default tags**: used for capture-device sync.

It writes everything to `~/.m3c-tools.env`.

> **Login vs. API key.** The browser login captures your *context* and can also store a
> device token. Uploads authenticate with an API key **or** a device token: set up at
> least one. Run `m3c-tools login` any time to (re-)pair via the browser.

**Prefer manual config?** Copy the template and edit it:

```bash
cp .env.example ~/.m3c-tools.env
```

```ini
ER1_API_URL=https://onboarding.guide/upload_2
ER1_API_KEY=your-api-key
ER1_CONTEXT_ID=your-context-id
```

Full variable reference: [m3c-tools manual → Configuration](../referenz/manual-m3c-tools.md#configuration-reference).

---

## 3. Verify

```bash
m3c-tools doctor
```

`doctor` checks the active profile, authentication (API key and/or device token), DNS, TLS,
and the ER1 `/health` and auth endpoints. Green across the board means you're ready.
With no ER1 configured, it says so, names what works without one, and exits `0`.
For a quick reachability-only check, use `m3c-tools check-er1`.

---

## 4. Your first capture

### Fetch a YouTube transcript (no ER1 needed)

```bash
m3c-tools transcript dQw4w9WgXcQ                 # plain text
m3c-tools transcript dQw4w9WgXcQ --format srt    # SubRip
m3c-tools transcript dQw4w9WgXcQ --list          # list available languages
m3c-tools transcript dQw4w9WgXcQ --translate de  # translate to German
```

Uses YouTube's InnerTube API: **no API key required**. Supports `text`, `srt`, `json`,
`webvtt`, proxies (`--proxy-url`), and translation.

### Capture a full observation to ER1

```bash
m3c-tools upload dQw4w9WgXcQ --impression "Great intro to the topic"
```

This fetches the transcript **and** the thumbnail, builds a composite document, and uploads
it to ER1. If subtitles are disabled, it still captures the **thumbnail and the link** so
the observation is never empty. Add your own audio with `--audio note.wav`.

### Transcribe local audio

```bash
m3c-tools whisper meeting.wav --model base --language en
```

Runs your local `whisper` binary. The first run downloads the model (~150 MB for `base`).

### Batch-import a folder of audio (macOS)

```bash
m3c-tools import-audio ~/m3c-inbox/ --run     # transcribe + upload + tag, end-to-end
m3c-tools import-audio --extensions           # show supported formats
```

Progress is tracked in a local SQLite DB, so re-runs skip what's already done.

---

## 5. Launch the menu-bar app (macOS)

```bash
open /Applications/M3C-Tools.app     # after `make install`
# or, in dev:
make menubar
```

A menu-bar icon appears. From there:

- **Fetch Transcript…** → paste a YouTube URL.
- **Capture Screenshot** → annotate + voice note → Store to ER1.
- **Projects** → your PLM project list (time tracking).

See the [Menu Bar App guide](menubar-app.md) for every menu item and the Observation Window.

---

## 6. Capture devices (optional)

If you use a **Plaud** recorder or a **Pocket** device:

```bash
m3c-tools plaud auth login      # pair (auto-launches Chrome): macOS/Windows/Linux
m3c-tools plaud list            # list recordings + sync status
m3c-tools plaud sync all        # sync everything to ER1

m3c-tools pocket ...            # see: m3c-tools pocket --help
```

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `doctor` shows `key_set=false` / auth failing | Your active profile has no real key. Re-run `m3c-tools setup` or `m3c-tools login`; ensure `ER1_API_KEY` isn't a placeholder. |
| "Projects" menu stuck on *Loading projects…* | No ER1 credential reached the app. Fix the active profile's key or run `login`, then restart the menu-bar app. |
| `subtitles are disabled for this video` | Expected. The capture still keeps the thumbnail + link. Add a voice note. |
| Whisper "command not found" | Install it: `python3 -m pip install openai-whisper` (needs `ffmpeg`). |
| `import-audio --run` exits `1` and reports `failed=1` | A transcription or an upload failed. A file with a failed transcription is not uploaded and is picked up again on the next run. A failed upload is queued; run `m3c-tools retry`. |
| Upload fails, then retries | Failed uploads queue locally. `m3c-tools status` shows `Uploads waiting for retry`. `m3c-tools retry` delivers them and keeps running until you stop it with Ctrl+C. |

---

## Next steps

- **Every command and flag:** [m3c-tools manual](../referenz/manual-m3c-tools.md)
- **Govern the skills your agents run:** [Quickstart: skillctl](quickstart-skillctl.md)
- **Platform-specific behavior:** [Platform differences](../referenz/PLATFORM-DIFFERENCES.md)
