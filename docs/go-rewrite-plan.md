# YT Tools — Go Rewrite Plan

## 0. Full youtube-transcript-api Library Port

The Go module must include a **complete port** of the forked
[youtube-transcript-api](https://github.com/jdepoix/youtube-transcript-api)
library (6 source files, ~1,500 lines). Every public type, method, and error
must have a Go equivalent.

### Public API Surface

```
YouTubeTranscriptApi                      # Main entry point
  ├── New(opts ...Option) *Api            # Constructor (proxy config, custom HTTP client)
  ├── Fetch(videoID, langs, preserveFmt)  # Shortcut: list → find → fetch
  └── List(videoID) *TranscriptList       # Get available transcripts

TranscriptList                            # Iterable list of transcripts
  ├── FindTranscript(langCodes)           # Find by language (manual first, then generated)
  ├── FindGeneratedTranscript(langCodes)  # Find only auto-generated
  ├── FindManuallyCreatedTranscript(...)  # Find only manually created
  ├── Iter() iter.Seq[*Transcript]        # Iterate all (manual first, then generated)
  └── String() string                     # Human-readable listing

Transcript                                # Single transcript metadata
  ├── VideoID string
  ├── Language string
  ├── LanguageCode string
  ├── IsGenerated bool
  ├── TranslationLanguages []TranslationLanguage
  ├── IsTranslatable() bool
  ├── Translate(langCode) *Transcript     # Returns new Transcript with &tlang= URL
  └── Fetch(preserveFormatting) *FetchedTranscript

FetchedTranscript                         # Fetched transcript data
  ├── Snippets []FetchedTranscriptSnippet
  ├── VideoID, Language, LanguageCode, IsGenerated
  ├── Len() int
  └── ToRawData() []map[string]any

FetchedTranscriptSnippet                  # Single caption segment
  ├── Text string
  ├── Start float64                       # seconds
  └── Duration float64                    # seconds
```

### Formatters (all must be ported)

```
Formatter (interface)
  ├── FormatTranscript(*FetchedTranscript) string
  └── FormatTranscripts([]*FetchedTranscript) string

JSONFormatter           # JSON output
PrettyPrintFormatter    # Pretty-printed output
TextFormatter           # Plain text (no timestamps)
SRTFormatter            # SubRip subtitle format
WebVTTFormatter         # Web Video Text Tracks format
FormatterLoader         # Factory: "json" | "pretty" | "text" | "srt" | "webvtt"
```

### Proxy Support (all must be ported)

```
ProxyConfig (interface)
  ├── ToTransportConfig() *http.Transport   # Go equivalent of to_requests_dict()
  ├── PreventKeepAlive() bool
  └── RetriesWhenBlocked() int

GenericProxyConfig      # HTTP/HTTPS/SOCKS proxy
WebshareProxyConfig     # Rotating residential proxy (Webshare.io)
```

### Error Types (all 16 must be ported as Go error types)

```
YouTubeTranscriptApiError           # Base error
├── CookieError
│   ├── CookiePathInvalid
│   └── CookieInvalid
├── CouldNotRetrieveTranscript      # Base for retrieval errors
│   ├── YouTubeDataUnparsable
│   ├── YouTubeRequestFailed        # wraps HTTP error
│   ├── VideoUnavailable
│   ├── VideoUnplayable             # includes reason + sub-reasons
│   ├── InvalidVideoId
│   ├── TranscriptsDisabled
│   ├── AgeRestricted
│   ├── NotTranslatable
│   ├── TranslationLanguageNotAvailable
│   ├── FailedToCreateConsentCookie
│   ├── NoTranscriptFound           # includes requested langs + available transcripts
│   ├── PoTokenRequired
│   ├── RequestBlocked              # context-aware message (no proxy / generic / webshare)
│   └── IpBlocked
```

### CLI (must be ported as `yt-transcript` subcommand)

```
m3c-tools transcript <video_ids...>
  --list-transcripts           # List available languages
  --languages <lang...>        # Priority list (default: en)
  --exclude-generated          # Skip auto-generated
  --exclude-manually-created   # Skip manual
  --format <json|pretty|text|srt|webvtt>
  --translate <lang>           # Translate to language
  --http-proxy <url>
  --https-proxy <url>
  --webshare-proxy-username <user>
  --webshare-proxy-password <pass>
```

### Internal Implementation (TranscriptListFetcher)

The fetcher pipeline must be ported exactly:

1. `_fetch_video_html(videoID)` — GET `youtube.com/watch?v=ID`, handle EU consent cookie
2. `_extract_innertube_api_key(html)` — regex for `"INNERTUBE_API_KEY":"..."`
3. `_fetch_innertube_data(videoID, apiKey)` — POST to InnerTube API with Android client context
4. `_extract_captions_json(innertubeData)` — extract `captions.playerCaptionsTracklistRenderer`
5. `_assert_playability(status)` — check playability, raise specific errors
6. `_TranscriptParser.parse(xml)` — parse caption XML, handle HTML entities + formatting tags

### Go Package Structure for the Library

```
pkg/transcript/
  api.go              # YouTubeTranscriptApi (New, Fetch, List)
  transcript.go       # Transcript, TranscriptList, FetchedTranscript, FetchedTranscriptSnippet
  fetcher.go          # TranscriptListFetcher (HTML fetch, InnerTube API, caption extraction)
  parser.go           # TranscriptParser (XML parsing, HTML cleanup)
  formatter.go        # All formatters (JSON, Text, SRT, WebVTT, Pretty)
  proxy.go            # ProxyConfig, GenericProxyConfig, WebshareProxyConfig
  errors.go           # All 16 error types
  settings.go         # Constants (WATCH_URL, INNERTUBE_CONTEXT, INNERTUBE_API_URL)
  languages.go        # Language code → flag emoji mapping
```

### Go Dependencies for the Library Port

| Python | Go Equivalent |
|--------|---------------|
| `requests.Session` | `net/http.Client` (stdlib) |
| `requests.HTTPError` | `net/http` status code checks |
| `defusedxml.ElementTree` | `encoding/xml` (stdlib) |
| `html.unescape` | `html.UnescapeString` (stdlib) |
| `re` | `regexp` (stdlib) |
| `json` | `encoding/json` (stdlib) |
| `pprint` | `encoding/json` with indent |
| `argparse` | `flag` or `cobra` |

**Zero external dependencies needed for the core library.** Everything uses Go stdlib.

---

## 1. Current System Inventory

### Python Modules (9 files, ~3,500 lines + 1,500 lines library)

| Module | Purpose | Lines | Key Dependencies |
|--------|---------|-------|-----------------|
| `yt_menubar.py` | Menu bar app (rumps) — main entry point | ~1030 | rumps, PyObjC, youtube_transcript_api |
| `impression_capture.py` | Voice impression + ER1 upload orchestration | ~2050 | whisper (subprocess), requests, threading |
| `impression_recorder.py` | Tkinter audio recording dialog (PyAudio) | ~350 | tkinter, pyaudio, wave |
| `impression_tags.py` | Tag system + observation types | ~250 | stdlib only |
| `screenshot_capture.py` | Clipboard-first screenshot capture | ~200 | subprocess (osascript, screencapture) |
| `er1_config.py` | ER1 API configuration from env vars | ~170 | stdlib only |
| `er1_retry_scheduler.py` | Background retry with exponential backoff | ~300 | threading |
| `upload_queue.py` | JSON-backed offline upload queue | ~200 | json, threading |
| `audio_importer.py` | Batch audio import from GDrive folder | ~280 | shutil, re, datetime |

### Feature Map

| Feature | Description | macOS-Specific? |
|---------|-------------|-----------------|
| Menu bar icon + dropdown | rumps.App with icon, submenus, dynamic updates | Yes (NSStatusBar) |
| Fetch YouTube transcript | youtube_transcript_api, language fallback with dialog | No |
| Clipboard copy + confirmation dialog | pbcopy + rumps.alert | Yes (pbcopy, NSAlert) |
| Transcript history (JSON) | Last 20 transcripts, persistent storage | No |
| Voice impression recording | PyAudio mic capture, Tkinter record/stop dialog | Partially (mic access) |
| Whisper transcription | System Python subprocess with openai-whisper | No |
| Screenshot capture | NSPasteboard clipboard check + screencapture -i | Yes |
| ER1 multipart upload | requests POST with audio_data_ext, image_data, transcript_file_ext | No |
| Offline retry queue | JSON-backed queue with exponential backoff | No |
| Retry scheduler | Background thread, adaptive polling | No |
| Tag system | Observation types (progress/idea/impulse), auto-tags | No |
| MEMORY folder structure | Organized file storage per observation | No |
| Batch audio import | Scan folder, parse filenames, transcribe, upload | No |
| Quick impulse | Screenshot + optional voice, minimal friction | Partially |

### External Dependencies

| Python Package | Purpose | Go Equivalent |
|----------------|---------|---------------|
| `rumps` | macOS menu bar app | **caseymrm/menuet** or **energye/systray** |
| `PyObjC` | Objective-C bridge | **progrium/darwinkit** or cgo |
| `youtube_transcript_api` | Fetch YT transcripts | Port or HTTP-based approach |
| `pyaudio` | Mic recording | **gordonklaus/portaudio** |
| `openai-whisper` | Speech-to-text | **whisper.cpp Go bindings** (no Python!) |
| `requests` | HTTP client | **net/http** (stdlib) |
| `tkinter` | Recording/tag editor dialogs | **menuet** alerts or **fyne** |
| `Pillow` | Image handling | **image** (stdlib) |

---

## 2. Go Library Selection

### Killer Criteria: macOS Menu Bar

**Answer: Yes, Go can do macOS menu bar apps.** Three viable options:

#### Option A: `caseymrm/menuet` (Recommended)

The closest equivalent to Python's `rumps`. macOS-only, uses NSStatusBar directly.

| Feature | rumps (Python) | menuet (Go) |
|---------|---------------|-------------|
| Menu bar icon | `rumps.App(icon=...)` | `menuet.App().SetImage(name)` |
| Menu items | `rumps.MenuItem(title, callback)` | `MenuItem{Text: "", Clicked: func(){}}` |
| Submenus | `item.add(child)` | `MenuItem{Children: func() []MenuItem{}}` |
| Separators | `menu.add(None)` | `MenuItem{Type: menuet.Separator}` |
| Dynamic menus | `.clear()` + `.add()` | `Children` func re-evaluated on each open |
| Alert dialogs | `rumps.alert(title, msg, ok, cancel)` | `menuet.App().Alert(Alert{...})` |
| Text input dialogs | `rumps.Window(message, default_text)` | `Alert{Inputs: []string{"placeholder"}}` |
| Notifications | `rumps.notification(title, subtitle, msg)` | `menuet.App().Notification(Notification{...})` |
| Item icons | `item.icon = path; item.dimensions = (w,h)` | `MenuItem{Image: "name"}` |
| Checkmarks | N/A | `MenuItem{State: true}` |
| Timer callbacks | `rumps.Timer(callback, interval)` | `time.Ticker` in goroutine |

**Verdict**: menuet covers 100% of the rumps features we use.

#### Option B: `energye/systray` (Cross-platform fallback)

If cross-platform is ever needed. Fewer dialog features — would need `andybrewer/mack` for alerts.

#### Option C: `progrium/darwinkit` (Maximum flexibility)

Full Apple framework access. More code but unlimited macOS API access. Good for complex custom UI.

### Audio Recording: `gordonklaus/portaudio`

Direct equivalent to PyAudio. Records PCM from microphone, encode to WAV with `go-audio/wav`.

```go
portaudio.Initialize()
stream, _ := portaudio.OpenDefaultStream(1, 0, 16000, 1024, buffer)
stream.Start()
// read samples in loop
stream.Stop()
// encode to WAV
```

### Whisper: `whisper.cpp` Go bindings

**This is a major improvement over Python.** No Python subprocess needed. Native C++ whisper runs in-process via cgo.

```go
model, _ := whisper.New("ggml-base.bin")
defer model.Close()
context, _ := model.NewContext()
context.Process(samples, nil, nil)
for i := 0; i < context.NumSegments(); i++ {
    text += context.SegmentText(i)
}
```

Benefits:
- No Python/pip dependency at all
- Fast on Apple Silicon (uses Accelerate framework)
- Model file (~150MB for base) bundled with the app
- No subprocess, no env pollution, no PYTHONHOME issues

### YouTube Transcript: Custom HTTP client

The `youtube_transcript_api` Python library fetches transcripts via YouTube's internal API (no official API key needed). We'd port the core logic:

1. Fetch video page HTML
2. Extract `captions` JSON from `ytInitialPlayerResponse`
3. Fetch the transcript XML/JSON from the caption URL
4. Parse segments

This is ~200 lines of Go using `net/http` + `encoding/json` + `encoding/xml`.

### Dialogs & UI

| Dialog | Python | Go |
|--------|--------|-----|
| Video ID input | `rumps.Window()` | `menuet.Alert{Inputs: [...]}` |
| Language selection | `rumps.alert(ok=, cancel=)` | `menuet.Alert{Buttons: [...]}` |
| Clipboard confirmation | `rumps.alert()` | `menuet.Alert{}` |
| Recording dialog | Tkinter (subprocess) | menuet alert OR Fyne window |
| Tag editor | Tkinter (subprocess) | menuet alert with input OR Fyne form |
| Impression offer | `rumps.alert()` | `menuet.Alert{}` |

For the recording dialog (Record/Stop/Cancel with visual feedback), we have two options:
1. **Simple**: Use menuet alerts with a "Recording..." status + Stop button
2. **Rich**: Use a small Fyne window with canvas-based buttons (closer to current Tkinter UI)

---

## 3. Architecture: Go Rewrite

```
cmd/
  m3c-tools/
    main.go              # Entry point, menuet.App() setup
  yt-transcript/
    main.go              # CLI entry point (port of __main__.py / _cli.py)
pkg/
  menubar/
    app.go               # Menu bar app (menuet) — equivalent to yt_menubar.py
    history.go            # Transcript history persistence
    dialogs.go            # Alert/input dialogs
  transcript/
    api.go               # YouTubeTranscriptApi (New, Fetch, List)
    transcript.go        # Transcript, TranscriptList, FetchedTranscript, FetchedTranscriptSnippet
    fetcher.go           # TranscriptListFetcher (HTML, InnerTube, captions)
    parser.go            # XML transcript parser with HTML tag handling
    formatter.go         # JSON, Text, SRT, WebVTT, Pretty formatters
    proxy.go             # ProxyConfig, GenericProxyConfig, WebshareProxyConfig
    errors.go            # All 16 error types
    settings.go          # WATCH_URL, INNERTUBE_CONTEXT, INNERTUBE_API_URL
    languages.go         # Language codes + flag emojis
  impression/
    capture.go            # Voice impression orchestration
    recorder.go           # Audio recording (portaudio)
    tags.go               # Tag system + observation types
    composite.go          # Composite document creation
  screenshot/
    capture.go            # Clipboard + screencapture integration
  whisper/
    transcriber.go        # whisper.cpp Go bindings wrapper
  er1/
    config.go             # ER1 settings from env vars / .env
    uploader.go           # Multipart HTTP upload
    queue.go              # Persistent upload queue (JSON-backed)
    scheduler.go          # Retry scheduler with exponential backoff
  importer/
    audio.go              # Batch audio import from GDrive folder
    parser.go             # Filename parsing (tags + timestamp)
    tracker.go            # Import tracking (avoid re-processing)
internal/
  env/
    dotenv.go             # .env file parser
  fileutil/
    memory.go             # MEMORY folder management
resources/
  yt_icon.png             # Menu bar icon
  yt_icon_color_16.png
  yt_icon_color_64.png
  ggml-base.bin           # Whisper model (bundled)
```

### Module Mapping

| Python Module | Go Package | Notes |
|---------------|-----------|-------|
| `youtube_transcript_api/` | `pkg/transcript/` | Full library port: api, fetcher, parser, formatters, proxy, errors |
| `youtube_transcript_api/_cli.py` | `cmd/yt-transcript/` | CLI with cobra or flag |
| `yt_menubar.py` | `pkg/menubar/` | menuet.App replaces rumps.App |
| `impression_capture.py` | `pkg/impression/` | Split into capture + composite + recorder |
| `impression_recorder.py` | `pkg/impression/recorder.go` | portaudio replaces pyaudio |
| `impression_tags.py` | `pkg/impression/tags.go` | Direct port |
| `screenshot_capture.py` | `pkg/screenshot/` | exec.Command("screencapture"), CGo for NSPasteboard |
| `er1_config.py` | `pkg/er1/config.go` | Direct port using os.Getenv |
| `er1_retry_scheduler.py` | `pkg/er1/scheduler.go` | goroutines + time.Ticker replace threading.Thread |
| `upload_queue.py` | `pkg/er1/queue.go` | sync.Mutex replaces threading.RLock |
| `audio_importer.py` | `pkg/importer/` | Direct port |

---

## 4. Migration Strategy

### Phase 1: Skeleton + Menu Bar (Week 1)

- Set up Go module, directory structure
- Implement menuet-based menu bar app with static menu
- Icon loading, "Quit" action
- `.env` parsing
- Build as `.app` bundle (use `go build` + script to create `.app` structure)

### Phase 2: youtube-transcript-api Library Port (Week 1-2)

- Port `_transcripts.py`: Transcript, TranscriptList, FetchedTranscript, FetchedTranscriptSnippet
- Port `_api.py`: YouTubeTranscriptApi with Fetch() and List()
- Port `TranscriptListFetcher`: HTML fetch, InnerTube API, consent cookie, playability checks
- Port `_TranscriptParser`: XML parsing, HTML entity unescaping, formatting tag preservation
- Port all 16 error types from `_errors.py`
- Port `formatters.py`: JSON, Text, SRT, WebVTT, PrettyPrint
- Port `proxies.py`: GenericProxyConfig, WebshareProxyConfig
- Port `_cli.py`: CLI tool with all flags (--languages, --format, --translate, --list-transcripts, etc.)
- Write tests (port from `youtube_transcript_api/test/`)

### Phase 3: Menu Bar Integration (Week 2)

- Language detection + selection dialog (menuet.Alert)
- Clipboard copy (exec.Command("pbcopy"))
- History persistence (JSON file)
- Transcript confirmation dialog

### Phase 4: ER1 Upload (Week 2-3)

- Port er1_config (env var reading)
- Multipart HTTP upload with net/http
- Upload queue (JSON-backed, sync.Mutex)
- Retry scheduler (goroutine + time.Ticker)
- Retry queue menu panel

### Phase 5: Whisper + Voice Recording (Week 3)

- Integrate whisper.cpp Go bindings
- Bundle ggml-base.bin model
- Implement portaudio recording
- Recording dialog (menuet alert or Fyne window)
- Tag system + tag editor dialog

### Phase 6: Screenshot + Impulse (Week 3-4)

- Screenshot capture (screencapture CLI, NSPasteboard via CGo)
- Screenshot observation flow
- Quick impulse capture
- Composite document creation

### Phase 7: Audio Importer (Week 4)

- Filename parser
- Folder scanner
- Tracker file
- Batch import with progress

### Phase 8: Polish + Packaging (Week 4-5)

- `.app` bundle build script (go build + macOS bundle structure)
- Code signing
- DMG or zip packaging
- Install/uninstall scripts
- Lifecycle scripts (start/stop/update)

---

## 5. Advantages of Go Rewrite

| Aspect | Python (current) | Go (proposed) |
|--------|-----------------|---------------|
| **Binary size** | ~50MB .app (py2app + framework) | ~15-20MB (static binary + whisper model) |
| **Startup time** | 2-3s (Python interpreter) | <100ms |
| **Whisper** | Subprocess to system Python | In-process via whisper.cpp (faster, no deps) |
| **Dependencies** | pip install rumps pyobjc pyaudio whisper... | `go build` (single command) |
| **Thread safety** | threading.Lock, GIL limitations | goroutines + channels (native concurrency) |
| **Distribution** | py2app bundle + system Python for whisper | Single binary + model file |
| **macOS integration** | PyObjC bridge (fragile) | CGo / menuet (direct) |
| **Tkinter workaround** | Subprocess to system Python (PYTHONHOME hack) | Not needed — native dialogs |
| **Crash resilience** | Python exceptions, subprocess failures | Go error handling, no subprocess needed |

---

## 6. Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| `caseymrm/menuet` not actively maintained | Medium | Fork or fallback to darwinkit |
| whisper.cpp Go bindings API changes | Low | Pin version, model format is stable |
| YouTube transcript API changes | Medium | Same risk as Python; abstract fetcher interface |
| portaudio macOS permissions | Low | Same as Python; .app bundle + Info.plist |
| No rich recording dialog UI | Medium | Start with menuet alerts; add Fyne window later if needed |
| youtube_transcript_api port effort | High | Could wrap the Python lib initially, port later |

---

## 7. Build & Distribution

### .app Bundle Structure

```
YT Transcript.app/
  Contents/
    Info.plist           # LSUIElement=1, CFBundleIdentifier, etc.
    MacOS/
      m3c-tools           # Go binary
    Resources/
      yt_icon.icns       # App icon
      yt_icon_color_16.png
      yt_icon_color_64.png
      ggml-base.bin      # Whisper model (~150MB)
      .env               # Default config
```

### Build Script

```bash
#!/bin/bash
GOOS=darwin GOARCH=arm64 go build -o YT-Transcript ./cmd/m3c-tools
# Create .app bundle structure
# Copy resources
# Sign with codesign
```

**No py2app, no Python framework, no system Python dependency.**

---

## 8. Verdict

**Yes, a full Go rewrite is feasible.** Every component has a proven Go equivalent:

- Menu bar: **menuet** (closest to rumps)
- Alert/input dialogs: **menuet** built-in (no Tkinter subprocess hack needed)
- Audio recording: **gordonklaus/portaudio**
- Whisper: **whisper.cpp Go bindings** (major improvement — in-process, no Python)
- HTTP upload: **net/http** stdlib
- Screenshot: **exec.Command + CGo** for NSPasteboard
- YouTube transcripts: Port ~200 lines of HTTP + parsing logic

The **biggest win** is eliminating the Python/whisper subprocess dance (PYTHONHOME, path detection, system Python dependency). The Go version would be a single self-contained binary with the whisper model bundled.

**Estimated effort**: 4-5 weeks for a feature-complete port including the full youtube-transcript-api library.

---

## 9. POC Validation Results (2026-03-09)

All four POCs built and tested successfully:

| POC | Component | Result | Notes |
|-----|-----------|--------|-------|
| 1 - Menu Bar | `menuet` macOS native | **PASS** | Builds, dialogs, notifications, history submenu |
| 2 - Transcript | `pkg/transcript/` library | **PASS** | 61 snippets fetched live (Rick Astley), all formatters work |
| 3 - Whisper | CLI subprocess (`/opt/homebrew/bin/whisper`) | **PASS** | 22 segments from German audio, JSON parsed with timing |
| 4 - Recorder | `gordonklaus/portaudio` native | **PASS** | MacBook Pro mic detected, 16kHz WAV written |
| 5 - Thumbnail | `pkg/transcript/thumbnail.go` | **PASS** | 220KB maxresdefault.jpg fetched |
| 6 - ER1 Upload | Full multimodal POST | **PASS** | Text + Audio + Image → GCS + Firestore |

### Key Technical Findings

- **Caption URLs**: Must strip `&fmt=srv3` from `baseUrl` to get classic XML format (Python lib does this)
- **Cookie jar**: Must use `http.CookieJar` with `CONSENT=YES+cb` on all YouTube requests
- **InnerTube API**: Always use InnerTube API for captions (never HTML parsing)
- **PoToken check**: URLs with `&exp=xpe` require Proof-of-Origin token (raise error, same as Python lib)
- **ER1 server bug**: `/upload_2` requires `image_data` field — crashes with `FileNotFoundError` if missing. Must always send image (use thumbnail or 1x1 placeholder)
- **Whisper approach**: Subprocess to CLI is simpler and sufficient for POC. Native whisper.cpp bindings can follow in production if performance matters.

### Design Decision: YouTube Thumbnail as Image Modality

For YouTube transcript imports, the system now captures the video's **title image (thumbnail)** and includes it as the `image_data` field in the ER1 upload. This:

1. Solves the ER1 server bug (image always present)
2. Provides visual context in the knowledge server
3. Uses YouTube's public thumbnail API: `https://img.youtube.com/vi/{id}/maxresdefault.jpg`
4. Falls back through sizes: maxresdefault → sddefault → hqdefault → mqdefault → default

New file: `pkg/transcript/thumbnail.go` with `FetchThumbnail()` and `ThumbnailURL()` methods.

### Multimodal Memory Capture — Formal Definition

**Multimodal Memory Capturing** is the process of recording an observation about digital content through up to three sensory channels (text, audio, image) and persisting it as a single structured entry in an ER1 knowledge server.

Each memory entry consists of:

| Modality | Field | Format | Required |
|----------|-------|--------|----------|
| Text | `transcript_file_ext` | Composite .txt document | Always |
| Audio | `audio_data_ext` | WAV 16kHz/16-bit mono | Always* |
| Image | `image_data` | PNG screenshot or JPEG thumbnail | Always* |

*The ER1 server requires all three fields. For YouTube imports, the thumbnail serves as the image. For audio-only imports, a 1x1 placeholder image is sent.

Four observation types feed into the system:
- **Progress** (YouTube): transcript + voice impression + video thumbnail
- **Idea** (Screenshot): user annotation + voice note + screenshot
- **Impulse** (Quick): auto-text + optional voice + optional screenshot
- **Audio Import** (Batch): whisper transcription + original audio + placeholder image
