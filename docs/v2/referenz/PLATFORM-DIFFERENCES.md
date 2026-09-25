# M3C Tools: Platform Differences

## Feature Matrix

| Feature | macOS | Windows | Linux |
|---------|-------|---------|-------|
| **System tray / menubar** | Native Cocoa (menuet) | System tray (systray) | System tray (systray) |
| **Tray icon** | Template image (auto dark/light) | Static PNG icon | Static PNG icon |
| **Voice recording** | PortAudio (built-in mic) | Not available | Not available |
| **Screenshot capture** | Native screencapture | Not available | Not available |
| **Whisper transcription** | Local whisper binary | Local whisper binary | Local whisper binary |
| **Transcript fetching** | Full | Full | Full |
| **Plaud Sync: legacy** (`plaud auth/list/sync/check`) | Full (Chrome CDP + API) | API only | API only |
| **Plaud Sync: durable dev API** (`plaud dev`) | Full (OAuth, server-side whisper) | Not available¹ | Not available¹ |
| **Pocket Sync** (`pocket`, `import-audio`, `token`) | USB + API | Not available¹ | Not available¹ |
| **ER1 Upload** | Full | Full | Full |
| **Config profiles** | Full | Full | Full |
| **Settings editor** | Web UI (localhost) | Web UI (localhost) | Web UI (localhost) |
| **skillctl** | Full | Full | Full |
| **skillctl trust-freeze** | The bundle lifecycle plus the portable `common.identity` probe. No macOS probe family exists, so a capture with a Linux profile is honestly `incomplete` | The bundle lifecycle, unit-tested on `windows-latest` by the Windows Gate. No Windows or WSL probe family exists, and no end-to-end run of the verbs on a real Windows host is recorded yet² | Twelve Linux probes plus `common.identity`, profile `ubuntu-bastion` version 3, executed on real hosts |
| **Auto-start on login** | LaunchAgent plist | Registry Run key | Systemd user service |
| **.app bundle** | Yes | No | No |
| **Keyboard shortcuts** | Global hotkeys (planned) | Not yet | Not yet |
| **Notifications** | Native (menuet) | Not yet | Not yet |

² Where a real run is claimed is decided by a round entry in
[`tests/evidence/trust-freeze/release-matrix.json`](../../../tests/evidence/trust-freeze/release-matrix.json),
never by this table and never by prose beside it. The evidence vocabulary keeps
`implemented`, `fixture-tested`, `cross-compiled` and `real-platform-tested`
apart on purpose: cross-compiling is not a platform test. A capture on a
platform without its own probe family is not broken, it is `incomplete` and says
which probes did not run.

¹ These command clusters (`plaud dev`, `pocket`, `import-audio`, `token`) are
still coupled to the darwin `main.go` and are **not compiled into** the non-darwin
build (`main_other.go`), on Windows/Linux they resolve to "Unknown command".
Multi-platform parity is tracked under **Pending / SPEC-0251 §5** in
[`../CHANGELOG.md`](../../../CHANGELOG.md). On Windows/Linux use the legacy `plaud sync`.

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    cmd/m3c-tools/                          │
├──────────────────────┬───────────────────────────────────┤
│  main.go             │  main_other.go                     │
│  //go:build darwin   │  //go:build !darwin                │
│                      │                                    │
│  Uses:               │  Uses:                             │
│  • pkg/menubar/      │  • pkg/tray/                       │
│    (menuet, Cocoa)   │    (fyne.io/systray)               │
│  • pkg/recorder/     │  • CLI-only features               │
│    (PortAudio, cgo)  │    (no cgo required)               │
│  • pkg/screenshot/   │                                    │
│    (screencapture)   │                                    │
├──────────────────────┴───────────────────────────────────┤
│               Shared packages (all platforms)             │
│  pkg/er1/, ER1 upload pipeline                    │
│  pkg/plaud/, Plaud sync + API client                │
│  pkg/transcript/, YouTube transcript fetcher             │
│  pkg/impression/, Composite document builder             │
│  pkg/tracking/, SQLite tracking DB                     │
│  pkg/whisper/, Whisper transcription (subprocess)     │
│  pkg/config/, Profile manager + settings editor      │
│  pkg/skillctl/, Skill scanner + delta engine           │
└──────────────────────────────────────────────────────────┘
```

## Menu Comparison

### macOS (menuet: native Cocoa)

- Dynamic submenus (children rebuilt on each open)
- NSImage template icons per menu item (auto dark/light)
- Native Cocoa windows (Plaud Sync, Tracking DB, Time Tracking)
- Floating observation window with text input
- Global keyboard shortcuts (planned)
- macOS notifications via menuet

### Windows/Linux (systray: cross-platform)

- Static menu structure (rebuilt on state change via systray.Quit + systray.Run cycle)
- Single tray icon (no per-item icons in systray)
- Web-based UIs (settings editor, review UI) opened in default browser
- Actions open browser or run CLI commands
- No native windows (all interaction via web UI or terminal)

### Key Differences for Users

| What | macOS | Windows/Linux |
|------|-------|---------------|
| Tray appearance | Custom icon per menu item | Text-only menu items |
| Plaud Sync window | Native Cocoa table | Opens browser (planned) |
| Voice recording | Built-in (PortAudio) | Use external recorder + import |
| Screenshots | One-click capture | Use OS screenshot + import |
| Observation window | Native floating dialog | Opens browser (planned) |
| Settings | Web editor or native | Web editor only |

## Build Requirements

| Platform | CGO | Dependencies | Build command |
|----------|-----|-------------|---------------|
| macOS arm64 | Yes | PortAudio, Cocoa frameworks | `go build ./cmd/m3c-tools` |
| macOS amd64 | Yes | PortAudio (universal), Cocoa | Cross-compile with CGO flags |
| Windows amd64 | No | None | `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/m3c-tools` |
| Linux amd64 | No | None | `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/m3c-tools` |
| Linux arm64 | No | None | `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build ./cmd/m3c-tools` |

## Installation

| Platform | Package | Command |
|----------|---------|---------|
| macOS | Homebrew (planned) | `brew install kamir/tap/m3c-tools` |
| macOS | DMG (local build only) | `make dmg`; NOT a release asset, see [releasing.md](../betrieb/releasing.md#the-macos-dmg-is-not-a-release-asset) |
| Windows | NSIS installer | `M3C-Tools-Setup.exe` |
| Windows | Winget (planned) | `winget install kamir.m3c-tools` |
| Linux | APT (planned) | `apt install m3c-tools` |
| Linux | Direct | Download binary, add to PATH |
| All | Go install | `go install github.com/kamir/m3c-tools/cmd/m3c-tools@latest` |
