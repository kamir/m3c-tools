---
layout: default
title: Erste Schritte
---

# Erste Schritte

[Deutsch](getting-started.de.md) · [English](getting-started.md)

## Voraussetzungen

- **macOS**: Die Menüleisten-App verwendet natives Cocoa über cgo.
- **Go 1.26.10+** für den Build aus Quellcode.
- **Homebrew-Abhängigkeiten**, gemeinsam installieren:
  ```bash
  brew install pkg-config portaudio ffmpeg
  ```
  - `pkg-config`: cgo benötigt es zum Finden der PortAudio-Header.
  - `portaudio`: Mikrofonaufnahme.
  - `ffmpeg`: Audiodekodierung; Whisper benötigt es zur Laufzeit.
- **Whisper** für die Spracherkennung:
  ```bash
  python3 -m pip install openai-whisper
  ```
  > **Hinweis:** Beim ersten Einsatz lädt Whisper sein Sprachmodell automatisch herunter. Das Standardmodell `base` ist etwa 150 MB groß, `medium` etwa 1,5 GB. Beim ersten Start ist Internetzugang erforderlich. Vorab herunterladen mit: `whisper --model base /dev/null`
- **ER1-Server**, optional: zum Hochladen von Beobachtungen in die Wissensbasis.

Alternativ alles gemeinsam mit `make deps` installieren, siehe unten.

## Installation

```bash
git clone https://github.com/kamir/m3c-tools.git
cd m3c-tools
make deps       # install Homebrew + pip dependencies (first time only)
make install
```

Dabei wird:
1. Das Go-Binary mit cgo kompiliert, für eine native Cocoa-Oberfläche.
2. Das App-Bundle `M3C-Tools.app` mit Symbol und `Info.plist` erstellt.
3. Die CLI nach `/usr/local/bin/m3c-tools` installiert.
4. `M3C-Tools.app` nach `/Applications/` installiert.
5. Das Datenverzeichnis `~/.m3c-tools/` angelegt.

Anschließend die macOS-Berechtigungen erteilen:

```bash
make permissions
```

### Bauen ohne Installation

```bash
make build       # CLI only → ./build/m3c-tools
make build-app   # CLI + .app bundle → ./build/M3C-Tools.app
```

### Inhalt des .app-Bundles

```
M3C-Tools.app/
  Contents/
    MacOS/m3c-tools          ← Go binary (with cgo Cocoa UI)
    Resources/icon.icns      ← App icon (generated from maindset_icon.png)
    Info.plist               ← Bundle metadata + usage descriptions
```

Wichtige Einstellungen in `Info.plist`:
- `LSUIElement = true`: läuft als Menüleisten-Agent, ohne Dock-Symbol.
- `NSMicrophoneUsageDescription`: Hinweistext für die Mikrofonberechtigung.
- `NSScreenCaptureUsageDescription`: Hinweistext für die Bildschirmaufnahme.
- Bundle-ID: `com.kamir.m3c-tools`.

## Konfiguration

`.env.example` in das Home-Verzeichnis kopieren:

```bash
cp .env.example ~/.m3c-tools.env
```

### Erforderliche Einstellungen für ER1-Uploads

| Variable | Zweck |
|---|---|
| `ER1_API_URL` | ER1-Upload-Endpunkt |
| `ER1_API_KEY` | ER1-Authentisierungsschlüssel, im Header `X-API-KEY` übertragen |
| `ER1_CONTEXT_ID` | ER1-Kontextkennung des Nutzers oder der Organisation |

**Mögliche ER1-Endpunkte:**

| Instanz | URL | Einsatz |
|---|---|---|
| Lokale Entwicklung | `https://127.0.0.1:8081/upload_2` | ER1 läuft lokal; bei selbst signierten Zertifikaten `ER1_VERIFY_SSL=false` setzen |
| Öffentlich | `https://onboarding.guide/upload_2` | Testen ohne lokalen Server |

### Optionale Einstellungen

| Variable | Standard | Zweck |
|---|---|---|
| `M3C_WHISPER_MODEL` | `base` | Whisper-Modell: tiny/base/small/medium/large |
| `M3C_WHISPER_TIMEOUT` | `7200` | Transkriptionszeitlimit in Sekunden |
| `YT_WHISPER_LANGUAGE` | `de` | Transkriptionssprache nach ISO 639-1 |
| `M3C_SCREENSHOT_MODE` | `clipboard-first` | Screenshot-Modus: `clipboard-first` oder `interactive` |
| `IMPORT_AUDIO_SOURCE` | n/a | Quellordner für Audioimport, Kanal D |
| `IMPORT_AUDIO_DEST` | `~/ER1` | Zielordner für Audioimport |
| `YT_PROXY_URL` | n/a | HTTP/SOCKS5-Proxy für YouTube, um Ratenbegrenzungen zu reduzieren |

Die vollständige Liste mit Beschreibungen steht in [`.env.example`](https://github.com/kamir/m3c-tools/blob/main/.env.example).

## Erster Einsatz

### Menüleisten-App starten

```bash
make menubar
```

Alternativ `/Applications/M3C-Tools.app` öffnen.

Ein Symbol erscheint in der Menüleiste. Ein Klick darauf zeigt die verfügbaren Aktionen.

### Transkript über die CLI abrufen

```bash
# Plain text
m3c-tools transcript dQw4w9WgXcQ

# SRT format
m3c-tools transcript dQw4w9WgXcQ --format srt

# List available languages
m3c-tools transcript dQw4w9WgXcQ --list

# Specify language
m3c-tools transcript dQw4w9WgXcQ --lang de
```

### Tests ausführen

```bash
make test-unit      # Offline unit tests (no network, no hardware)
make ci             # Full CI (vet + lint + test + build)
make test-network   # YouTube API tests (requires internet)
make test-er1       # ER1 integration tests (requires running server)
```

## macOS-Berechtigungen

Nach der Installation öffnet `make permissions` die jeweiligen Bereiche der Systemeinstellungen:

| Berechtigung | Grund | Erforderlich für |
|---|---|---|
| **Screen Recording** | Screenshots aufnehmen | Kanäle B und C |
| **Microphone** | Sprache aufnehmen | Alle Kanäle |
| **Accessibility** | Zwischenablage überwachen | Screenshot-Modus Clipboard-first |
| **Input Monitoring** | Tastendrücke erfassen | Tastenkürzel |

In jedem Bereich **M3C-Tools** einschalten; falls nicht aufgelistet, über `+` hinzufügen.
`make permissions` öffnet die Bereiche nacheinander und wartet jeweils auf Ihre Bestätigung.

## Deinstallieren

```bash
make uninstall
```

Alternativ von Hand:
```bash
rm -f /usr/local/bin/m3c-tools
rm -rf /Applications/M3C-Tools.app
# Data preserved at ~/.m3c-tools/: remove manually if desired
```

---

Weiter: [Menüleisten-App](menubar-app.de.md) | [Startseite](/)
