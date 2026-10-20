# M3C Tools: Plattformunterschiede

[Deutsch](PLATFORM-DIFFERENCES.de.md) | [English](PLATFORM-DIFFERENCES.md)

## Funktionsmatrix

| Funktion | macOS | Windows | Linux |
|---------|-------|---------|-------|
| **Infobereich / Menüleiste** | Natives Cocoa (menuet) | Infobereich (systray) | Infobereich (systray) |
| **Symbol im Infobereich** | Vorlagenbild (automatisch hell/dunkel) | Statisches PNG-Symbol | Statisches PNG-Symbol |
| **Sprachaufnahme** | PortAudio (eingebautes Mikrofon) | Nicht verfügbar | Nicht verfügbar |
| **Screenshot-Aufnahme** | Natives screencapture | Nicht verfügbar | Nicht verfügbar |
| **Whisper-Transkription** | Lokale whisper-Binärdatei | Lokale whisper-Binärdatei | Lokale whisper-Binärdatei |
| **Transkript-Abruf** | Vollständig | Vollständig | Vollständig |
| **Plaud Sync: bisherige Variante** (`plaud auth/list/sync/check`) | Vollständig (Chrome CDP + API) | Nur API | Nur API |
| **Plaud Sync: dauerhafte Entwicklungs-API** (`plaud dev`) | Vollständig (OAuth, serverseitiges whisper) | Nicht verfügbar¹ | Nicht verfügbar¹ |
| **Pocket Sync** (`pocket`, `import-audio`, `token`) | USB + API | Nicht verfügbar¹ | Nicht verfügbar¹ |
| **ER1-Upload** | Vollständig | Vollständig | Vollständig |
| **Konfigurationsprofile** | Vollständig | Vollständig | Vollständig |
| **Einstellungseditor** | Weboberfläche (localhost) | Weboberfläche (localhost) | Weboberfläche (localhost) |
| **skillctl** | Vollständig | Vollständig | Vollständig |
| **skillctl trust-freeze** | Bundle-Lebenszyklus und portable Probe `common.identity`. Es gibt keine macOS-Probenfamilie; eine Erfassung mit einem Linux-Profil ist daher ausdrücklich `incomplete` | Bundle-Lebenszyklus, durch das Windows-Gate auf `windows-latest` mit Unit-Tests geprüft. Es gibt keine Windows- oder WSL-Probenfamilie; eine durchgängige Ausführung der Befehle auf einem echten Windows-Rechner ist bisher nicht dokumentiert² | Zwölf Linux-Proben und `common.identity`, Profil `ubuntu-bastion` Version 3, auf echten Rechnern ausgeführt |
| **Autostart bei Anmeldung** | LaunchAgent-plist | Registry-Run-Schlüssel | Systemd-Benutzerdienst |
| **.app-Bundle** | Ja | Nein | Nein |
| **Tastenkürzel** | Globale Tastenkürzel (geplant) | Noch nicht | Noch nicht |
| **Benachrichtigungen** | Nativ (menuet) | Noch nicht | Noch nicht |

² Ob eine echte Ausführung nachgewiesen ist, bestimmt ein Rundeneintrag in
[`tests/evidence/trust-freeze/release-matrix.json`](../../../tests/evidence/trust-freeze/release-matrix.json),
nicht diese Tabelle oder ihre Begleittexte. Das Nachweisvokabular unterscheidet
bewusst zwischen `implemented`, `fixture-tested`, `cross-compiled` und
`real-platform-tested`: Cross-Kompilierung ist kein Plattformtest. Eine Erfassung
auf einer Plattform ohne eigene Probenfamilie ist nicht defekt, sondern
`incomplete`; sie nennt die nicht ausgeführten Proben.

¹ Diese Befehlsgruppen (`plaud dev`, `pocket`, `import-audio`, `token`) sind noch
an die Darwin-Datei `main.go` gekoppelt und werden **nicht in den Nicht-Darwin-Build**
(`main_other.go`) einkompiliert. Unter Windows/Linux liefern sie „Unknown command“.
Die plattformübergreifende Funktionsgleichheit wird unter **Pending / SPEC-0251 §5**
in [`../CHANGELOG.md`](../../../CHANGELOG.md) verfolgt. Verwenden Sie unter Windows/Linux
die bisherige Variante `plaud sync`.

## Architektur

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

## Menüvergleich

### macOS (menuet: natives Cocoa)

- Dynamische Untermenüs (Inhalte werden bei jedem Öffnen neu aufgebaut)
- NSImage-Vorlagensymbole pro Menüeintrag (automatisch hell/dunkel)
- Native Cocoa-Fenster (Plaud Sync, Tracking DB, Time Tracking)
- Schwebendes Beobachtungsfenster mit Texteingabe
- Globale Tastenkürzel (geplant)
- macOS-Benachrichtigungen über menuet

### Windows/Linux (systray: plattformübergreifend)

- Statische Menüstruktur (bei Zustandsänderung über einen Zyklus aus systray.Quit und systray.Run neu aufgebaut)
- Ein Symbol im Infobereich (systray bietet keine Symbole pro Menüeintrag)
- Weboberflächen (Einstellungseditor, Review-Oberfläche) öffnen sich im Standardbrowser
- Aktionen öffnen den Browser oder führen CLI-Befehle aus
- Keine nativen Fenster (Interaktion ausschließlich über Weboberfläche oder Terminal)

### Wesentliche Unterschiede für Nutzer

| Bereich | macOS | Windows/Linux |
|------|-------|---------------|
| Darstellung im Infobereich | Eigenes Symbol pro Menüeintrag | Menüeinträge nur als Text |
| Plaud-Sync-Fenster | Native Cocoa-Tabelle | Öffnet den Browser (geplant) |
| Sprachaufnahme | Eingebaut (PortAudio) | Externen Recorder verwenden und importieren |
| Screenshots | Aufnahme mit einem Klick | Betriebssystem-Screenshot verwenden und importieren |
| Beobachtungsfenster | Nativer schwebender Dialog | Öffnet den Browser (geplant) |
| Einstellungen | Webeditor oder nativ | Nur Webeditor |

## Build-Voraussetzungen

| Plattform | CGO | Abhängigkeiten | Build-Befehl |
|----------|-----|-------------|---------------|
| macOS arm64 | Ja | PortAudio, Cocoa-Frameworks | `go build ./cmd/m3c-tools` |
| macOS amd64 | Ja | PortAudio (universal), Cocoa | Mit CGO-Flags cross-kompilieren |
| Windows amd64 | Nein | Keine | `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/m3c-tools` |
| Linux amd64 | Nein | Keine | `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/m3c-tools` |
| Linux arm64 | Nein | Keine | `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build ./cmd/m3c-tools` |

## Installation

| Plattform | Paket | Befehl |
|----------|---------|---------|
| macOS | Homebrew (geplant) | `brew install kamir/tap/m3c-tools` |
| macOS | DMG (nur lokaler Build) | `make dmg`; nur lokale Paketierung, kein Release-Artefakt |
| Windows | NSIS-Installer | `M3C-Tools-Setup.exe` |
| Windows | Winget (geplant) | `winget install kamir.m3c-tools` |
| Linux | APT (geplant) | `apt install m3c-tools` |
| Linux | Direkt | Binärdatei herunterladen und zu PATH hinzufügen |
| Alle | Go install | `go install github.com/kamir/m3c-tools/cmd/m3c-tools@latest` |
