# M3C Tools: Designsystem

[Deutsch](DESIGN-SYSTEM.de.md) · [English](DESIGN-SYSTEM.md)

**Datum:** 2026-04-02
**Geltungsbereich:** Go-Desktop-App mit Menüleiste, nativen Fenstern und webbasierten Review-Oberflächen

---

## Visuelle Ausrichtung

| Eigenschaft | Wert |
|---|---|
| **Stil** | 1,8 px Linienbreite, abgerundete Ecken, 24x24-Raster |
| **Container** | Glaskachel mit 20 bis 24 px Rundung |
| **Palette** | Siehe unten |
| **Menüleiste** | Monochromes Template-Bild mit automatischem Hell-/Dunkelmodus |

## Farbtoken

### Grundpalette

| Token | Hex | Verwendung |
|---|---|---|
| `--bg` | `#0b0f17` | Tiefer Hintergrund |
| `--panel` | `#111827` | Karten- und Panelhintergrund |
| `--panel-2` | `#0f172a` | Alternatives Panel |
| `--stroke` | `#e5e7eb` | Symbollinien und Ränder |
| `--muted` | `#94a3b8` | Sekundärtext |

### Akzentpalette

| Token | Hex | Verwendung |
|---|---|---|
| `--accent` | `#7c3aed` | Primärakzent, Violett |
| `--accent-2` | `#22c55e` | Erfolg und positives Ergebnis, Grün |
| `--accent-3` | `#06b6d4` | Information und Suche, Cyan |

### Glaseffekt

```css
background: rgba(17, 24, 39, 0.72);
backdrop-filter: blur(16px);
border: 1px solid rgba(255, 255, 255, 0.08);
border-radius: 24px;
box-shadow: 0 12px 40px rgba(0, 0, 0, 0.35);
```

## Symbolsatz

Alle Symbole haben dieselben Grundeigenschaften:
- ViewBox: `0 0 24 24`
- Fill: `none`
- Stroke: `currentColor` für Template-Darstellung
- Stroke-width: `1.8`
- Stroke-linecap: `round`
- Stroke-linejoin: `round`

### Symbolkatalog

| Name | SVG | Menü-PNG | Menüeintrag |
|---|---|---|---|
| Core App | `core-app.svg` | `menubar-icon.png` | Menüleistensymbol |
| Logout | `logout.svg` | `menu-logout.png` | Logout from ER1 |
| Transcript | `transcript.svg` | `menu-transcript.png` | Fetch Transcript... |
| Screenshot | `screenshot.svg` | `menu-screenshot.png` | Capture Screenshot... |
| Quick Impulse | `quick-impulse.svg` | `menu-quick-impulse.png` | Quick Impulse |
| Audio Import | `audio-import.svg` | `menu-audio-import.png` | Audio Import |
| Tracking DB | `tracking-db.svg` | `menu-tracking-db.png` | Audio Recording Tracking DB |
| Sync | `sync.svg` | `menu-sync.png` | Plaud Sync |
| Projects | `projects.svg` | `menu-projects.png` | Projects |
| History | `history.svg` | `menu-history.png` | History (N) |
| Log File | `log-file.svg` | `menu-log-file.png` | Open Log File |
| User Account | `user-account.svg` | `menu-user-account.png` | Mein Nutzerkonto / Login |
| Star | `star.svg` | `menu-star.png` | Star on GitHub |
| App Icon | `app-icon-128.svg` | n/a | macOS-App-Symbol mit Farbverlauf |

## Anforderungen an das Menüleistensymbol

Template-Bilder der macOS-Menüleiste:
- **Format:** PNG mit Alphakanal
- **Größe in der Menüleiste:** 22x22 px bei @1x, 44x44 px bei @2x
- **Größe im Menüeintrag:** 21x21 px bei @1x, 42x42 px bei @2x
- **Farbe:** Schwarz auf transparentem Hintergrund; macOS invertiert im Dunkelmodus automatisch
- **Datei:** `menubar-icon.png` / `menubar-icon@2x.png`

## Typografie

- **Primär:** Inter, ui-sans-serif, system-ui
- **Monospace:** ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas

## Anwendung auf Komponenten

| Komponente | Gestaltung |
|---|---|
| **Menüleistensymbol** | Template-PNG aus Core-App-SVG |
| **skillctl-Review-Oberfläche** | Vollständiges Glas- und Farbverlaufsthema |
| **skillctl-HTML-Berichte** | Glaspanels und Akzentkennzeichen |
| **Plaud-Sync-Fenster** | Natives Cocoa, Palette soweit möglich |
| **skillctl-Menüleiste** | Dasselbe Template-Symbolmuster |
