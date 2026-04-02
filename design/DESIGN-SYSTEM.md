# M3C Tools — Design System

**Date:** 2026-04-02
**Scope:** Go desktop app (menubar, native windows, web-based review UIs)

---

## Visual Direction

| Property | Value |
|----------|-------|
| **Style** | 1.8px stroke / rounded corners / 24x24 grid |
| **Container** | Rounded 20-24px glass tile |
| **Palette** | See below |
| **Menubar** | Monochrome template image (auto dark/light) |

## Color Tokens

### Core Palette

| Token | Hex | Usage |
|-------|-----|-------|
| `--bg` | `#0b0f17` | Deep background |
| `--panel` | `#111827` | Card/panel background |
| `--panel-2` | `#0f172a` | Alternate panel |
| `--stroke` | `#e5e7eb` | Icon strokes, borders |
| `--muted` | `#94a3b8` | Secondary text |

### Accent Palette

| Token | Hex | Usage |
|-------|-----|-------|
| `--accent` | `#7c3aed` | Primary accent (purple) |
| `--accent-2` | `#22c55e` | Success / positive (green) |
| `--accent-3` | `#06b6d4` | Info / search (cyan) |

### Glass Effect

```css
background: rgba(17, 24, 39, 0.72);
backdrop-filter: blur(16px);
border: 1px solid rgba(255, 255, 255, 0.08);
border-radius: 24px;
box-shadow: 0 12px 40px rgba(0, 0, 0, 0.35);
```

## Icon Set

All icons use the same base properties:
- ViewBox: `0 0 24 24`
- Fill: `none`
- Stroke: `currentColor` (for template rendering)
- Stroke-width: `1.8`
- Stroke-linecap: `round`
- Stroke-linejoin: `round`

### Icon Catalog

| Name | SVG | Menu PNG | Menu Item |
|------|-----|----------|-----------|
| Core App | `core-app.svg` | `menubar-icon.png` | Menubar icon |
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
| App Icon | `app-icon-128.svg` | — | macOS app icon (gradient) |

## Menubar Icon Requirements

macOS menubar template images:
- **Format:** PNG with alpha channel
- **Menubar size:** 22x22 px (@1x), 44x44 px (@2x)
- **Menu item size:** 21x21 px (@1x), 42x42 px (@2x)
- **Color:** Black on transparent (macOS auto-inverts for dark mode)
- **File:** `menubar-icon.png` / `menubar-icon@2x.png`

## Typography

- **Primary:** Inter, ui-sans-serif, system-ui
- **Mono:** ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas

## Application to Components

| Component | Design Treatment |
|-----------|-----------------|
| **Menubar icon** | Template PNG from Core App SVG |
| **skillctl review UI** | Full glass + gradient theme |
| **skillctl HTML reports** | Glass panels, accent badges |
| **Plaud sync window** | Native Cocoa (palette where possible) |
| **skillctl menubar** | Same template icon pattern |
