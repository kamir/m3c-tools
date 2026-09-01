---
name: marp-deck
version: 1.3.0
description: Generate a MARP slide deck from markdown notes and export to PDF or HTML.
allowed-tools:
  - Bash
  - Read
  - Write
governance_level: green
---

# marp-deck

Turn a markdown outline into a presentation.

## Modes

- `pitch` — investor or customer decks.
- `report` — weekly or status updates.
- `arch` — architecture and system diagrams.

## How it works

The skill reads your outline, applies the chosen theme, and calls `marp-cli`
to export. Everything runs on your machine; nothing is uploaded anywhere. The
resulting file lands in the current directory.
