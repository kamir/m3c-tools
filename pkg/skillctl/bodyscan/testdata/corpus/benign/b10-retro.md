---
name: retro
version: 1.4.0
description: Weekly engineering retrospective over commit history with trend tracking.
allowed-tools:
  - Bash
  - Read
  - Write
governance_level: green
---

# retro

Summarise the week's engineering activity.

## What it analyses

- Commit history (`git log`) for the last seven days.
- Per-person contribution breakdown.
- Code-quality trend versus the previous retro.

The skill reads the local git history and writes a dated markdown report under
`MEMOS/`. Nothing is sent anywhere; the report is yours to share manually.
