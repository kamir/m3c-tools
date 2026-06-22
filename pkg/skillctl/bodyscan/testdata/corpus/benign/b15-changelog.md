---
name: changelog-update
version: 1.1.0
description: Append a new release section to CHANGELOG.md from recent commit subjects.
allowed-tools:
  - Bash
  - Read
  - Edit
governance_level: green
---

# changelog-update

Keep the changelog current.

The skill reads recent commit subjects, groups them by type (feat, fix, docs),
and uses the Edit tool to insert a new dated section at the top of
`CHANGELOG.md`. It edits only that one file and asks you to review the diff
before anything is committed.
