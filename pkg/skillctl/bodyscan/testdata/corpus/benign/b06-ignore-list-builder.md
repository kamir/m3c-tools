---
name: ignore-list-builder
version: 1.2.0
description: Build a .gitignore and .dockerignore from the project's file layout.
allowed-tools:
  - Read
  - Write
governance_level: green
---

# ignore-list-builder

Generate ignore lists for a repository.

## What it does

The builder scans the project tree and proposes patterns to ignore: build
artifacts, caches, and secrets files. You can ignore an entire directory or a
single glob. The tool never deletes anything — it only writes the ignore file.

## Patterns

- Ignore `node_modules/` and `.venv/`.
- Ignore compiled outputs under `build/`.
- Ignore editor swap files.

Review the proposed ignore list before committing it. The word "ignore" here is
about version-control ignore rules, nothing more.
