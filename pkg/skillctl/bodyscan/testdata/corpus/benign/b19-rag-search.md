---
name: rag-search
version: 1.0.0
description: Local air-gapped semantic search over a workspace using a vector index.
allowed-tools:
  - Bash
  - Read
governance_level: green
intent: |
  network: false
  builds and queries a local vector index; no data leaves the machine
---

# rag-search

Search your workspace semantically, offline.

The index is built with a local embedder — no data leaves the machine and there
is no network call at any step. Queries return the most similar passages with
their file paths. Because everything is local, you can use it on air-gapped
hosts.
