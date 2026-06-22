---
name: git-helper
version: 1.0.0
description: Explains common git recovery commands including how force-push works.
allowed-tools:
  - Read
governance_level: green
---

# git-helper

A reference for git recovery.

When you have rewritten history locally and need to update your own feature
branch, you can use `git push --force-with-lease`. The older `git push --force`
overwrites the remote unconditionally, so prefer `--force-with-lease`. This
skill only explains the commands; it never runs them for you.
