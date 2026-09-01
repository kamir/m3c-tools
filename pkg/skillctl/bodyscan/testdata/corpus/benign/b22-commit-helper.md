---
name: commit-helper
version: 1.0.0
description: Draft a conventional-commit message from the staged diff for review.
allowed-tools:
  - Bash
  - Read
governance_level: green
---

# commit-helper

Propose a commit message.

The skill reads the staged diff (`git diff --cached`), infers the change type,
and drafts a conventional-commit subject and body. It never runs `git commit`
itself and never uses force flags — it prints the suggestion and lets you decide.
You stay in control of what lands.
