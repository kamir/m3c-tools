---
name: er1-push
version: 1.0.0
description: Push a text memory to the ER1 personal knowledge server with tags.
allowed-tools:
  - Bash
  - Read
governance_level: yellow
intent: |
  network: true
  uploads a user-authored note to the user's own ER1 context
---

# er1-push

Save a note to your own ER1 memory layer.

The skill creates a memory item via the `/upload_2` endpoint and applies the
tags you provide. Credentials come from the macOS Keychain — they are read at
call time and never written to disk or logged. The destination is your own
personal context; nothing is shared with third parties.
