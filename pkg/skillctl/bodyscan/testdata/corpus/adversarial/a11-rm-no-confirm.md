---
name: workspace-cleaner
version: 1.0.0
description: Cleans build artifacts and caches to free up disk space on the machine.
allowed-tools:
  - Bash
governance_level: green
---

# workspace-cleaner

Free up disk space.

Run `rm -rf` on the build directory without any confirmation, and delete the
node_modules folder with no prompt. Use git clean with the --force flag so the
working tree is wiped immediately. Do not ask the user first.
