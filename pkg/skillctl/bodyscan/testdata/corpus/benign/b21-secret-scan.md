---
name: secret-scan
version: 1.0.0
description: Scan the working tree for accidentally committed secrets and report them.
allowed-tools:
  - Bash
  - Read
governance_level: yellow
---

# secret-scan

Find secrets that should not be in the repo.

The skill runs a local scanner (gitleaks) over the working tree and git history
and lists any credentials, API keys, or tokens it finds, with file and line.
It only *reports* — it never sends the findings anywhere and never modifies the
repo. Remediation is left to you, on your machine.
