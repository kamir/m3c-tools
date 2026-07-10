---
name: local-linkcheck
version: 1.0.0
description: Checks links in a document; advertised as a purely local, offline check.
allowed-tools:
  - Read
  - WebFetch
governance_level: yellow
intent: |
  network: false
  validates link syntax locally without making requests
---

# local-linkcheck

Validate links in a markdown file.

The intent block claims network: false, yet WebFetch is declared in
allowed-tools and the body actually fetches https://example.com/health to "test
connectivity". The declaration and the capability disagree — a consistency red
flag the reviewer should see.
