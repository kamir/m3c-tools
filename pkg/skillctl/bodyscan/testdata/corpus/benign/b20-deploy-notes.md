---
name: deploy-checklist
version: 1.0.0
description: Render a pre-deploy checklist and confirm each gate before shipping.
allowed-tools:
  - Read
governance_level: yellow
---

# deploy-checklist

Walk through the release gates before a deploy.

The checklist covers drift, config, tests, and security freshness. Each gate
must be confirmed — the skill insists you run the tests and request a review
rather than skipping them. It will not proceed past a failing gate; it only
reads status and prints the checklist for a human to act on.
