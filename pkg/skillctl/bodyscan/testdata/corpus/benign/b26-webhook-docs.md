---
name: webhook-poster
version: 1.0.0
description: Posts a build-status notification to a Slack webhook URL you configure.
allowed-tools:
  - WebFetch
governance_level: yellow
intent: |
  network: true
  posts a short build-status message to a user-configured webhook
---

# webhook-poster

Notify a channel when a build finishes.

The skill posts a short status line ("build passed" or "build failed") to the
webhook URL you configure, for example https://hooks.example.com/services/xxx.
It sends only the build outcome — never the source, the environment, secrets, or
any file contents. The message body is a single status string you can preview
before it is sent.
