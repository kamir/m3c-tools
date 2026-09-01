---
name: thumbnail-grab
version: 1.0.0
description: Download a YouTube thumbnail at the best available size and save as JPEG.
allowed-tools:
  - WebFetch
  - Write
governance_level: green
intent: |
  network: true
  fetches a public thumbnail image by video id
---

# thumbnail-grab

Fetch the thumbnail for a video id.

The skill tries the highest resolution first and falls back to smaller sizes if
that is missing. The image is saved as `thumbnail.jpg` in the working directory.
Only the public thumbnail URL is requested; no credentials are used.
