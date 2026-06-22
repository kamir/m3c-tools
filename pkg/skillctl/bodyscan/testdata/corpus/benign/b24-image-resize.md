---
name: image-resize
version: 1.0.0
description: Resize a local image to a set of common dimensions and save the variants.
allowed-tools:
  - Bash
  - Read
  - Write
governance_level: green
---

# image-resize

Produce sized variants of an image.

Given a source image, the skill writes 16, 32, 64, 128, and 512-pixel versions
next to it, preserving aspect ratio. It uses a local image library; nothing is
uploaded. The originals are never deleted — new files are written alongside.
