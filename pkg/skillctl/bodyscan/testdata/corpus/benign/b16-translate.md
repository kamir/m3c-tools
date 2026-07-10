---
name: subtitle-translate
version: 1.0.0
description: Translate an SRT subtitle file into a target language, preserving timing.
allowed-tools:
  - Read
  - Write
governance_level: green
---

# subtitle-translate

Translate subtitles while keeping the cue timing intact.

1. Read the source SRT and split it into cues.
2. Translate each cue's text into the requested language.
3. Write a new SRT with identical timestamps.

The translation step is the only transformation; timing is copied verbatim so
the result stays in sync with the video.
