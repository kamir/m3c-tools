---
name: whisper-transcribe
version: 1.0.0
description: Transcribe a local WAV file to text using the whisper CLI binary.
allowed-tools:
  - Bash
  - Read
  - Write
governance_level: green
---

# whisper-transcribe

Transcribe a recording into text.

1. Locate the whisper binary in PATH.
2. Run it on the input WAV with `--output_format json`.
3. Parse the segments and write a plain transcript.

All processing is local. The audio never leaves the machine. The output is a
text file alongside the input.
