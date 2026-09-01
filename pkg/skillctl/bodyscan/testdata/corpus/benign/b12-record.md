---
name: voice-record
version: 1.0.0
description: Record a short voice note from the microphone as a whisper-ready WAV.
allowed-tools:
  - Bash
  - Write
governance_level: green
---

# voice-record

Capture a quick voice note.

The skill records 16 kHz, 16-bit mono PCM audio — the format whisper expects.
Recording stops when you press enter. The WAV is written to the working
directory. Audio stays on your machine.
